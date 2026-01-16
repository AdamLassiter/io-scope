use std::{
    collections::{HashMap, HashSet},
    ffi::CString,
    os::fd::OwnedFd,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use nix::{
    libc,
    sys::{
        ptrace,
        signal::{Signal, raise},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, close, dup2_stderr, dup2_stdout, execvp, fork, pipe},
};
use time::OffsetDateTime;

use crate::{
    agg::Aggregator,
    model::{
        agg::LiveState,
        cli::{RunConfig, RunMode},
        syscall::{ResourceKind, SyscallEvent, SyscallKind},
    },
    trace::{
        TraceProvider,
        socket::{SocketTable, resolve_fd_info},
        spawn_log_reader,
    },
};

pub struct PtraceTracer;

impl PtraceTracer {
    pub fn new() -> Self {
        Self
    }
}

impl<A: Aggregator> TraceProvider<A> for PtraceTracer {
    fn run(
        &mut self,
        cfg: &RunConfig,
        agg: &mut A,
        live_state: Option<Arc<Mutex<LiveState>>>,
    ) -> Result<()> {
        run_linux_ptrace_raw(cfg, agg, live_state)
    }
}

fn run_linux_ptrace_raw<A: Aggregator>(
    cfg: &RunConfig,
    agg: &mut A,
    live_state: Option<Arc<Mutex<LiveState>>>,
) -> Result<()> {
    agg.on_start();

    let use_pipes = matches!(cfg.mode, RunMode::Live) && live_state.is_some();
    let stdout_pipe = if use_pipes {
        Some(pipe().context("pipe for stdout failed")?)
    } else {
        None
    };
    let stderr_pipe = if use_pipes {
        Some(pipe().context("pipe for stderr failed")?)
    } else {
        None
    };

    let child_pid = match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => {
            child_exec(cfg, use_pipes, stdout_pipe, stderr_pipe);
        }
        ForkResult::Parent { child } => child,
    };

    // Parent: close write ends, spawn log readers
    if use_pipes {
        if let Some((read_fd, write_fd)) = stdout_pipe {
            close(write_fd)?;
            if let Some(state) = live_state.as_ref() {
                spawn_log_reader(read_fd, state.clone(), false);
            }
        }
        if let Some((read_fd, write_fd)) = stderr_pipe {
            close(write_fd)?;
            if let Some(state) = live_state.as_ref() {
                spawn_log_reader(read_fd, state.clone(), true);
            }
        }
    }

    // Add initial child to tracked PIDs
    if let Some(ref state) = live_state {
        let mut s = state.lock().unwrap();
        s.child_pids.clear();
        s.child_pids.insert(child_pid.as_raw());
    }

    parent_trace(child_pid, agg, live_state)?;
    agg.on_end();
    Ok(())
}

fn child_exec(
    cfg: &RunConfig,
    use_pipes: bool,
    stdout_pipe: Option<(OwnedFd, OwnedFd)>,
    stderr_pipe: Option<(OwnedFd, OwnedFd)>,
) -> ! {
    let result: Result<(), nix::Error> = (|| {
        if use_pipes {
            if let Some((_, write_fd)) = stdout_pipe.as_ref() {
                dup2_stdout(write_fd)?;
            }
            if let Some((_, write_fd)) = stderr_pipe.as_ref() {
                dup2_stderr(write_fd)?;
            }
            // Close all pipe ends in child
            for (read_fd, write_fd) in [stdout_pipe, stderr_pipe].into_iter().flatten() {
                close(read_fd)?;
                close(write_fd)?;
            }
        }

        // Ask to be traced by parent
        ptrace::traceme()?;

        // Stop ourselves so parent can set options
        raise(Signal::SIGSTOP)?;

        let c_cmd = CString::new(cfg.cmd.as_str()).unwrap();
        let mut c_args: Vec<CString> = vec![c_cmd.clone()];
        c_args.extend(cfg.args.iter().map(|a| CString::new(a.as_str()).unwrap()));

        execvp(&c_cmd, &c_args)?;
        Ok(())
    })();

    let _ = result;
    std::process::exit(127);
}

fn parent_trace<A: Aggregator>(
    child_pid: Pid,
    agg: &mut A,
    live_state: Option<Arc<Mutex<LiveState>>>,
) -> Result<()> {
    // Track fd -> path per traced pid
    let mut fd_info: HashMap<Pid, HashMap<i32, (String, ResourceKind)>> = HashMap::new();
    let mut socket_table: SocketTable = SocketTable::new();
    let mut traced_pids: HashSet<Pid> = HashSet::from([child_pid]);
    let mut in_syscall: HashMap<Pid, bool> = HashMap::new();

    // Wait for SIGSTOP from child
    match waitpid(child_pid, None).context("initial waitpid failed")? {
        WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => return Ok(()),
        _ => {}
    }

    // Set ptrace options
    ptrace::setoptions(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_TRACEEXIT
            | ptrace::Options::PTRACE_O_TRACEVFORK,
    )
    .context("PTRACE_SETOPTIONS failed")?;

    // Start tracing syscalls
    ptrace::syscall(child_pid, None).context("initial PTRACE_SYSCALL failed")?;

    loop {
        // Wait for any traced child (-1)
        let status = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG))
            .context("waitpid failed inside loop")?;

        match status {
            WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
                traced_pids.remove(&pid);
                in_syscall.remove(&pid);
                if traced_pids.is_empty() {
                    break;
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                let is_exit = in_syscall.get(&pid).copied().unwrap_or(false);

                if is_exit {
                    // Syscall exit: decode and emit event
                    let regs = ptrace::getregs(pid).context("PTRACE_GETREGS failed")?;

                    if let Some(mut ev) = decode_syscall_exit(pid, &regs) {
                        if let Some(fd) = ev.fd {
                            let pid_map = fd_info.entry(pid).or_default();

                            match ev.kind {
                                SyscallKind::Close => {
                                    pid_map.remove(&fd);
                                }
                                _ => {
                                    if !pid_map.contains_key(&fd)
                                        && let Some((path, kind)) =
                                            resolve_fd_info(pid, fd, &mut socket_table)
                                    {
                                        pid_map.insert(fd, (path, kind));
                                    }
                                    if let Some((path, kind)) = pid_map.get(&fd) {
                                        ev.resource = Some(path.clone());
                                        ev.resource_kind = Some(*kind);
                                    }
                                }
                            }
                        }

                        agg.on_event(&ev);
                    }

                    in_syscall.insert(pid, false);
                } else {
                    in_syscall.insert(pid, true);
                }

                ptrace::syscall(pid, None).context("PTRACE_SYSCALL failed (syscall-stop)")?;
            }
            WaitStatus::PtraceEvent(pid, _sig, event) => {
                // Handle fork/clone/vfork events
                if (event == libc::PTRACE_EVENT_FORK
                    || event == libc::PTRACE_EVENT_VFORK
                    || event == libc::PTRACE_EVENT_CLONE)
                    && let Ok(new_pid) = ptrace::getevent(pid)
                {
                    let new_pid = Pid::from_raw(new_pid as i32);
                    traced_pids.insert(new_pid);
                    in_syscall.insert(new_pid, false);

                    // Update live state with new child PID
                    if let Some(ref state) = live_state {
                        let mut s = state.lock().unwrap();
                        s.child_pids.insert(new_pid.as_raw());
                    }
                }
                ptrace::syscall(pid, None)?;
            }
            WaitStatus::Stopped(pid, sig) => {
                // New child stopped, or signal delivery
                if !traced_pids.contains(&pid) {
                    traced_pids.insert(pid);
                    in_syscall.insert(pid, false);

                    if let Some(ref state) = live_state {
                        let mut s = state.lock().unwrap();
                        s.child_pids.insert(pid.as_raw());
                    }
                }
                ptrace::syscall(pid, Some(sig)).context("PTRACE_SYSCALL failed (signal)")?;
            }
            WaitStatus::StillAlive => {
                agg.tick();
                std::thread::sleep(Duration::from_micros(10));
            }
            _ => {
                // Continue on other statuses (try to extract pid if possible)
                if let Some(pid) = extract_pid_from_status(&status) {
                    ptrace::syscall(pid, None)?;
                }
            }
        }
    }

    Ok(())
}

fn decode_syscall_exit(pid: Pid, regs: &libc::user_regs_struct) -> Option<SyscallEvent> {
    let nr = regs.orig_rax as i64;
    let ret = regs.rax as i64;
    let ts = OffsetDateTime::now_utc();

    let (kind, fd, bytes) = match nr {
        libc::SYS_read => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Read, Some(fd), bytes)
        }
        libc::SYS_write => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Write, Some(fd), bytes)
        }
        libc::SYS_pread64 => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Pread, Some(fd), bytes)
        }
        libc::SYS_pwrite64 => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Pwrite, Some(fd), bytes)
        }
        libc::SYS_readv => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Readv, Some(fd), bytes)
        }
        libc::SYS_writev => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Writev, Some(fd), bytes)
        }
        libc::SYS_preadv | libc::SYS_preadv2 => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Readv, Some(fd), bytes)
        }
        libc::SYS_pwritev | libc::SYS_pwritev2 => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Writev, Some(fd), bytes)
        }
        libc::SYS_sendto | libc::SYS_sendmsg => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Send, Some(fd), bytes)
        }
        libc::SYS_recvfrom | libc::SYS_recvmsg => {
            let fd = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Recv, Some(fd), bytes)
        }
        libc::SYS_sendmmsg => {
            // Returns number of messages sent, not bytes
            let fd = regs.rdi as i32;
            (SyscallKind::Send, Some(fd), 0)
        }
        libc::SYS_recvmmsg => {
            // Returns number of messages received, not bytes
            let fd = regs.rdi as i32;
            (SyscallKind::Recv, Some(fd), 0)
        }
        libc::SYS_open | libc::SYS_openat | libc::SYS_openat2 => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_creat => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_close => {
            let fd = regs.rdi as i32;
            (SyscallKind::Close, Some(fd), 0)
        }
        libc::SYS_close_range => {
            // Closes a range of fds; we don't track individual fds here
            (SyscallKind::Close, None, 0)
        }
        libc::SYS_fsync | libc::SYS_fdatasync => {
            let fd = regs.rdi as i32;
            (SyscallKind::Fsync, Some(fd), 0)
        }
        libc::SYS_sync_file_range => {
            let fd = regs.rdi as i32;
            (SyscallKind::Fsync, Some(fd), 0)
        }
        libc::SYS_mmap => {
            let fd = regs.r8 as i32;
            (SyscallKind::Mmap, Some(fd), 0)
        }
        libc::SYS_splice => {
            // splice(fd_in, off_in, fd_out, off_out, len, flags)
            // fd_in is in rdi, fd_out is in r10
            let fd_in = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Read, Some(fd_in), bytes)
        }
        libc::SYS_tee => {
            // tee(fd_in, fd_out, len, flags)
            let fd_in = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Read, Some(fd_in), bytes)
        }
        libc::SYS_copy_file_range => {
            // copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
            let fd_in = regs.rdi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Read, Some(fd_in), bytes)
        }
        libc::SYS_sendfile => {
            // sendfile(out_fd, in_fd, offset, count)
            // Note: in_fd is in rsi, not rdi
            let fd_in = regs.rsi as i32;
            let bytes = if ret > 0 { ret as u64 } else { 0 };
            (SyscallKind::Read, Some(fd_in), bytes)
        }
        libc::SYS_dup | libc::SYS_dup2 | libc::SYS_dup3 => {
            // Track as open since it creates a new fd
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_socket | libc::SYS_accept | libc::SYS_accept4 => {
            // Creates a new fd
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_connect => {
            // Track connect for socket activity (no bytes)
            let fd = regs.rdi as i32;
            (SyscallKind::Other, Some(fd), 0)
        }
        libc::SYS_pipe | libc::SYS_pipe2 => {
            // Creates two fds; we can't easily track both here
            (SyscallKind::Open, None, 0)
        }
        libc::SYS_eventfd | libc::SYS_eventfd2 => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_epoll_create | libc::SYS_epoll_create1 => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_timerfd_create => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_signalfd | libc::SYS_signalfd4 => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_inotify_init | libc::SYS_inotify_init1 => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_memfd_create => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_userfaultfd => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_perf_event_open => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_fanotify_init => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        _ => (SyscallKind::Other, None, 0),
    };

    Some(SyscallEvent {
        pid: pid.as_raw(),
        ts,
        kind,
        fd,
        bytes,
        resource: None,
        resource_kind: None,
    })
}

fn extract_pid_from_status(status: &WaitStatus) -> Option<Pid> {
    match status {
        WaitStatus::Continued(pid) => Some(*pid),
        _ => None,
    }
}
