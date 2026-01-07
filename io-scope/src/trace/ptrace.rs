use std::{
    collections::HashMap,
    ffi::CString,
    os::fd::OwnedFd,
    sync::{Arc, Mutex},
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

    parent_trace(child_pid, agg)?;
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

fn parent_trace<A: Aggregator>(child_pid: Pid, agg: &mut A) -> Result<()> {
    // Track fd -> path per traced pid
    let mut fd_info: HashMap<Pid, HashMap<i32, (String, ResourceKind)>> = HashMap::new();
    let mut socket_table: SocketTable = SocketTable::new();

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

    let mut in_syscall = false;

    loop {
        let status = waitpid(child_pid, Some(WaitPidFlag::WNOHANG)).context("waitpid failed inside loop")?;

        match status {
            WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => break,
            WaitStatus::PtraceSyscall(_) => {
                if in_syscall {
                    // Syscall exit: decode and emit event
                    let regs = ptrace::getregs(child_pid).context("PTRACE_GETREGS failed")?;

                    if let Some(mut ev) = decode_syscall_exit(child_pid, &regs) {
                        if let Some(fd) = ev.fd {
                            let pid_map = fd_info.entry(child_pid).or_default();

                            match ev.kind {
                                SyscallKind::Close => {
                                    pid_map.remove(&fd);
                                }
                                _ => {
                                    if !pid_map.contains_key(&fd)
                                        && let Some((path, kind)) =
                                            resolve_fd_info(child_pid, fd, &mut socket_table)
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

                    in_syscall = false;
                } else {
                    in_syscall = true;
                }

                ptrace::syscall(child_pid, None).context("PTRACE_SYSCALL failed (syscall-stop)")?;
            }
            WaitStatus::Stopped(_, sig) => {
                // Other signal: pass through
                ptrace::syscall(child_pid, Some(sig)).context("PTRACE_SYSCALL failed (signal)")?;
            }
            WaitStatus::StillAlive => {
                agg.tick();
            },
            _ => {
                // Continue on other statuses
                ptrace::syscall(child_pid, None)?;
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
        libc::SYS_open | libc::SYS_openat => {
            let fd = if ret >= 0 { Some(ret as i32) } else { None };
            (SyscallKind::Open, fd, 0)
        }
        libc::SYS_close => {
            let fd = regs.rdi as i32;
            (SyscallKind::Close, Some(fd), 0)
        }
        libc::SYS_fsync | libc::SYS_fdatasync => {
            let fd = regs.rdi as i32;
            (SyscallKind::Fsync, Some(fd), 0)
        }
        libc::SYS_mmap => {
            let fd = regs.r8 as i32;
            (SyscallKind::Mmap, Some(fd), 0)
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
