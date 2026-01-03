use std::{
    collections::HashMap,
    ffi::CString,
    io::{BufRead, BufReader},
    os::fd::FromRawFd,
    sync::{Arc, Mutex},
    thread,
};

use anyhow::{Result, bail};
use libc;
use time::OffsetDateTime;

use crate::{
    agg::Aggregator,
    model::{
        agg::LiveState,
        cli::RunConfig,
        syscall::{ResourceKind, SyscallEvent, SyscallKind},
    },
    trace::{
        TraceProvider,
        socket::{SocketTable, resolve_fd_info},
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
    use crate::model::cli::RunMode;

    agg.on_start();

    let use_pipes = matches!(cfg.mode, RunMode::Live) && live_state.is_some();
    let mut stdout_pipe: [libc::c_int; 2] = [-1, -1];
    let mut stderr_pipe: [libc::c_int; 2] = [-1, -1];
    if use_pipes {
        if unsafe { libc::pipe(stdout_pipe.as_mut_ptr()) } == -1 {
            bail!("pipe for stdout failed");
        }
        if unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) } == -1 {
            bail!("pipe for stderr failed");
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork failed");
    }

    if pid == 0 {
        // Child
        child_exec(cfg, use_pipes, stdout_pipe, stderr_pipe);
    } else {
        if use_pipes {
            unsafe {
                // Close write ends in parent; keep read ends.
                libc::close(stdout_pipe[1]);
                libc::close(stderr_pipe[1]);
            }

            if let Some(state) = live_state.clone() {
                spawn_log_reader(stdout_pipe[0], state.clone(), false);
                spawn_log_reader(stderr_pipe[0], state, true);
            }
        }
        // Parent
        parent_trace(pid, agg)?;
    }

    agg.on_end();
    Ok(())
}

fn child_exec(
    cfg: &RunConfig,
    use_pipes: bool,
    stdout_pipe: [libc::c_int; 2],
    stderr_pipe: [libc::c_int; 2],
) -> ! {
    // Ask to be traced by parent.
    unsafe {
        // In live mode, detach child's stdout/stderr from our TUI.
        if use_pipes {
            // Redirect stdout/stderr to pipes
            if stdout_pipe[1] >= 0 {
                libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO);
            }
            if stderr_pipe[1] >= 0 {
                libc::dup2(stderr_pipe[1], libc::STDERR_FILENO);
            }
            // Close both ends in child (we only need the dup'ed fds)
            if stdout_pipe[0] >= 0 {
                libc::close(stdout_pipe[0]);
            }
            if stdout_pipe[1] >= 0 {
                libc::close(stdout_pipe[1]);
            }
            if stderr_pipe[0] >= 0 {
                libc::close(stderr_pipe[0]);
            }
            if stderr_pipe[1] >= 0 {
                libc::close(stderr_pipe[1]);
            }
        }

        if libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ) == -1
        {
            libc::_exit(127);
        }

        // Stop ourselves so parent can set options.
        libc::raise(libc::SIGSTOP);

        // Build argv for execvp: [cmd, args..., NULL]
        let c_cmd = match CString::new(cfg.cmd.as_str()) {
            Ok(c) => c,
            Err(_) => libc::_exit(127),
        };

        let mut c_args: Vec<CString> = Vec::with_capacity(cfg.args.len());
        for a in &cfg.args {
            match CString::new(a.as_str()) {
                Ok(c) => c_args.push(c),
                Err(_) => libc::_exit(127),
            }
        }

        let mut argv: Vec<*const libc::c_char> = Vec::with_capacity(c_args.len() + 2);
        argv.push(c_cmd.as_ptr());
        for a in &c_args {
            argv.push(a.as_ptr());
        }
        argv.push(std::ptr::null());

        libc::execvp(c_cmd.as_ptr(), argv.as_ptr());
        // If execvp returns, it failed.
        libc::_exit(127);
    }
}

fn parent_trace<A: Aggregator>(child_pid: libc::pid_t, agg: &mut A) -> Result<()> {
    unsafe {
        let mut status: libc::c_int = 0;

        // Track fd -> path per traced pid
        let mut fd_info: HashMap<libc::pid_t, HashMap<i32, (String, ResourceKind)>> =
            HashMap::new();
        // socket inode -> endpoint
        let mut socket_table: SocketTable = SocketTable::new();

        // Wait for SIGSTOP from child.
        if libc::waitpid(child_pid, &mut status, 0) == -1 {
            bail!("waitpid failed");
        }

        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(());
        }

        // Set ptrace options.
        if libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            child_pid,
            std::ptr::null_mut::<libc::c_void>(),
            ((libc::PTRACE_O_TRACESYSGOOD
                | libc::PTRACE_O_TRACECLONE
                | libc::PTRACE_O_TRACEFORK
                | libc::PTRACE_O_TRACEEXEC
                | libc::PTRACE_O_TRACEEXIT
                | libc::PTRACE_O_TRACEVFORK
                | libc::PTRACE_O_TRACEVFORKDONE
                | libc::PTRACE_O_TRACESECCOMP) as libc::c_long) as *mut libc::c_void,
        ) == -1
        {
            bail!("PTRACE_SETOPTIONS failed");
        }

        // Start tracing syscalls.
        if libc::ptrace(
            libc::PTRACE_SYSCALL,
            child_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ) == -1
        {
            bail!("initial PTRACE_SYSCALL failed");
        }

        let mut in_syscall = false;

        loop {
            let w = libc::waitpid(child_pid, &mut status, 0);
            if w == -1 {
                bail!("waitpid failed inside loop");
            }

            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                break;
            }

            if libc::WIFSTOPPED(status) {
                let sig = libc::WSTOPSIG(status);
                let is_syscall_stop = sig == (libc::SIGTRAP | 0x80);

                if is_syscall_stop {
                    if in_syscall {
                        // Syscall exit: decode and emit event.
                        let mut regs: libc::user_regs_struct = std::mem::zeroed();
                        if libc::ptrace(
                            libc::PTRACE_GETREGS,
                            child_pid,
                            std::ptr::null_mut::<libc::c_void>(),
                            &mut regs as *mut _ as *mut libc::c_void,
                        ) == -1
                        {
                            bail!("PTRACE_GETREGS failed");
                        }

                        if let Some(mut ev) = decode_syscall_exit(child_pid, &regs) {
                            if let Some(fd) = ev.fd {
                                use crate::model::syscall::SyscallKind;

                                let pid_map = fd_info.entry(child_pid).or_default();

                                match ev.kind {
                                    SyscallKind::Close => {
                                        // Drop mapping on close
                                        pid_map.remove(&fd);
                                    }
                                    _ => {
                                        // Ensure we have fd info (path, kind)
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

                    // Continue to next syscall stop.
                    if libc::ptrace(
                        libc::PTRACE_SYSCALL,
                        child_pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    ) == -1
                    {
                        bail!("PTRACE_SYSCALL failed (syscall-stop)");
                    }
                } else {
                    // Other signal: pass through.
                    if libc::ptrace(
                        libc::PTRACE_SYSCALL,
                        child_pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        (sig as libc::c_long) as *mut libc::c_void,
                    ) == -1
                    {
                        bail!("PTRACE_SYSCALL failed (signal)");
                    }
                }
            }
        }
    }

    Ok(())
}

fn decode_syscall_exit(pid: libc::pid_t, regs: &libc::user_regs_struct) -> Option<SyscallEvent> {
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
            // On x86_64, fd is 5th arg, in r8
            let fd = regs.r8 as i32;
            (SyscallKind::Mmap, Some(fd), 0)
        }
        _ => (SyscallKind::Other, None, 0),
    };

    Some(SyscallEvent {
        pid,
        ts,
        kind,
        fd,
        bytes,
        resource: None,
        resource_kind: None,
    })
}

fn spawn_log_reader(fd: libc::c_int, state: Arc<Mutex<LiveState>>, is_stderr: bool) {
    thread::spawn(move || {
        // Safety: we own this fd here.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let reader = BufReader::new(file);

        for line in reader.lines() {
            if let Ok(mut line) = line {
                if is_stderr {
                    line = format!("[stderr] {}", line);
                }

                let mut s = state.lock().unwrap();
                const MAX_LOG_LINES: usize = 200;
                if s.log_lines.len() >= MAX_LOG_LINES {
                    s.log_lines.pop_front();
                }
                s.log_lines.push_back(line);
            } else {
                break;
            }
        }
    });
}
