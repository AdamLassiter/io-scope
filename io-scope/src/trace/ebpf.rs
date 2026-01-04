use std::{
    ffi::CString,
    io::{BufRead, BufReader},
    os::fd::FromRawFd,
    sync::{Arc, Mutex},
    thread,
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    EbpfLoader,
    maps::{Array, perf::PerfEventArray},
    programs::TracePoint,
    util::online_cpus,
};
use bytes::BytesMut;
use time::OffsetDateTime;

use crate::{
    agg::Aggregator,
    model::{
        agg::LiveState,
        cli::{RunConfig, RunMode},
        syscall::{SyscallEvent, SyscallKind},
    },
    trace::{
        TraceProvider,
        socket::{SocketTable, resolve_fd_info},
    },
};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IoEvent {
    pub tgid: u32,
    pub pid: i32,
    pub fd: i32,
    pub bytes: i64,
    pub kind: u8,
}

pub struct EbpfTracer {
    bpf: Option<Ebpf>,
}

impl EbpfTracer {
    pub fn new() -> Result<Self> {
        let path = std::env::var("IO_SCOPE_EBPF_PATH")
            .context("IO_SCOPE_EBPF_PATH not set; did you build your eBPF object?")?;
        let data = std::fs::read(path).context("failed to read BPF object")?;

        let bpf = EbpfLoader::new().load(&data)?;
        Ok(Self { bpf: Some(bpf) })
    }
}

impl<A: Aggregator> TraceProvider<A> for EbpfTracer {
    fn run(
        &mut self,
        cfg: &RunConfig,
        agg: &mut A,
        live_state: Option<Arc<Mutex<LiveState>>>,
    ) -> Result<()> {
        run_linux_ebpf(cfg, agg, self.bpf.take(), live_state)
    }
}

fn child_exec(
    cfg: &RunConfig,
    use_pipes: bool,
    stdout_pipe: [libc::c_int; 2],
    stderr_pipe: [libc::c_int; 2],
) -> ! {
    unsafe {
        if use_pipes {
            if stdout_pipe[1] >= 0 {
                libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO);
            }
            if stderr_pipe[1] >= 0 {
                libc::dup2(stderr_pipe[1], libc::STDERR_FILENO);
            }
            // Close all pipe ends in child
            for &fd in &[stdout_pipe[0], stdout_pipe[1], stderr_pipe[0], stderr_pipe[1]] {
                if fd >= 0 {
                    libc::close(fd);
                }
            }
        }

        // Stop child so parent can attach eBPF
        libc::raise(libc::SIGSTOP);

        let c_cmd = CString::new(cfg.cmd.as_str()).unwrap();
        let c_args: Vec<CString> = cfg
            .args
            .iter()
            .map(|a| CString::new(a.as_str()).unwrap())
            .collect();

        let mut argv: Vec<*const libc::c_char> = Vec::with_capacity(c_args.len() + 2);
        argv.push(c_cmd.as_ptr());
        for a in &c_args {
            argv.push(a.as_ptr());
        }
        argv.push(std::ptr::null());

        libc::execvp(c_cmd.as_ptr(), argv.as_ptr());
        libc::_exit(127);
    }
}

fn check_child_done(child_pid: i32) -> Result<bool> {
    let mut status: libc::c_int = 0;
    let res = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };

    match res {
        0 => Ok(false),
        p if p == child_pid => Ok(libc::WIFEXITED(status) || libc::WIFSIGNALED(status)),
        -1 => {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::ECHILD) {
                Ok(true)
            } else {
                Err(anyhow!("waitpid error: {:?}", errno))
            }
        }
        _ => Ok(false),
    }
}

fn run_linux_ebpf<A: Aggregator>(
    cfg: &RunConfig,
    agg: &mut A,
    bpf_opt: Option<Ebpf>,
    live_state: Option<Arc<Mutex<LiveState>>>,
) -> Result<()> {
    let mut bpf = bpf_opt.context("BPF object already used or not initialized")?;

    agg.on_start();

    // Set up pipes if in live mode
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

    // 1) Spawn stopped child process
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(anyhow!("fork failed"));
    } else if pid == 0 {
        child_exec(cfg, use_pipes, stdout_pipe, stderr_pipe);
    }

    let child_pid = pid;

    // Parent: close write ends, spawn log readers
    if use_pipes {
        unsafe {
            libc::close(stdout_pipe[1]);
            libc::close(stderr_pipe[1]);
        }

        if let Some(state) = live_state.as_ref() {
            spawn_log_reader(stdout_pipe[0], state.clone(), false);
            spawn_log_reader(stderr_pipe[0], state.clone(), true);
        }
    }

    // 2) Configure BPF
    {
        let map = bpf
            .map_mut("TARGET_TGID")
            .ok_or_else(|| anyhow!("BPF map TARGET_TGID not found"))?;
        let mut arr: Array<_, u32> = Array::try_from(map)?;
        arr.set(0, child_pid as u32, 0)
            .context("failed to set TARGET_TGID")?;
    }

    // Attach tracepoints
    for (name, category, tp_name) in [
        ("sys_enter_read", "syscalls", "sys_enter_read"),
        ("sys_enter_write", "syscalls", "sys_enter_write"),
        ("sys_exit_read", "syscalls", "sys_exit_read"),
        ("sys_exit_write", "syscalls", "sys_exit_write"),
    ] {
        let prog = bpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("BPF program {} not found", name))?;
        let prog: &mut TracePoint = prog.try_into()?;
        prog.load()?;
        prog.attach(category, tp_name)
            .with_context(|| format!("attach {}", name))?;
    }

    // Set up perf buffers for all CPUs
    let io_map = bpf
        .map_mut("IO_EVENTS")
        .ok_or_else(|| anyhow!("BPF map IO_EVENTS not found"))?;
    let mut perf = PerfEventArray::try_from(io_map)?;

    let cpus = online_cpus()
        .map_err(|(_msg, err)| err)
        .context("failed to get online CPUs")?;
    let mut bufs: Vec<_> = cpus
        .iter()
        .map(|cpu| perf.open(*cpu, None))
        .collect::<Result<_, _>>()
        .context("failed to open perf buffers")?;

    let mut slots: Vec<BytesMut> = (0..8).map(|_| BytesMut::with_capacity(4096)).collect();

    // 3) Resume child
    unsafe { libc::kill(child_pid, libc::SIGCONT) };

    // 4) Poll perf buffers
    let mut child_done = false;
    loop {
        let mut got_events = false;

        for buf in &mut bufs {
            let events = buf.read_events(&mut slots)?;
            if events.read > 0 {
                got_events = true;
            }

            for slot in slots.iter().take(events.read) {
                if slot.len() >= std::mem::size_of::<IoEvent>() {
                    let io_ev: IoEvent =
                        unsafe { std::ptr::read_unaligned(slot.as_ptr() as *const _) };
                    let ev = io_event_to_syscall_event(&io_ev);
                    agg.on_event(&ev);
                }
            }
        }

        if child_done && !got_events {
            let any_readable = bufs.iter().any(|buf| buf.readable());
            if !any_readable {
                break;
            }
        }

        if !child_done {
            child_done = check_child_done(child_pid)?;
        }

        if !got_events {
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    }

    agg.on_end();
    Ok(())
}

fn io_event_to_syscall_event(io_ev: &IoEvent) -> SyscallEvent {
    let kind = if io_ev.kind == 0 {
        SyscallKind::Read
    } else {
        SyscallKind::Write
    };

    let bytes = if io_ev.bytes > 0 {
        io_ev.bytes as u64
    } else {
        0
    };

    let pid = io_ev.tgid as i32;

    let mut socket_table = SocketTable::new();
    let (resource, resource_kind) = if io_ev.fd >= 0 {
        resolve_fd_info(pid as libc::pid_t, io_ev.fd, &mut socket_table)
            .map(|(res, kind)| (Some(res), Some(kind)))
            .unwrap_or((None, None))
    } else {
        (None, None)
    };

    SyscallEvent {
        pid,
        ts: OffsetDateTime::now_utc(),
        kind,
        fd: Some(io_ev.fd),
        bytes,
        resource,
        resource_kind,
    }
}

fn spawn_log_reader(fd: libc::c_int, state: Arc<Mutex<LiveState>>, is_stderr: bool) {
    thread::spawn(move || {
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let Ok(mut line) = line else { break };

            if is_stderr {
                line = format!("[stderr] {}", line);
            }

            let mut s = state.lock().unwrap();
            const MAX_LOG_LINES: usize = 200;
            if s.log_lines.len() >= MAX_LOG_LINES {
                s.log_lines.pop_front();
            }
            s.log_lines.push_back(line);
        }
    });
}