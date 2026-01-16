use std::{
    ffi::CString,
    os::fd::OwnedFd,
    sync::{Arc, Mutex}, time::Duration,
};

use anyhow::{Context, Result, anyhow};
use aya::{
    Ebpf,
    EbpfLoader,
    maps::{Array, MapData, perf::{PerfEventArray, PerfEventArrayBuffer}},
    programs::TracePoint,
    util::online_cpus,
};
use bytes::BytesMut;
use nix::{
    sys::{
        signal::{Signal, kill, raise},
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
        syscall::{SyscallEvent, SyscallKind},
    },
    trace::{
        TraceProvider,
        socket::{SocketTable, resolve_fd_info},
        spawn_log_reader,
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

        // Stop child so parent can attach eBPF
        raise(Signal::SIGSTOP)?;

        let c_cmd = CString::new(cfg.cmd.as_str()).unwrap();
        let mut c_args: Vec<CString> = vec![c_cmd.clone()];
        c_args.extend(cfg.args.iter().map(|a| CString::new(a.as_str()).unwrap()));

        execvp(&c_cmd, &c_args)?;
        Ok(())
    })();

    // If we get here, exec failed
    let _ = result;
    std::process::exit(127);
}

fn check_child_done(child_pid: Pid) -> Result<bool> {
    match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::StillAlive) => Ok(false),
        Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => Ok(true),
        Ok(_) => Ok(false), // Other states (stopped, continued, etc.)
        Err(nix::errno::Errno::ECHILD) => Ok(true),
        Err(e) => Err(anyhow!("waitpid error: {:?}", e)),
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

    // Track the initial child PID
    if let Some(ref state) = live_state {
        let mut s = state.lock().unwrap();
        s.child_pids.clear();
    }

    // Set up pipes if in live mode
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

    let child_pid = spawn_stopped_child(cfg, &live_state, use_pipes, stdout_pipe, stderr_pipe)?;
    let (bufs, slots) = configure_ebpf(&mut bpf, child_pid)?;
    kill(child_pid, Signal::SIGCONT).context("failed to resume child")?;
    poll_ringbuffers(agg, live_state, child_pid, bufs, slots)?;

    agg.on_end();
    Ok(())
}

fn poll_ringbuffers<A: Aggregator>(agg: &mut A, live_state: Option<Arc<Mutex<LiveState>>>, child_pid: Pid, mut bufs: Vec<PerfEventArrayBuffer<&mut MapData>>, mut slots: Vec<BytesMut>) -> Result<(), anyhow::Error> {
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

                    // Track any new child PIDs we see
                    if let Some(ref state) = live_state {
                        let mut s = state.lock().unwrap();
                        s.child_pids.insert(io_ev.pid);
                    }

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
            agg.tick();
        }

        if !got_events {
            std::thread::sleep(Duration::from_micros(10));
        }
    };
    Ok(())
}

fn configure_ebpf(bpf: &mut Ebpf, child_pid: Pid) -> Result<(Vec<PerfEventArrayBuffer<&mut MapData>>, Vec<BytesMut>), anyhow::Error> {
    {
        let map = bpf
            .map_mut("TARGET_TGID")
            .ok_or_else(|| anyhow!("BPF map TARGET_TGID not found"))?;
        let mut arr: Array<_, u32> = Array::try_from(map)?;
        arr.set(0, child_pid.as_raw() as u32, 0)
            .context("failed to set TARGET_TGID")?;
    }
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
    let io_map = bpf
        .map_mut("IO_EVENTS")
        .ok_or_else(|| anyhow!("BPF map IO_EVENTS not found"))?;
    let mut perf = PerfEventArray::try_from(io_map)?;
    let cpus = online_cpus()
        .map_err(|(_msg, err)| err)
        .context("failed to get online CPUs")?;
    let bufs: Vec<_> = cpus
        .iter()
        .map(|cpu| perf.open(*cpu, None))
        .collect::<Result<_, _>>()
        .context("failed to open perf buffers")?;
    let slots: Vec<BytesMut> = (0..8).map(|_| BytesMut::with_capacity(4096)).collect();
    Ok((bufs, slots))
}

fn spawn_stopped_child(cfg: &RunConfig, live_state: &Option<Arc<Mutex<LiveState>>>, use_pipes: bool, stdout_pipe: Option<(OwnedFd, OwnedFd)>, stderr_pipe: Option<(OwnedFd, OwnedFd)>) -> Result<Pid, anyhow::Error> {
    let child_pid = match unsafe { fork() }.context("fork failed")? {
        ForkResult::Child => {
            child_exec(cfg, use_pipes, stdout_pipe, stderr_pipe);
        }
        ForkResult::Parent { child } => child,
    };
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
    if let Some(ref state) = *live_state {
        let mut s = state.lock().unwrap();
        s.child_pids.insert(child_pid.as_raw());
    }
    Ok(child_pid)
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

    let pid = Pid::from_raw(io_ev.tgid as i32);

    let mut socket_table = SocketTable::new();
    let (resource, resource_kind) = if io_ev.fd >= 0 {
        resolve_fd_info(pid, io_ev.fd, &mut socket_table)
            .map(|(res, kind)| (Some(res), Some(kind)))
            .unwrap_or((None, None))
    } else {
        (None, None)
    };

    SyscallEvent {
        pid: pid.as_raw(),
        ts: OffsetDateTime::now_utc(),
        kind,
        fd: Some(io_ev.fd),
        bytes,
        resource,
        resource_kind,
    }
}
