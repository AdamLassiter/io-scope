use std::{
    env::var,
    ffi::CString,
    fs::read,
    os::fd::OwnedFd,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use aya::{
    Ebpf,
    EbpfLoader,
    maps::{Array, MapData, RingBuf},
    programs::TracePoint,
};
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

// Match SyscallKind enum from eBPF kernelspace
const KIND_READ: u8 = 0;
const KIND_WRITE: u8 = 1;
const KIND_PREAD: u8 = 2;
const KIND_PWRITE: u8 = 3;
const KIND_READV: u8 = 4;
const KIND_WRITEV: u8 = 5;
const KIND_SEND: u8 = 6;
const KIND_RECV: u8 = 7;
const KIND_OPEN: u8 = 8;
const KIND_CLOSE: u8 = 9;
const KIND_FSYNC: u8 = 10;
const KIND_MMAP: u8 = 11;

const TRACEPOINTS: &[&str] = &[
    // read/write
    "sys_enter_read",
    "sys_exit_read",
    "sys_enter_write",
    "sys_exit_write",
    // pread64/pwrite64
    "sys_enter_pread64",
    "sys_exit_pread64",
    "sys_enter_pwrite64",
    "sys_exit_pwrite64",
    // readv/writev
    "sys_enter_readv",
    "sys_exit_readv",
    "sys_enter_writev",
    "sys_exit_writev",
    // preadv/pwritev
    "sys_enter_preadv",
    "sys_exit_preadv",
    "sys_enter_pwritev",
    "sys_exit_pwritev",
    // preadv2/pwritev2
    "sys_enter_preadv2",
    "sys_exit_preadv2",
    "sys_enter_pwritev2",
    "sys_exit_pwritev2",
    // sendto/recvfrom
    "sys_enter_sendto",
    "sys_exit_sendto",
    "sys_enter_recvfrom",
    "sys_exit_recvfrom",
    // sendmsg/recvmsg
    "sys_enter_sendmsg",
    "sys_exit_sendmsg",
    "sys_enter_recvmsg",
    "sys_exit_recvmsg",
    // sendmmsg/recvmmsg
    "sys_enter_sendmmsg",
    "sys_exit_sendmmsg",
    "sys_enter_recvmmsg",
    "sys_exit_recvmmsg",
    // sendfile64
    "sys_enter_sendfile64",
    "sys_exit_sendfile64",
    // open/openat/openat2
    "sys_enter_open",
    "sys_exit_open",
    "sys_enter_openat",
    "sys_exit_openat",
    "sys_enter_openat2",
    "sys_exit_openat2",
    // close
    "sys_enter_close",
    "sys_exit_close",
    // fsync/fdatasync
    "sys_enter_fsync",
    "sys_exit_fsync",
    "sys_enter_fdatasync",
    "sys_exit_fdatasync",
    // mmap
    "sys_enter_mmap",
    "sys_exit_mmap",
    // splice/copy_file_range
    "sys_enter_splice",
    "sys_exit_splice",
    "sys_enter_copy_file_range",
    "sys_exit_copy_file_range",
];

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
        let path = var("IO_SCOPE_EBPF_PATH")
            .context("IO_SCOPE_EBPF_PATH not set; did you build your eBPF object?")?;
        let data = read(path).context("failed to read BPF object")?;

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
    let (ring, drop_count) = configure_ebpf(&mut bpf, child_pid)?;

    let drop_count = move || -> Result<u64> { Ok(drop_count.get(&0, 0)?) };

    kill(child_pid, Signal::SIGCONT).context("failed to resume child")?;
    poll_ringbuf(agg, live_state, child_pid, ring, drop_count)?;

    agg.on_end();
    Ok(())
}

fn configure_ebpf(
    bpf: &mut Ebpf,
    child_pid: Pid,
) -> Result<(RingBuf<&MapData>, Array<&MapData, u64>), anyhow::Error> {
    {
        let map = bpf
            .map_mut("TARGET_TGID")
            .ok_or_else(|| anyhow!("BPF map TARGET_TGID not found"))?;
        let mut arr: Array<_, u32> = Array::try_from(map)?;
        arr.set(0, child_pid.as_raw() as u32, 0)
            .context("failed to set TARGET_TGID")?;
    }

    for name in TRACEPOINTS {
        let prog = bpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("BPF program {} not found", name))?;
        let prog: &mut TracePoint = prog.try_into()?;
        prog.load()?;
        prog.attach("syscalls", name)
            .with_context(|| format!("attach {}", name))?;
    }

    let io_map = bpf
        .map("IO_EVENTS")
        .ok_or_else(|| anyhow!("BPF map IO_EVENTS not found"))?;
    let ring = RingBuf::try_from(io_map)?;

    let drop_map = bpf
        .map("DROP_COUNT")
        .ok_or_else(|| anyhow!("BPF map DROP_COUNT not found"))?;
    let drop_count: Array<_, u64> = Array::try_from(drop_map)?;

    Ok((ring, drop_count))
}

fn poll_ringbuf<A: Aggregator, T>(
    agg: &mut A,
    live_state: Option<Arc<Mutex<LiveState>>>,
    child_pid: Pid,
    mut ring: RingBuf<&MapData>,
    dropped_events: T,
) -> Result<(), anyhow::Error>
where
    T: Fn() -> Result<u64, anyhow::Error>,
{
    let mut child_done = false;
    let mut last_dropped = 0;

    loop {
        let mut got_events = false;

        while let Some(item) = ring.next() {
            got_events = true;

            if item.len() >= std::mem::size_of::<IoEvent>() {
                let io_ev: IoEvent = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const _) };

                let current_drops = dropped_events()?;
                if current_drops != last_dropped {
                    agg.on_dropped(current_drops - last_dropped);
                    last_dropped = current_drops;
                }

                if let Some(ref state) = live_state {
                    let mut s = state.lock().unwrap();
                    s.child_pids.insert(io_ev.pid);
                }

                let ev = io_event_to_syscall_event(&io_ev);
                agg.on_event(&ev);
            }
        }

        if child_done && !got_events {
            break;
        }

        if !child_done {
            child_done = check_child_done(child_pid)?;
            agg.tick();
        }

        if !got_events {
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    Ok(())
}

fn spawn_stopped_child(
    cfg: &RunConfig,
    live_state: &Option<Arc<Mutex<LiveState>>>,
    use_pipes: bool,
    stdout_pipe: Option<(OwnedFd, OwnedFd)>,
    stderr_pipe: Option<(OwnedFd, OwnedFd)>,
) -> Result<Pid, anyhow::Error> {
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
    let kind = match io_ev.kind {
        KIND_READ => SyscallKind::Read,
        KIND_WRITE => SyscallKind::Write,
        KIND_PREAD => SyscallKind::Pread,
        KIND_PWRITE => SyscallKind::Pwrite,
        KIND_READV => SyscallKind::Readv,
        KIND_WRITEV => SyscallKind::Writev,
        KIND_SEND => SyscallKind::Send,
        KIND_RECV => SyscallKind::Recv,
        KIND_OPEN => SyscallKind::Open,
        KIND_CLOSE => SyscallKind::Close,
        KIND_FSYNC => SyscallKind::Fsync,
        KIND_MMAP => SyscallKind::Mmap,
        _ => SyscallKind::Other,
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
