use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    EbpfLoader,
    maps::{
        HashMap as AyaHashMap,
        perf::{Events, PerfEventArray},
    },
    programs::TracePoint,
    util::online_cpus,
};
use time::OffsetDateTime;

use crate::{
    agg::Aggregator,
    model::{
        agg::LiveState,
        cli::RunConfig,
        syscall::{SyscallEvent, SyscallKind},
    },
    trace::{
        TraceProvider,
        socket::{SocketTable, resolve_fd_info},
    },
};

// Mirror of IoEvent from BPF side
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct IoEvent {
    tgid: u32,
    pid: i32,
    fd: i32,
    bytes: i64,
    kind: u8, // 0 = read-like, 1 = write-like
    _pad: [u8; 3],
}

pub struct EbpfTracer {
    bpf: Option<Ebpf>,
}

impl EbpfTracer {
    pub fn new() -> Result<Self> {
        // For now: load BPF path from env.
        // You can later embed it with include_bytes_aligned!.
        let path = std::env::var("IO_SCOPE_EBPF_PATH")
            .context("IO_SCOPE_EBPF_PATH not set; did build your eBPF object?")?;
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
        _live_state: Option<Arc<Mutex<LiveState>>>,
    ) -> Result<()> {
        run_linux_ebpf(cfg, agg, self.bpf.take())
    }
}

fn run_linux_ebpf<A: Aggregator>(
    cfg: &RunConfig,
    agg: &mut A,
    bpf_opt: Option<Ebpf>,
) -> Result<()> {
    use std::process::Command;

    use bytes::BytesMut;

    let mut bpf = bpf_opt.context("BPF object already used or not initialized")?;

    agg.on_start();

    // Spawn child normally
    let mut cmd = Command::new(&cfg.cmd);
    cmd.args(&cfg.args);
    let mut child = cmd.spawn().context("failed to spawn child process")?;
    let child_pid = child.id();

    // Set TARGET_TGID[0] = child_pid in BPF map
    {
        let map = bpf
            .map_mut("TARGET_TGID")
            .ok_or_else(|| anyhow!("BPF map TARGET_TGID not found"))?;
        let mut map: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(map)?;
        map.insert(0, child_pid, 0)
            .context("failed to set TARGET_TGID")?;
    }

    // Attach tracepoints: sys_exit_read / sys_exit_write
    {
        let prog = bpf
            .program_mut("sys_exit_read")
            .ok_or_else(|| anyhow!("BPF program sys_exit_read not found"))?;
        let prog: &mut TracePoint = prog.try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_exit_read")
            .context("attach sys_exit_read")?;

        let prog = bpf
            .program_mut("sys_exit_write")
            .ok_or_else(|| anyhow!("BPF program sys_exit_write not found"))?;
        let prog: &mut TracePoint = prog.try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_exit_write")
            .context("attach sys_exit_write")?;
    }

    // Set up perf reader on IO_EVENTS (sync)
    let io_map = bpf
        .map_mut("IO_EVENTS")
        .ok_or_else(|| anyhow!("BPF map IO_EVENTS not found"))?;
    let mut perf = PerfEventArray::try_from(io_map)?;

    // Build per-CPU buffers
    let cpus = online_cpus().map_err(|(s, e)| anyhow!("online_cpus failed: {s}: {e}"))?;
    if cpus.is_empty() {
        bail!("no online CPUs found");
    }

    struct CpuBuf<T> {
        buf: aya::maps::perf::PerfEventArrayBuffer<T>,
        slots: Vec<BytesMut>,
    }

    let mut per_cpu = Vec::<CpuBuf<_>>::new();
    const SLOTS_PER_CPU: usize = 8;

    for cpu in cpus {
        let buf = perf.open(cpu, None)?;
        let mut slots = Vec::with_capacity(SLOTS_PER_CPU);
        for _ in 0..SLOTS_PER_CPU {
            slots.push(BytesMut::with_capacity(4096));
        }
        per_cpu.push(CpuBuf { buf, slots });
    }

    // Simple polling loop until child exits
    loop {
        let child_done = match child.try_wait()? {
            Some(_status) => true,
            None => false,
        };

        for cpu_buf in per_cpu.iter_mut() {
            let events = cpu_buf
                .buf
                .read_events(&mut cpu_buf.slots)
                .unwrap_or(Events { read: 0, lost: 0 });

            let read = events.read;
            if read == 0 {
                continue;
            }

            for i in 0..read {
                let data = &cpu_buf.slots[i];
                if data.len() < std::mem::size_of::<IoEvent>() {
                    continue;
                }

                let io_ev: IoEvent =
                    unsafe { std::ptr::read_unaligned(data.as_ptr() as *const IoEvent) };

                if let Some(ev) = io_event_to_syscall_event(&io_ev) {
                    agg.on_event(&ev);
                }
            }
        }

        if child_done {
            break;
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    agg.on_end();
    Ok(())
}

fn io_event_to_syscall_event(io_ev: &IoEvent) -> Option<SyscallEvent> {
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

    let mut socket_table = SocketTable::new();
    let (resource, resource_kind) = if let Some((resource, resource_kind)) =
        resolve_fd_info(io_ev.pid, io_ev.fd, &mut socket_table)
    {
        (Some(resource), Some(resource_kind))
    } else {
        (None, None)
    };

    Some(SyscallEvent {
        pid: io_ev.pid,
        ts: OffsetDateTime::now_utc(),
        kind,
        fd: Some(io_ev.fd),
        bytes,
        resource,
        resource_kind,
    })
}
