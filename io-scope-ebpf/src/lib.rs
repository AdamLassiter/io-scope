#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};

#[repr(C)]
pub struct IoEvent {
    pub tgid: u32,
    pub pid: i32,
    pub fd: i32,
    pub bytes: i64,
    pub kind: u8,
}

#[map(name = "IO_EVENTS")]
static mut IO_EVENTS: PerfEventArray<IoEvent> = PerfEventArray::new(0);

#[map(name = "TARGET_TGID")]
static mut TARGET_TGID: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[tracepoint(category = "syscalls", name = "sys_exit_read")]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match unsafe { handle_sys_exit_rw(&ctx, 0) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_write")]
pub fn sys_exit_write(ctx: TracePointContext) -> u32 {
    match unsafe { handle_sys_exit_rw(&ctx, 1) } {
        Ok(v) => v,
        Err(_) => 0,
    }
}

unsafe fn handle_sys_exit_rw(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    let ret = unsafe { ctx.read_at::<i64>(16)? };
    if ret <= 0 {
        return Ok(0);
    }

    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as i32;

    if let Some(target) = unsafe { TARGET_TGID.get(&0) } {
        if *target != tgid {
            return Ok(0);
        }
    }

    let ev = IoEvent {
        tgid,
        pid,
        fd: -1,
        bytes: ret,
        kind,
    };

    let cpu = unsafe { helpers::bpf_get_smp_processor_id() };
    unsafe {
        IO_EVENTS.output(ctx, &ev, cpu);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
