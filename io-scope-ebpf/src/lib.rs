#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers,
    macros::{map, tracepoint},
    maps::{Array, HashMap, PerfEventArray},
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
static mut TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "FD_BY_PID")]
static mut FD_BY_PID: HashMap<u64, i32> = HashMap::with_max_entries(10240, 0);

#[tracepoint(category = "syscalls", name = "sys_enter_read")]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_rw(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_write")]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_rw(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn handle_sys_enter_rw(ctx: &TracePointContext) -> Result<u32, i64> {
    // struct trace_event_raw_sys_enter { trace_entry ent; long id; unsigned long args[6]; }
    // args[0] (fd) starts at offset 16 on x86_64.
    let fd = unsafe { ctx.read_at::<i32>(16)? };

    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    unsafe {
        FD_BY_PID.insert(&pid_tgid, &fd, 0)?;
    }

    Ok(0)
}

#[tracepoint(category = "syscalls", name = "sys_exit_read")]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, 0) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_write")]
pub fn sys_exit_write(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, 1) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn handle_sys_exit_rw(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    let bytes = unsafe { ctx.read_at::<i64>(16)? };
    if bytes <= 0 {
        return Ok(0);
    }

    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as i32;

    if !should_trace(tgid) {
        return Ok(0);
    }

    let fd = unsafe {
        match FD_BY_PID.get(&pid_tgid) {
            Some(fd) => *fd,
            None => -1,
        }
    };

    let ev = IoEvent {
        tgid,
        pid,
        fd,
        bytes,
        kind,
    };

    unsafe {
        IO_EVENTS.output(ctx, &ev, 0);
        FD_BY_PID.remove(&pid_tgid)?; // clean up
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

fn should_trace(tgid: u32) -> bool {
    unsafe {
        match TARGET_TGID.get(0) {
            // 0 means "no filter" (trace everything)
            Some(target) => *target == 0 || *target == tgid,
            None => true,
        }
    }
}
