use aya_ebpf::{helpers::bpf_get_current_pid_tgid, programs::TracePointContext};

use crate::{DROP_COUNT, FD_BY_PID, IO_EVENTS, IoEvent, KIND_MMAP, KIND_OPEN, TARGET_TGID};

// ----------------------------------------------------------------------------
// Shared handler implementations
// ----------------------------------------------------------------------------

/// Handle sys_enter for syscalls where fd is at offset 16 (most common)
pub fn handle_sys_enter_fd_at_16(ctx: &TracePointContext) -> Result<u32, i64> {
    // Tracepoint args are 8-byte aligned; read as u64 then truncate
    let fd = unsafe { ctx.read_at::<u64>(16)? } as i32;

    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe {
        FD_BY_PID.insert(&pid_tgid, &fd, 0)?;
    }

    Ok(0)
}

/// Handle sys_enter for mmap where fd is at offset 48
pub fn handle_sys_enter_mmap(ctx: &TracePointContext) -> Result<u32, i64> {
    // mmap: addr(16), len(24), prot(32), flags(40), fd(48), off(56)
    let fd = unsafe { ctx.read_at::<u64>(48)? } as i32;

    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe {
        FD_BY_PID.insert(&pid_tgid, &fd, 0)?;
    }

    Ok(0)
}

/// Handle sys_enter for syscalls that don't have an fd on enter (open)
pub fn handle_sys_enter_no_fd(ctx: &TracePointContext) -> Result<u32, i64> {
    let _ = ctx; // Mark as intentionally unused

    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe {
        // Store -1 as placeholder
        FD_BY_PID.insert(&pid_tgid, &-1i32, 0)?;
    }

    Ok(0)
}

/// Handle sys_exit for read/write syscalls (return value is bytes)
fn emit_event(ev: IoEvent) {
    unsafe {
        if let Some(mut entry) = IO_EVENTS.reserve::<IoEvent>(0) {
            entry.write(ev);
            entry.submit(0);
        } else {
            // Ring buffer full - increment drop counter
            if let Some(count) = DROP_COUNT.get_ptr_mut(0) {
                *count += 1;
            }
        }
    }
}

pub fn handle_sys_exit_rw(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    let ret = unsafe { ctx.read_at::<i64>(16)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as i32;

    // Clean up fd map entry
    let fd = unsafe {
        match FD_BY_PID.get(&pid_tgid) {
            Some(fd) => {
                let f = *fd;
                let _ = FD_BY_PID.remove(&pid_tgid);
                f
            }
            None => -1,
        }
    };

    if !should_trace(tgid) {
        return Ok(0);
    }

    // Skip failed syscalls
    if ret < 0 {
        return Ok(0);
    }

    emit_event(IoEvent {
        tgid,
        pid,
        fd,
        bytes: ret,
        kind,
    });

    Ok(0)
}

/// Handle sys_exit for open (return value is fd)
pub fn handle_sys_exit_open(ctx: &TracePointContext) -> Result<u32, i64> {
    let ret = unsafe { ctx.read_at::<i64>(16)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as i32;

    // Clean up placeholder
    unsafe {
        let _ = FD_BY_PID.remove(&pid_tgid);
    }

    if !should_trace(tgid) {
        return Ok(0);
    }

    // Skip failed opens
    if ret < 0 {
        return Ok(0);
    }

    emit_event(IoEvent {
        tgid,
        pid,
        fd: ret as i32,
        bytes: 0,
        kind: KIND_OPEN,
    });

    Ok(0)
}

/// Handle sys_exit for syscalls without byte counts (close, fsync, mmap)
pub fn handle_sys_exit_no_bytes(ctx: &TracePointContext, kind: u8) -> Result<u32, i64> {
    let ret = unsafe { ctx.read_at::<i64>(16)? };

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as i32;

    let fd = unsafe {
        match FD_BY_PID.get(&pid_tgid) {
            Some(fd) => {
                let f = *fd;
                let _ = FD_BY_PID.remove(&pid_tgid);
                f
            }
            None => -1,
        }
    };

    if !should_trace(tgid) {
        return Ok(0);
    }

    // Skip failed syscalls (except mmap which returns MAP_FAILED as unsigned)
    if kind != KIND_MMAP && ret < 0 {
        return Ok(0);
    }

    emit_event(IoEvent {
        tgid,
        pid,
        fd,
        bytes: 0,
        kind,
    });

    Ok(0)
}

pub fn should_trace(tgid: u32) -> bool {
    unsafe {
        match TARGET_TGID.get(0) {
            Some(target) => *target == 0 || *target == tgid,
            None => true,
        }
    }
}
