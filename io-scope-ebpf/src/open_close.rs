use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use crate::{
    KIND_CLOSE,
    KIND_FSYNC,
    helpers::{
        handle_sys_enter_fd_at_16,
        handle_sys_enter_no_fd,
        handle_sys_exit_no_bytes,
        handle_sys_exit_open,
    },
};

// ----------------------------------------------------------------------------
// open / openat / openat2
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_open")]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_no_fd(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_no_fd(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat2")]
pub fn sys_enter_openat2(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_no_fd(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_open")]
pub fn sys_exit_open(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_open(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat")]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_open(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_openat2")]
pub fn sys_exit_openat2(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_open(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// close
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_close")]
pub fn sys_enter_close(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_close")]
pub fn sys_exit_close(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_no_bytes(&ctx, KIND_CLOSE) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// fsync / fdatasync
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_fsync")]
pub fn sys_enter_fsync(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_fdatasync")]
pub fn sys_enter_fdatasync(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_fsync")]
pub fn sys_exit_fsync(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_no_bytes(&ctx, KIND_FSYNC) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_fdatasync")]
pub fn sys_exit_fdatasync(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_no_bytes(&ctx, KIND_FSYNC) {
        Ok(v) => v,
        Err(_) => 0,
    }
}
