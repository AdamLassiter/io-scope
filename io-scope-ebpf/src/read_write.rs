use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use crate::{
    KIND_PREAD,
    KIND_PWRITE,
    KIND_READ,
    KIND_READV,
    KIND_WRITE,
    KIND_WRITEV,
    helpers::{handle_sys_enter_fd_at_16, handle_sys_exit_rw},
};

// ----------------------------------------------------------------------------
// read / write
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_read")]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_write")]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_read")]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_READ) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_write")]
pub fn sys_exit_write(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_WRITE) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// pread64 / pwrite64
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_pread64")]
pub fn sys_enter_pread64(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwrite64")]
pub fn sys_enter_pwrite64(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_pread64")]
pub fn sys_exit_pread64(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_PREAD) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_pwrite64")]
pub fn sys_exit_pwrite64(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_PWRITE) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// readv / writev
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_readv")]
pub fn sys_enter_readv(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_writev")]
pub fn sys_enter_writev(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_readv")]
pub fn sys_exit_readv(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_READV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_writev")]
pub fn sys_exit_writev(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_WRITEV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// preadv / pwritev
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_preadv")]
pub fn sys_enter_preadv(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwritev")]
pub fn sys_enter_pwritev(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_preadv")]
pub fn sys_exit_preadv(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_READV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_pwritev")]
pub fn sys_exit_pwritev(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_WRITEV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// preadv2 / pwritev2
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_preadv2")]
pub fn sys_enter_preadv2(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_pwritev2")]
pub fn sys_enter_pwritev2(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_preadv2")]
pub fn sys_exit_preadv2(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_READV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_pwritev2")]
pub fn sys_exit_pwritev2(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_WRITEV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}
