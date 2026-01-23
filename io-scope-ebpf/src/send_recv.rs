use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use crate::{
    KIND_RECV, KIND_SEND, KIND_WRITE, helpers::{handle_sys_enter_fd_at_16, handle_sys_exit_no_bytes, handle_sys_exit_rw}
};

// ----------------------------------------------------------------------------
// sendto / recvfrom
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_sendto")]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_recvfrom")]
pub fn sys_enter_recvfrom(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_sendto")]
pub fn sys_exit_sendto(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_SEND) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_recvfrom")]
pub fn sys_exit_recvfrom(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_RECV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// sendmsg / recvmsg
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_sendmsg")]
pub fn sys_enter_sendmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_recvmsg")]
pub fn sys_enter_recvmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_sendmsg")]
pub fn sys_exit_sendmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_SEND) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_recvmsg")]
pub fn sys_exit_recvmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_RECV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// sendmmsg / recvmmsg (multiple messages)
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_sendmmsg")]
pub fn sys_enter_sendmmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_recvmmsg")]
pub fn sys_enter_recvmmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// Note: sendmmsg/recvmmsg return number of messages, not bytes
// We emit 0 bytes but still track the syscall
#[tracepoint(category = "syscalls", name = "sys_exit_sendmmsg")]
pub fn sys_exit_sendmmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_no_bytes(&ctx, KIND_SEND) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_recvmmsg")]
pub fn sys_exit_recvmmsg(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_no_bytes(&ctx, KIND_RECV) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

// ----------------------------------------------------------------------------
// sendfile (multiple messages)
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_sendfile64")]
pub fn sys_enter_sendfile64(ctx: TracePointContext) -> u32 {
    // sendfile64: out_fd(16), in_fd(24), offset(32), count(40)
    // Track out_fd as the destination
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_sendfile64")]
pub fn sys_exit_sendfile64(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_WRITE) {
        Ok(v) => v,
        Err(_) => 0,
    }
}