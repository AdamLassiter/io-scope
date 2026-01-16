use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use crate::{
    KIND_READ,
    helpers::{handle_sys_enter_fd_at_16, handle_sys_exit_rw},
};

// ----------------------------------------------------------------------------
// splice / tee / copy_file_range (zero-copy)
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_splice")]
pub fn sys_enter_splice(ctx: TracePointContext) -> u32 {
    // fd_in at offset 16
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_splice")]
pub fn sys_exit_splice(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_READ) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_enter_copy_file_range")]
pub fn sys_enter_copy_file_range(ctx: TracePointContext) -> u32 {
    // fd_in at offset 16
    match handle_sys_enter_fd_at_16(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_copy_file_range")]
pub fn sys_exit_copy_file_range(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_rw(&ctx, KIND_READ) {
        Ok(v) => v,
        Err(_) => 0,
    }
}
