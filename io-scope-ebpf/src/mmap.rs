use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

use crate::{
    KIND_MMAP,
    helpers::{handle_sys_enter_mmap, handle_sys_exit_no_bytes},
};

// ----------------------------------------------------------------------------
// mmap (fd is at offset 48)
// ----------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_mmap")]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    match handle_sys_enter_mmap(&ctx) {
        Ok(v) => v,
        Err(_) => 0,
    }
}

#[tracepoint(category = "syscalls", name = "sys_exit_mmap")]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    match handle_sys_exit_no_bytes(&ctx, KIND_MMAP) {
        Ok(v) => v,
        Err(_) => 0,
    }
}
