#![no_std]
#![no_main]
#![allow(static_mut_refs)]

mod helpers;
mod mmap;
mod open_close;
mod read_write;
mod send_recv;
mod splice_tee;

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerfEventArray},
};

#[repr(C)]
pub struct IoEvent {
    pub tgid: u32,
    pub pid: i32,
    pub fd: i32,
    pub bytes: i64,
    pub kind: u8,
}

// Match SyscallKind enum from userspace
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

#[map(name = "IO_EVENTS")]
static mut IO_EVENTS: PerfEventArray<IoEvent> = PerfEventArray::new(0);

#[map(name = "TARGET_TGID")]
static mut TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

// Store fd from sys_enter to use in sys_exit
#[map(name = "FD_BY_PID")]
static mut FD_BY_PID: HashMap<u64, i32> = HashMap::with_max_entries(10240, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
