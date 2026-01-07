use crate::model::syscall::{SyscallEvent, SyscallKind};

pub mod live;
mod pattern;
mod phase;
pub mod summary;

pub trait Aggregator {
    type Output;

    fn on_start(&mut self);
    fn on_event(&mut self, event: &SyscallEvent);
    fn on_end(&mut self);
    fn finalize(self) -> Self::Output;
    fn tick(&mut self) {}
}

fn is_read_like(kind: SyscallKind) -> bool {
    matches!(
        kind,
        SyscallKind::Read | SyscallKind::Pread | SyscallKind::Readv | SyscallKind::Recv
    )
}

fn is_write_like(kind: SyscallKind) -> bool {
    matches!(
        kind,
        SyscallKind::Write | SyscallKind::Pwrite | SyscallKind::Writev | SyscallKind::Send
    )
}
