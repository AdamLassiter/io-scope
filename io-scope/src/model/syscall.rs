use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ResourceKind {
    File,
    Socket,
    Pipe,
    Tty,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SyscallKind {
    Read,
    Write,
    Pread,
    Pwrite,
    Readv,
    Writev,
    Send,
    Recv,
    Open,
    Close,
    Fsync,
    Mmap,
    Other,
}

/// One completed syscall (we emit only on syscall *exit*).
#[derive(Debug, Clone)]
pub struct SyscallEvent {
    pub pid: i32,
    pub ts: OffsetDateTime,
    pub kind: SyscallKind,
    pub fd: Option<i32>,
    pub bytes: u64,
    pub resource: Option<String>,
    pub resource_kind: Option<ResourceKind>,
}

#[derive(Debug, Clone, Default)]
pub struct SyscallStats {
    pub count: u64,
    pub total_bytes: u64,
}

/// Stats broken down by resource kind (disk, network, etc.)
#[derive(Debug, Clone, Default)]
pub struct KindStats {
    pub calls: u64,
    pub bytes: u64,
}
