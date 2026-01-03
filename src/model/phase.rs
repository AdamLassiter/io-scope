use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PhaseKind {
    IoHeavy,
    CpuHeavy,
}

#[derive(Debug, Clone)]
pub struct Phase {
    pub kind: PhaseKind,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
    pub syscalls: u64,
    pub bytes: u64,
}
