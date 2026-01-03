use std::collections::{HashMap, VecDeque};

use time::OffsetDateTime;

use crate::model::{
    path::PathStats,
    pattern::PatternHint,
    phase::Phase,
    socket::SocketStats,
    syscall::{SyscallKind, SyscallStats},
};

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub cmdline: String,
    pub total_syscalls: u64,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,

    // Syscall aggregates
    pub by_kind: HashMap<SyscallKind, SyscallStats>,
    pub by_path: HashMap<String, PathStats>,
    pub by_socket: HashMap<String, SocketStats>,

    // Heuristic analysis results
    pub pattern_hints: Vec<PatternHint>,
    pub phases: Vec<Phase>,
}

/// Shared state for live view (very small on purpose).
#[derive(Debug, Clone, Default)]
pub struct LiveState {
    /// Snapshot of current aggregate over the whole run so far.
    pub summary: Option<RunSummary>,

    /// Sparkline data (syscalls/sec).
    pub rate_history: VecDeque<f64>,
    pub last_rate: f64,

    /// Captured stdout/stderr lines from the traced process.
    pub log_lines: VecDeque<String>,
}
