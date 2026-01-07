use std::collections::{HashMap, VecDeque};

use time::OffsetDateTime;

use crate::model::{
    bin::{IoByKind, TimeBin}, path::PathStats, pattern::PatternHint, phase::Phase, socket::SocketStats, syscall::{ResourceKind, SyscallKind, SyscallStats}
};

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub cmdline: String,
    pub total_syscalls: u64,
    pub total_bytes: u64,
    pub start: Option<OffsetDateTime>,
    pub end: Option<OffsetDateTime>,
    pub bucket_ms: i128,
    pub bins: Vec<TimeBin>,

    // Syscall aggregates
    pub by_kind: HashMap<SyscallKind, SyscallStats>,
    pub by_path: HashMap<String, PathStats>,
    pub by_socket: HashMap<String, SocketStats>,
    pub by_resource: HashMap<ResourceKind, IoByKind>,

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
