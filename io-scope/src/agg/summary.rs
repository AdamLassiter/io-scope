use std::collections::HashMap;

use time::{Duration, OffsetDateTime};

use crate::{
    agg::{
        Aggregator,
        is_read_like,
        is_write_like,
        pattern::build_pattern_hints,
        phase::build_phases,
    },
    model::{
        agg::RunSummary,
        path::PathStats,
        socket::SocketStats,
        syscall::{ResourceKind, SyscallEvent, SyscallKind, SyscallStats},
    },
};

#[derive(Debug, Clone, Default)]
pub struct TimeBin {
    pub syscalls: u64,
    pub bytes: u64,
}

pub struct SummaryAggregator {
    total_syscalls: u64,
    start: Option<OffsetDateTime>,
    end: Option<OffsetDateTime>,
    by_kind: HashMap<SyscallKind, SyscallStats>,
    by_path: HashMap<String, PathStats>,
    by_socket: HashMap<String, SocketStats>,
    bucket: Duration,
    bins: Vec<TimeBin>,
}

impl SummaryAggregator {
    pub fn new() -> Self {
        Self {
            total_syscalls: 0,
            start: None,
            end: None,
            by_kind: HashMap::new(),
            by_path: HashMap::new(),
            by_socket: HashMap::new(),
            bucket: Duration::milliseconds(200),
            bins: Vec::new(),
        }
    }

    /// Build a RunSummary snapshot from current state.
    /// cmdline will be filled by the caller (as in finalize()).
    pub fn snapshot(&self) -> RunSummary {
        let start = self.start.unwrap_or_else(OffsetDateTime::now_utc);
        let end = self.end.unwrap_or_else(OffsetDateTime::now_utc);

        let pattern_hints = build_pattern_hints(&self.by_kind, &self.by_path);
        let phases = build_phases(start, self.bucket, &self.bins);

        RunSummary {
            cmdline: String::new(),
            total_syscalls: self.total_syscalls,
            start,
            end,
            by_kind: self.by_kind.clone(),
            by_path: self.by_path.clone(),
            pattern_hints,
            phases,
            by_socket: self.by_socket.clone(), // NEW
        }
    }
}

impl Aggregator for SummaryAggregator {
    type Output = RunSummary;

    fn on_start(&mut self) {
        let now = OffsetDateTime::now_utc();
        self.start = Some(now);
        self.end = Some(now);
        self.bins.clear();
    }

    fn on_event(&mut self, event: &SyscallEvent) {
        self.total_syscalls += 1;
        self.end = Some(event.ts);

        // Per-kind stats: all kinds go here directly
        let entry = self.by_kind.entry(event.kind).or_default();
        entry.count += 1;
        entry.total_bytes += event.bytes;

        // Files
        if let (Some(path), Some(ResourceKind::File)) = (&event.resource, event.resource_kind) {
            let p = self.by_path.entry(path.clone()).or_default();
            p.bytes += event.bytes;
            if is_read_like(event.kind) {
                p.reads += 1;
            }
            if is_write_like(event.kind) {
                p.writes += 1;
            }
            if event.kind == SyscallKind::Open {
                p.opens += 1;
            }
            if event.kind == SyscallKind::Close {
                p.closes += 1;
            }
        }

        // Sockets
        if let (Some(peer), Some(ResourceKind::Socket)) = (&event.resource, event.resource_kind) {
            let s = self.by_socket.entry(peer.clone()).or_default();
            if is_read_like(event.kind) {
                s.read_calls += 1;
                s.read_bytes += event.bytes;
            }
            if is_write_like(event.kind) {
                s.write_calls += 1;
                s.write_bytes += event.bytes;
            }
        }

        // Timeline
        if let Some(start) = self.start {
            let dt = event.ts - start;
            let ms = dt.whole_milliseconds();
            if ms >= 0 {
                let idx = (ms / self.bucket.whole_milliseconds()) as usize;
                if idx >= self.bins.len() {
                    self.bins.resize(idx + 1, TimeBin::default());
                }
                let bin = &mut self.bins[idx];
                bin.syscalls += 1;
                if is_read_like(event.kind) || is_write_like(event.kind) {
                    bin.bytes += event.bytes;
                }
            }
        }
    }

    fn on_end(&mut self) {
        if self.end.is_none() {
            self.end = Some(OffsetDateTime::now_utc());
        }
    }

    fn finalize(self) -> Self::Output {
        let start = self.start.unwrap_or_else(OffsetDateTime::now_utc);
        let end = self.end.unwrap_or_else(OffsetDateTime::now_utc);

        let pattern_hints = build_pattern_hints(&self.by_kind, &self.by_path);
        let phases = build_phases(start, self.bucket, &self.bins);

        RunSummary {
            cmdline: String::new(),
            total_syscalls: self.total_syscalls,
            start,
            end,
            by_kind: self.by_kind,
            by_path: self.by_path,
            pattern_hints,
            phases,
            by_socket: self.by_socket,
        }
    }
}
