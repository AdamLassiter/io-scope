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
        bin::{AggregatedTotals, TimeBin},
        syscall::{ResourceKind, SyscallEvent, SyscallKind},
    },
};

pub struct SummaryAggregator {
    start: Option<OffsetDateTime>,
    end: Option<OffsetDateTime>,
    bucket: Duration,
    bins: Vec<TimeBin>,
}

impl SummaryAggregator {
    pub fn new() -> Self {
        Self {
            start: None,
            end: None,
            bucket: Duration::milliseconds(100),
            bins: Vec::new(),
        }
    }

    fn bin_index(&self, ts: OffsetDateTime) -> Option<usize> {
        let start = self.start?;
        let dt = ts - start;
        let ms = dt.whole_milliseconds();
        if ms >= 0 {
            Some((ms / self.bucket.whole_milliseconds()) as usize)
        } else {
            None
        }
    }

    fn ensure_bin(&mut self, idx: usize) -> &mut TimeBin {
        if idx >= self.bins.len() {
            self.bins.resize_with(idx + 1, TimeBin::default);
        }
        &mut self.bins[idx]
    }

    pub fn extend_bins_to(&mut self, ts: OffsetDateTime) {
        let Some(start) = self.start else { return };
        let dt = ts - start;
        let ms = dt.whole_milliseconds();
        if ms < 0 {
            return;
        }

        let idx = (ms / self.bucket.whole_milliseconds()) as usize;
        if idx >= self.bins.len() {
            self.bins.resize_with(idx + 1, TimeBin::default);
        }
        self.end = Some(ts);
    }

    fn record_event(&mut self, event: &SyscallEvent) {
        let Some(idx) = self.bin_index(event.ts) else {
            return;
        };

        let bin = self.ensure_bin(idx);
        bin.syscalls += 1;

        // Per-kind stats
        let kind_entry = bin.by_kind.entry(event.kind).or_default();
        kind_entry.count += 1;
        kind_entry.total_bytes += event.bytes;

        // Track bytes for read/write syscalls
        if is_read_like(event.kind) || is_write_like(event.kind) {
            bin.bytes += event.bytes;

            // Track by resource kind
            if let Some(res_kind) = event.resource_kind {
                let io_entry = bin.by_resource.entry(res_kind).or_default();
                io_entry.calls += 1;
                io_entry.bytes += event.bytes;
            }
        }

        // Files
        if let (Some(path), Some(ResourceKind::File)) = (&event.resource, event.resource_kind) {
            let p = bin.by_path.entry(path.clone()).or_default();
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
            let s = bin.by_socket.entry(peer.clone()).or_default();
            if is_read_like(event.kind) {
                s.read_calls += 1;
                s.read_bytes += event.bytes;
            }
            if is_write_like(event.kind) {
                s.write_calls += 1;
                s.write_bytes += event.bytes;
            }
        }
    }

    fn build_summary(&self) -> RunSummary {
        let start = self.start.unwrap_or_else(OffsetDateTime::now_utc);
        let end = self.end.unwrap_or_else(OffsetDateTime::now_utc);

        let totals = AggregatedTotals::from_bins(&self.bins);
        let pattern_hints = build_pattern_hints(&totals);
        let phases = build_phases(start, self.bucket, &self.bins);

        RunSummary {
            cmdline: String::new(),
            total_syscalls: totals.total_syscalls,
            total_dropped: totals.total_dropped,
            total_bytes: totals.total_bytes,
            start: Some(start),
            end: Some(end),
            bucket_ms: self.bucket.whole_milliseconds(),
            bins: self.bins.clone(),
            by_kind: totals.by_kind,
            by_path: totals.by_path,
            by_socket: totals.by_socket,
            by_resource: totals.by_resource,
            by_pid: totals.by_pid,
            pattern_hints,
            phases,
        }
    }

    pub fn snapshot(&self) -> RunSummary {
        self.build_summary()
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
        self.end = Some(event.ts);
        self.record_event(event);
    }
    
    fn on_dropped(&mut self, count: u64) {
        let Some(idx) = self.bin_index(OffsetDateTime::now_utc()) else {
            return;
        };
        let bin = self.ensure_bin(idx);
        bin.dropped += count;
    }

    fn on_end(&mut self) {
        if self.end.is_none() {
            self.end = Some(OffsetDateTime::now_utc());
        }
    }

    fn tick(&mut self) {}

    fn finalize(self) -> Self::Output {
        self.build_summary()
    }
}
