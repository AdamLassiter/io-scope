use std::collections::HashMap;

use time::{Duration, OffsetDateTime};

use crate::model::{
    bin::TimeBin,
    phase::{IoCategory, IoPattern, Phase, PhaseKind},
};

/// Thresholds for phase detection (can be tuned).
struct Thresholds {
    /// Fraction of peak syscalls to consider "active".
    active_frac: f64,
    /// Bytes per call below this is "bursty".
    bursty_threshold: f64,
    /// Bytes per call above this is "streaming".
    streaming_threshold: f64,
    /// Minimum syscalls to not be "idle".
    min_syscalls: u64,
    /// Minimum bytes to be considered IO (vs compute).
    min_bytes_for_io: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            active_frac: 0.2,
            bursty_threshold: 256.0,
            streaming_threshold: 4096.0,
            min_syscalls: 1,
            min_bytes_for_io: 1,
        }
    }
}

pub fn build_phases(start: OffsetDateTime, bucket: Duration, bins: &[TimeBin]) -> Vec<Phase> {
    if bins.is_empty() {
        return Vec::new();
    }

    let thresh = Thresholds::default();

    // Compute global stats for relative thresholds
    let max_syscalls = bins.iter().map(|b| b.syscalls).max().unwrap_or(0);
    let active_syscall_thresh = ((max_syscalls as f64) * thresh.active_frac).max(1.0) as u64;

    let mut result = Vec::new();
    let mut current: Option<PhaseBuilder> = None;

    for (idx, bin) in bins.iter().enumerate() {
        let bin_kind = classify_bin(bin, &thresh, active_syscall_thresh);

        match &mut current {
            Some(builder) if builder.can_extend(&bin_kind) => {
                builder.extend(bin);
            }
            Some(builder) => {
                // Finalize previous phase
                if let Some(phase) = builder.build(start, bucket) {
                    result.push(phase);
                }
                current = Some(PhaseBuilder::new(idx, bin_kind, bin));
            }
            None => {
                current = Some(PhaseBuilder::new(idx, bin_kind, bin));
            }
        }
    }

    // Finalize last phase
    if let Some(builder) = current
        && let Some(phase) = builder.build(start, bucket)
    {
        result.push(phase);
    }

    result
}

fn classify_bin(bin: &TimeBin, thresh: &Thresholds, active_thresh: u64) -> PhaseKind {
    if bin.syscalls < thresh.min_syscalls || bin.syscalls < active_thresh / 4 {
        return PhaseKind::Idle;
    }

    if bin.bytes < thresh.min_bytes_for_io {
        return PhaseKind::Compute;
    }

    let category = dominant_io_category(bin);
    let pattern = classify_pattern(bin.avg_bytes_per_call(), thresh);

    PhaseKind::Io { category, pattern }
}

fn dominant_io_category(bin: &TimeBin) -> IoCategory {
    if bin.by_resource.is_empty() {
        return IoCategory::Mixed;
    }

    // Find dominant by bytes (prefer bytes over calls for IO classification)
    let mut by_category: HashMap<IoCategory, u64> = HashMap::new();
    for (res_kind, io) in &bin.by_resource {
        let cat = IoCategory::from_resource(*res_kind);
        *by_category.entry(cat).or_default() += io.bytes;
    }

    // If nearly all bytes from one category (>70%), use it; else Mixed
    let total: u64 = by_category.values().sum();
    if total == 0 {
        return IoCategory::Mixed;
    }

    for (cat, bytes) in &by_category {
        if *bytes as f64 / total as f64 > 0.5 {
            return *cat;
        }
    }

    IoCategory::Mixed
}

fn classify_pattern(avg_bytes: f64, thresh: &Thresholds) -> IoPattern {
    if avg_bytes < thresh.bursty_threshold {
        IoPattern::Bursty
    } else if avg_bytes > thresh.streaming_threshold {
        IoPattern::Streaming
    } else {
        IoPattern::Balanced
    }
}

struct PhaseBuilder {
    start_idx: usize,
    end_idx: usize,
    kind: PhaseKind,
    syscalls: u64,
    bytes: u64,
}

impl PhaseBuilder {
    fn new(idx: usize, kind: PhaseKind, bin: &TimeBin) -> Self {
        Self {
            start_idx: idx,
            end_idx: idx + 1,
            kind,
            syscalls: bin.syscalls,
            bytes: bin.bytes,
        }
    }

    fn can_extend(&self, other_kind: &PhaseKind) -> bool {
        // Allow extending if same high-level category
        match (&self.kind, other_kind) {
            (PhaseKind::Idle, PhaseKind::Idle) => true,
            (PhaseKind::Compute, PhaseKind::Compute) => true,
            (PhaseKind::Io { category: c1, .. }, PhaseKind::Io { category: c2, .. }) => c1 == c2,
            // Absorb idle bins into active phases
            (PhaseKind::Io { .. }, PhaseKind::Idle) => true,
            (PhaseKind::Compute, PhaseKind::Idle) => true,
            _ => false,
        }
    }

    fn extend(&mut self, bin: &TimeBin) {
        self.end_idx += 1;
        self.syscalls += bin.syscalls;
        self.bytes += bin.bytes;
    }

    fn build(&self, start: OffsetDateTime, bucket: Duration) -> Option<Phase> {
        // Skip trivial idle phases
        if matches!(self.kind, PhaseKind::Idle) && self.syscalls == 0 {
            return None;
        }

        let phase_start = start + bucket * (self.start_idx as i32);
        let phase_end = start + bucket * (self.end_idx as i32);
        let avg = if self.syscalls > 0 {
            self.bytes as f64 / self.syscalls as f64
        } else {
            0.0
        };

        Some(Phase {
            kind: self.kind,
            start: phase_start,
            end: phase_end,
            syscalls: self.syscalls,
            bytes: self.bytes,
            avg_bytes_per_call: avg,
        })
    }
}
