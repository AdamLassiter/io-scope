use time::{Duration, OffsetDateTime};

use crate::{
    agg::summary::TimeBin,
    model::phase::{Phase, PhaseKind},
};

pub fn build_phases(start: OffsetDateTime, bucket: Duration, bins: &[TimeBin]) -> Vec<Phase> {
    if bins.is_empty() {
        return Vec::new();
    }

    // Basic stats to set relative thresholds
    let mut max_bytes = 0_u64;
    let mut max_syscalls = 0_u64;
    let mut total_bytes = 0_u64;
    let mut total_syscalls = 0_u64;

    for b in bins {
        if b.bytes > max_bytes {
            max_bytes = b.bytes;
        }
        if b.syscalls > max_syscalls {
            max_syscalls = b.syscalls;
        }
        total_bytes += b.bytes;
        total_syscalls += b.syscalls;
    }

    if total_syscalls == 0 {
        return Vec::new();
    }

    // Thresholds relative to peak
    let io_heavy_bytes_thresh = (max_bytes as f64 * 0.5).max(1.0) as u64;
    let io_heavy_syscalls_thresh = (max_syscalls as f64 * 0.5).max(1.0) as u64;

    let mut result = Vec::new();
    let mut current_kind: Option<PhaseKind> = None;
    let mut current_start_idx: usize = 0;
    let mut acc_syscalls: u64 = 0;
    let mut acc_bytes: u64 = 0;

    for (idx, bin) in bins.iter().enumerate() {
        let kind = if bin.bytes >= io_heavy_bytes_thresh || bin.syscalls >= io_heavy_syscalls_thresh
        {
            PhaseKind::IoHeavy
        } else if bin.syscalls > 0 && bin.bytes == 0 {
            PhaseKind::CpuHeavy
        } else {
            // very low / mixed; we ignore as standalone phases
            // but we still accumulate into neighboring phases
            if let Some(_k) = current_kind {
                // extend current
                acc_syscalls += bin.syscalls;
                acc_bytes += bin.bytes;
                continue;
            } else {
                // idle/mixed before first phase
                continue;
            }
        };

        match current_kind {
            Some(k) if k == kind => {
                // extend current phase
                acc_syscalls += bin.syscalls;
                acc_bytes += bin.bytes;
            }
            Some(k) => {
                // close previous phase
                let phase = make_phase(
                    start,
                    bucket,
                    current_start_idx,
                    idx,
                    k,
                    acc_syscalls,
                    acc_bytes,
                );
                result.push(phase);

                // start new
                current_kind = Some(kind);
                current_start_idx = idx;
                acc_syscalls = bin.syscalls;
                acc_bytes = bin.bytes;
            }
            None => {
                current_kind = Some(kind);
                current_start_idx = idx;
                acc_syscalls = bin.syscalls;
                acc_bytes = bin.bytes;
            }
        }
    }

    if let Some(k) = current_kind {
        let phase = make_phase(
            start,
            bucket,
            current_start_idx,
            bins.len(),
            k,
            acc_syscalls,
            acc_bytes,
        );
        result.push(phase);
    }

    result
}

fn make_phase(
    start: OffsetDateTime,
    bucket: Duration,
    start_idx: usize,
    end_idx: usize,
    kind: PhaseKind,
    syscalls: u64,
    bytes: u64,
) -> Phase {
    let start_ts = start + bucket * (start_idx as i32);
    let end_ts = start + bucket * (end_idx as i32);
    Phase {
        kind,
        start: start_ts,
        end: end_ts,
        syscalls,
        bytes,
    }
}
