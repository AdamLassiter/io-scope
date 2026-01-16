use crate::model::{
    bin::AggregatedTotals,
    pattern::{HintLevel, PatternHint},
    syscall::{KindStats, ResourceKind, SyscallKind},
};

pub fn build_pattern_hints(totals: &AggregatedTotals) -> Vec<PatternHint> {
    let mut hints = Vec::new();

    // Analyze by syscall kind
    add_io_size_hints(&mut hints, totals);

    // Analyze by resource type
    add_resource_hints(&mut hints, &totals.by_resource);

    // Path-level hints
    add_path_hints(&mut hints, totals);

    hints
}

fn add_io_size_hints(hints: &mut Vec<PatternHint>, totals: &AggregatedTotals) {
    let mut read_calls = 0_u64;
    let mut read_bytes = 0_u64;
    let mut write_calls = 0_u64;
    let mut write_bytes = 0_u64;

    for (kind, stats) in &totals.by_kind {
        if is_read_like(*kind) {
            read_calls += stats.count;
            read_bytes += stats.total_bytes;
        }
        if is_write_like(*kind) {
            write_calls += stats.count;
            write_bytes += stats.total_bytes;
        }
    }

    if read_calls > 1000 {
        let avg = read_bytes as f64 / read_calls as f64;
        if avg < 128.0 {
            hints.push(PatternHint {
                level: HintLevel::Warn,
                title: "Many tiny reads".to_string(),
                detail: format!(
                    "{} read calls, avg {:.1} bytes/call. Consider buffering.",
                    read_calls, avg
                ),
            });
        } else if avg < 512.0 && read_calls > 10000 {
            hints.push(PatternHint {
                level: HintLevel::Info,
                title: "Small reads".to_string(),
                detail: format!(
                    "{} read calls, avg {:.1} bytes/call. Larger buffers may help.",
                    read_calls, avg
                ),
            });
        }
    }

    if write_calls > 1000 {
        let avg = write_bytes as f64 / write_calls as f64;
        if avg < 128.0 {
            hints.push(PatternHint {
                level: HintLevel::Warn,
                title: "Many tiny writes".to_string(),
                detail: format!(
                    "{} write calls, avg {:.1} bytes/call. Consider batching.",
                    write_calls, avg
                ),
            });
        }
    }
}

fn add_resource_hints(
    hints: &mut Vec<PatternHint>,
    by_resource: &std::collections::HashMap<ResourceKind, KindStats>,
) {
    // Check for high network IO with small packets
    if let Some(net_io) = by_resource.get(&ResourceKind::Socket)
        && net_io.calls > 500
    {
        let avg = net_io.bytes as f64 / net_io.calls as f64;
        if avg < 100.0 {
            hints.push(PatternHint {
                    level: HintLevel::Warn,
                    title: "Chatty network IO".to_string(),
                    detail: format!(
                        "{} network calls, avg {:.1} bytes. Consider batching or using larger messages.",
                        net_io.calls, avg
                    ),
                });
        }
    }

    // Check for pipe thrashing
    if let Some(pipe_io) = by_resource.get(&ResourceKind::Pipe)
        && pipe_io.calls > 10000
    {
        let avg = pipe_io.bytes as f64 / pipe_io.calls as f64;
        if avg < 64.0 {
            hints.push(PatternHint {
                level: HintLevel::Info,
                title: "High pipe traffic".to_string(),
                detail: format!(
                    "{} pipe operations, avg {:.1} bytes. Consider buffering pipe IO.",
                    pipe_io.calls, avg
                ),
            });
        }
    }

    // Check disk vs network balance
    let disk_bytes = by_resource
        .get(&ResourceKind::File)
        .map(|io| io.bytes)
        .unwrap_or(0);
    let net_bytes = by_resource
        .get(&ResourceKind::Socket)
        .map(|io| io.bytes)
        .unwrap_or(0);

    if disk_bytes > 0 && net_bytes > 0 {
        let total = disk_bytes + net_bytes;
        let disk_pct = disk_bytes as f64 / total as f64 * 100.0;
        let net_pct = net_bytes as f64 / total as f64 * 100.0;

        if disk_pct > 80.0 {
            hints.push(PatternHint {
                level: HintLevel::Info,
                title: "Disk-dominated workload".to_string(),
                detail: format!("{:.0}% disk, {:.0}% network by bytes.", disk_pct, net_pct),
            });
        } else if net_pct > 80.0 {
            hints.push(PatternHint {
                level: HintLevel::Info,
                title: "Network-dominated workload".to_string(),
                detail: format!("{:.0}% network, {:.0}% disk by bytes.", net_pct, disk_pct),
            });
        }
    }
}

fn add_path_hints(hints: &mut Vec<PatternHint>, totals: &AggregatedTotals) {
    for (path, stats) in &totals.by_path {
        // Hot small files
        if stats.bytes > 0 && stats.bytes < 4 * 1024 && stats.reads > 100 {
            hints.push(PatternHint {
                level: HintLevel::Info,
                title: "Hot small file".to_string(),
                detail: format!(
                    "{}: {} reads, {} bytes. Consider caching.",
                    path, stats.reads, stats.bytes
                ),
            });
        }

        // Open/close storms
        let open_close = stats.opens + stats.closes;
        if open_close > 200 && stats.bytes < 1024 * 1024 {
            hints.push(PatternHint {
                level: HintLevel::Warn,
                title: "Frequent open/close".to_string(),
                detail: format!(
                    "{}: {} open/close ops, {} bytes. Keep file open.",
                    path, open_close, stats.bytes
                ),
            });
        }
    }
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
