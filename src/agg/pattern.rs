use std::collections::HashMap;

use crate::{
    agg::{is_read_like, is_write_like},
    model::{
        path::PathStats,
        pattern::{HintLevel, PatternHint},
        syscall::{SyscallKind, SyscallStats},
    },
};

pub fn build_pattern_hints(
    by_kind: &HashMap<SyscallKind, SyscallStats>,
    by_path: &HashMap<String, PathStats>,
) -> Vec<PatternHint> {
    let mut hints = Vec::new();

    // Aggregate read-like
    let mut read_calls = 0_u64;
    let mut read_bytes = 0_u64;
    for (k, s) in by_kind {
        if is_read_like(*k) {
            read_calls += s.count;
            read_bytes += s.total_bytes;
        }
    }

    if read_calls > 0 {
        let avg = read_bytes as f64 / read_calls as f64;
        if read_calls > 1000 && avg < 128.0 {
            hints.push(PatternHint {
                level: HintLevel::Warn,
                title: "Many tiny reads".to_string(),
                detail: format!(
                    "{} read-like calls, avg {:.1} bytes/call. \
                     Consider buffering or larger reads.",
                    read_calls, avg
                ),
            });
        }
    }

    // Aggregate write-like
    let mut write_calls = 0_u64;
    let mut write_bytes = 0_u64;
    for (k, s) in by_kind {
        if is_write_like(*k) {
            write_calls += s.count;
            write_bytes += s.total_bytes;
        }
    }

    if write_calls > 0 {
        let avg = write_bytes as f64 / write_calls as f64;
        if write_calls > 1000 && avg < 128.0 {
            hints.push(PatternHint {
                level: HintLevel::Warn,
                title: "Many tiny writes".to_string(),
                detail: format!(
                    "{} write-like calls, avg {:.1} bytes/call. \
                     Consider batching writes.",
                    write_calls, avg
                ),
            });
        }
    }

    // Hot small files / open-close storms unchanged
    for (path, stats) in by_path {
        if stats.bytes > 0 && stats.bytes < 4 * 1024 && stats.reads > 100 {
            hints.push(PatternHint {
                level: HintLevel::Info,
                title: "Hot small file".to_string(),
                detail: format!(
                    "{}: {} reads, {} bytes. \
                     Consider caching this in memory.",
                    path, stats.reads, stats.bytes
                ),
            });
        }
    }

    for (path, stats) in by_path {
        let open_close = stats.opens + stats.closes;
        if open_close > 200 && stats.bytes < 1024 * 1024 {
            hints.push(PatternHint {
                level: HintLevel::Warn,
                title: "Frequent open/close on same path".to_string(),
                detail: format!(
                    "{}: {} open/close operations, {} bytes I/O. \
                     Consider keeping the file open.",
                    path, open_close, stats.bytes
                ),
            });
        }
    }

    hints
}
