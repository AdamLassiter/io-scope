use std::{
    cmp::Reverse,
    collections::HashMap,
    fmt::{self},
};

use time::OffsetDateTime;

use crate::model::{
    agg::RunSummary,
    path::PathStats,
    pattern::{HintLevel, PatternHint},
    phase::{IoCategory, IoPattern, Phase, PhaseKind},
    socket::SocketStats,
    syscall::{KindStats, ResourceKind, SyscallKind, SyscallStats},
};

pub fn print_summary(summary: &RunSummary) {
    let s = render_summary_to_string(summary);
    // Avoid double newline; the renderer already uses \n internally.
    print!("{s}");
}

pub fn render_summary_to_string(summary: &RunSummary) -> String {
    let mut out = String::new();
    write_summary(&mut out, summary).unwrap();
    out
}

fn write_summary<W: fmt::Write>(out: &mut W, summary: &RunSummary) -> fmt::Result {
    let duration = summary.end.unwrap_or(OffsetDateTime::now_utc())
        - summary.start.unwrap_or(OffsetDateTime::now_utc());
    let secs = duration.whole_seconds();
    let nanos = duration.subsec_nanoseconds();
    let frac = (nanos as f64) / 1_000_000_000.0;
    let elapsed = (secs as f64) + frac;

    let syscall_rate = if elapsed > 0.0 {
        summary.total_syscalls as f64 / elapsed
    } else {
        0.0
    };
    let bytes_rate = if elapsed > 0.0 {
        summary.total_bytes as f64 / elapsed
    } else {
        0.0
    };

    writeln!(out, "Command:      {}", summary.cmdline)?;
    writeln!(out, "Duration:     {:.3}s", elapsed)?;
    writeln!(out, "Syscalls:     {}", summary.total_syscalls)?;
    writeln!(out, "Dropped:      {}", summary.total_dropped)?;
    writeln!(out, "Sys. Rate:    {:.1} syscalls/s", syscall_rate)?;
    writeln!(out, "Bytes Rate:   {:.1} bytes/s", bytes_rate)?;

    if !summary.by_kind.is_empty() {
        writeln!(out)?;
        writeln!(out, "By syscall kind:")?;
        write_syscall_table(out, &summary.by_kind)?;
    }

    if !summary.by_path.is_empty() {
        writeln!(out)?;
        writeln!(out, "Top paths by bytes:")?;
        write_top_paths(out, &summary.by_path, 10)?;
    }

    if !summary.by_socket.is_empty() {
        writeln!(out)?;
        writeln!(out, "Network peers:")?;
        write_network(out, &summary.by_socket)?;
    }

    if !summary.by_resource.is_empty() {
        writeln!(out)?;
        writeln!(out, "IO by resource kind:")?;
        write_resource(out, summary)?;
    }

    if !summary.pattern_hints.is_empty() {
        writeln!(out)?;
        writeln!(out, "Heuristics (patterns):")?;
        write_pattern_hints(out, &summary.pattern_hints)?;
    }

    if !summary.phases.is_empty() {
        writeln!(out)?;
        writeln!(out, "Phases:")?;
        write_phases(out, &summary.phases)?;
    }

    Ok(())
}

fn write_resource<W: fmt::Write>(out: &mut W, summary: &RunSummary) -> Result<(), fmt::Error> {
    writeln!(out, "{:<10} {:>10} {:>16}", "Resource", "Calls", "Bytes")?;
    writeln!(out, "{:-<10} {:-<10} {:-<16}", "", "", "")?;
    let mut rows: Vec<(ResourceKind, &KindStats)> =
        summary.by_resource.iter().map(|(k, v)| (*k, v)).collect();
    rows.sort_by_key(|(_, io)| Reverse(io.bytes));
    for (res_kind, io) in rows {
        let name = match res_kind {
            crate::model::syscall::ResourceKind::File => "file",
            crate::model::syscall::ResourceKind::Socket => "socket",
            crate::model::syscall::ResourceKind::Pipe => "pipe",
            crate::model::syscall::ResourceKind::Tty => "tty",
        };

        writeln!(out, "{:<10} {:>10} {:>16}", name, io.calls, io.bytes)?;
    }
    Ok(())
}

fn write_syscall_table<W: fmt::Write>(
    out: &mut W,
    map: &HashMap<SyscallKind, SyscallStats>,
) -> fmt::Result {
    let mut rows: Vec<(SyscallKind, &SyscallStats)> = map.iter().map(|(k, v)| (*k, v)).collect();

    rows.sort_by_key(|(_, s)| (Reverse(s.total_bytes), Reverse(s.count)));

    writeln!(out, "{:<10} {:>10} {:>16}", "Kind", "Count", "Bytes")?;
    writeln!(out, "{:-<10} {:-<10} {:-<16}", "", "", "")?;

    for (kind, stats) in rows {
        let name = match kind {
            SyscallKind::Read => "read",
            SyscallKind::Write => "write",
            SyscallKind::Pread => "pread",
            SyscallKind::Pwrite => "pwrite",
            SyscallKind::Readv => "readv",
            SyscallKind::Writev => "writev",
            SyscallKind::Send => "send",
            SyscallKind::Recv => "recv",
            SyscallKind::Open => "open",
            SyscallKind::Close => "close",
            SyscallKind::Fsync => "fsync",
            SyscallKind::Mmap => "mmap",
            SyscallKind::Other => "other",
        };

        writeln!(
            out,
            "{:<10} {:>10} {:>16}",
            name, stats.count, stats.total_bytes
        )?;
    }

    Ok(())
}

fn write_top_paths<W: fmt::Write>(
    out: &mut W,
    map: &HashMap<String, PathStats>,
    max_entries: usize,
) -> fmt::Result {
    let mut rows: Vec<(&String, &PathStats)> = map.iter().collect();
    rows.sort_by_key(|(_, s)| Reverse(s.bytes));

    writeln!(
        out,
        "{:<40} {:>12} {:>8} {:>8}",
        "Path", "Bytes", "Reads", "Writes"
    )?;
    writeln!(out, "{:-<40} {:-<12} {:-<8} {:-<8}", "", "", "", "")?;

    for (i, (path, stats)) in rows.into_iter().enumerate() {
        if i >= max_entries {
            break;
        }
        writeln!(
            out,
            "{:<40} {:>12} {:>8} {:>8}",
            truncate(path, 40),
            stats.bytes,
            stats.reads,
            stats.writes
        )?;
    }

    Ok(())
}

fn write_network<W: fmt::Write>(out: &mut W, map: &HashMap<String, SocketStats>) -> fmt::Result {
    let mut rows: Vec<(&String, &SocketStats)> = map.iter().collect();

    rows.sort_by_key(|(_, s)| Reverse(s.read_bytes + s.write_bytes));

    writeln!(
        out,
        "{:<50} {:>12} {:>12} {:>8} {:>8}",
        "Peer", "Read B", "Write B", "R calls", "W calls"
    )?;
    writeln!(
        out,
        "{:-<50} {:-<12} {:-<12} {:-<8} {:-<8}",
        "", "", "", "", ""
    )?;

    for (peer, stats) in rows.into_iter().take(10) {
        let trunc_peer_len = peer.len().min(50);
        let mut peer = peer.clone();
        peer.truncate(trunc_peer_len);

        writeln!(
            out,
            "{:<50} {:>12} {:>12} {:>8} {:>8}",
            peer, stats.read_bytes, stats.write_bytes, stats.read_calls, stats.write_calls
        )?;
    }

    Ok(())
}

fn write_pattern_hints<W: fmt::Write>(out: &mut W, hints: &[PatternHint]) -> fmt::Result {
    for h in hints {
        let level = match h.level {
            HintLevel::Info => "[INFO]",
            HintLevel::Warn => "[WARN]",
        };
        writeln!(out, "{} {}: {}", level, h.title, h.detail)?;
    }
    Ok(())
}

fn write_phases<W: fmt::Write>(out: &mut W, phases: &[Phase]) -> fmt::Result {
    for p in phases {
        let kind = match p.kind {
            PhaseKind::Io { category, pattern } => match category {
                IoCategory::Disk => match pattern {
                    IoPattern::Balanced => "Disk IO-heavy (balanced)",
                    IoPattern::Bursty => "Disk IO-heavy (bursty)",
                    IoPattern::Streaming => "Disk IO-heavy (streaming)",
                },
                IoCategory::Network => match pattern {
                    IoPattern::Balanced => "Network IO-heavy (balanced)",
                    IoPattern::Bursty => "Network IO-heavy (bursty)",
                    IoPattern::Streaming => "Network IO-heavy (streaming)",
                },
                IoCategory::Mixed => "Mixed IO-heavy",
                IoCategory::Pipe => "Pipe IO-heavy",
                IoCategory::Tty => "TTY IO-heavy",
            },
            PhaseKind::Compute => "CPU-heavy",
            PhaseKind::Idle => "Idle",
        };
        let dur = p.end - p.start;
        let secs = dur.whole_seconds();
        let nanos = dur.subsec_nanoseconds();
        let elapsed = (secs as f64) + (nanos as f64) / 1_000_000_000.0;

        writeln!(
            out,
            "[{}] {:.3}s – syscalls: {}, bytes: {}, avg bytes per call: {:.1}",
            kind, elapsed, p.syscalls, p.bytes, p.avg_bytes_per_call
        )?;
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else if max > 3 {
        format!("{}...", &s[..(max - 3)])
    } else {
        s[..max].to_string()
    }
}
