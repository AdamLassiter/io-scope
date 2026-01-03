use std::{
    cmp::Reverse,
    collections::HashMap,
    fmt::{self},
};

use crate::model::{
    agg::RunSummary,
    path::PathStats,
    pattern::{HintLevel, PatternHint},
    phase::{Phase, PhaseKind},
    socket::SocketStats,
    syscall::{SyscallKind, SyscallStats},
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
    let duration = summary.end - summary.start;
    let secs = duration.whole_seconds();
    let nanos = duration.subsec_nanoseconds();
    let frac = (nanos as f64) / 1_000_000_000.0;
    let elapsed = (secs as f64) + frac;

    let rate = if elapsed > 0.0 {
        summary.total_syscalls as f64 / elapsed
    } else {
        0.0
    };

    writeln!(out, "Command:      {}", summary.cmdline)?;
    writeln!(out, "Duration:     {:.3}s", elapsed)?;
    writeln!(out, "Syscalls:     {}", summary.total_syscalls)?;
    writeln!(out, "Rate:         {:.1} syscalls/s", rate)?;

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

fn write_syscall_table<W: fmt::Write>(
    out: &mut W,
    map: &HashMap<SyscallKind, SyscallStats>,
) -> fmt::Result {
    let mut rows: Vec<(SyscallKind, &SyscallStats)> = map.iter().map(|(k, v)| (*k, v)).collect();

    rows.sort_by_key(|(_, s)| (std::cmp::Reverse(s.total_bytes), Reverse(s.count)));

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
    rows.sort_by_key(|(_, s)| std::cmp::Reverse(s.bytes));

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

    rows.sort_by_key(|(_, s)| std::cmp::Reverse(s.read_bytes + s.write_bytes));

    writeln!(
        out,
        "{:<30} {:>12} {:>12} {:>8} {:>8}",
        "Peer", "Read B", "Write B", "R calls", "W calls"
    )?;
    writeln!(
        out,
        "{:-<30} {:-<12} {:-<12} {:-<8} {:-<8}",
        "", "", "", "", ""
    )?;

    for (peer, stats) in rows.into_iter().take(10) {
        writeln!(
            out,
            "{:<30} {:>12} {:>12} {:>8} {:>8}",
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
            PhaseKind::IoHeavy => "I/O-heavy",
            PhaseKind::CpuHeavy => "CPU-ish",
        };
        let dur = p.end - p.start;
        let secs = dur.whole_seconds();
        let nanos = dur.subsec_nanoseconds();
        let elapsed = (secs as f64) + (nanos as f64) / 1_000_000_000.0;

        writeln!(
            out,
            "[{}] {:.3}s – syscalls: {}, bytes: {}",
            kind, elapsed, p.syscalls, p.bytes
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
