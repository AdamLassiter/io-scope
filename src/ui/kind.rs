use std::cmp::Reverse;

use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

use crate::model::{
    agg::LiveState,
    syscall::{SyscallKind, SyscallStats},
};

pub fn draw_by_kind(frame: &mut Frame, area: Rect, state: &LiveState) {
    let block = Block::default()
        .title("By syscall kind")
        .borders(Borders::ALL);

    let mut lines = Vec::new();

    let Some(summary) = &state.summary else {
        lines.push(Line::from("No data yet..."));
        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
        return;
    };

    let mut rows: Vec<(SyscallKind, &SyscallStats)> =
        summary.by_kind.iter().map(|(k, v)| (*k, v)).collect();

    rows.sort_by_key(|(_, s)| Reverse(s.total_bytes));

    lines.push(Line::from(format!(
        "{:<10} {:>10} {:>16}",
        "Kind", "Count", "Bytes"
    )));
    lines.push(Line::from(format!("{:-<10} {:-<10} {:-<16}", "", "", "")));

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

        lines.push(Line::from(format!(
            "{:<10} {:>10} {:>16}",
            name, stats.count, stats.total_bytes
        )));
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}
