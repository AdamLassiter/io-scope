use std::cmp::Reverse;

use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

use crate::model::{agg::LiveState, path::PathStats};

pub fn draw_paths(frame: &mut Frame, area: Rect, state: &LiveState, scroll: u16) {
    let block = Block::default()
        .title("Top paths by bytes")
        .borders(Borders::ALL);

    let mut lines = Vec::new();

    let Some(summary) = &state.summary else {
        lines.push(Line::from("No data yet..."));
        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
        return;
    };

    let mut v: Vec<(&String, &PathStats)> = summary.by_path.iter().collect();
    v.sort_by_key(|(_, ps)| Reverse(ps.bytes));

    lines.push(Line::from(format!(
        "{:<40} {:>12} {:>8} {:>8}",
        "Path", "Bytes", "Reads", "Writes"
    )));
    lines.push(Line::from(format!(
        "{:-<40} {:-<12} {:-<8} {:-<8}",
        "", "", "", ""
    )));

    for (path, stats) in v.into_iter().take(20) {
        lines.push(Line::from(format!(
            "{:<40} {:>12} {:>8} {:>8}",
            truncate_path(path, 40),
            stats.bytes,
            stats.reads,
            stats.writes
        )));
    }

    let paragraph = Paragraph::new(lines).block(block).scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}

fn truncate_path(path: &str, max: usize) -> String {
    if path.len() <= max {
        path.to_string()
    } else if max > 3 {
        format!("{}...", &path[..(max - 3)])
    } else {
        path[..max].to_string()
    }
}