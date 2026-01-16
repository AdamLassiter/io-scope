use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph},
};

use crate::model::agg::LiveState;

pub fn draw_log_full(frame: &mut Frame, area: Rect, state: &LiveState, scroll: u16) {
    let block = Block::default()
        .title(format!(
            "IO stdout / stderr ({} lines, scroll: {})",
            state.log_lines.len(),
            scroll
        ))
        .borders(Borders::ALL);

    let mut text = Text::default();
    for line in state.log_lines.iter() {
        text.lines.push(Line::from(Span::raw(line.clone())));
    }

    let paragraph = Paragraph::new(text).block(block).scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}