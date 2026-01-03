use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph},
};

use crate::model::agg::LiveState;

pub fn draw_log_full(frame: &mut Frame, area: Rect, state: &LiveState) {
    let block = Block::default()
        .title("IO stdout / stderr")
        .borders(Borders::ALL);

    let mut text = Text::default();
    for line in state.log_lines.iter().rev() {
        // newest at bottom
        text.lines.insert(0, Line::from(Span::raw(line.clone())));
    }

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}
