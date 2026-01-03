use ratatui::{
    Frame,
    layout::Rect,
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

use crate::{model::agg::LiveState, ui::report::render_summary_to_string};

pub fn draw_summary(frame: &mut Frame, area: Rect, state: &LiveState) {
    let block = Block::default().title("Summary").borders(Borders::ALL);

    let mut lines = Vec::new();

    let Some(summary) = &state.summary else {
        lines.push(Line::from("No data yet..."));
        let paragraph = Paragraph::new(lines).block(block);
        frame.render_widget(paragraph, area);
        return;
    };

    let text = render_summary_to_string(summary);

    for line in text.lines() {
        lines.push(Line::from(line.to_string()));
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}
