use std::collections::HashMap;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::Marker,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph},
};

use crate::model::{
    agg::{LiveState, RunSummary},
    phase::{IoCategory, PhaseKind},
    syscall::SyscallKind,
};

const COLORS: &[Color] = &[
    Color::Cyan,
    Color::Magenta,
    Color::Yellow,
    Color::Green,
    Color::Red,
    Color::Blue,
    Color::LightCyan,
    Color::LightMagenta,
];

const MAX_KINDS: usize = 8;

pub fn draw_timeline(frame: &mut Frame, area: Rect, state: &LiveState) {
    let Some(summary) = &state.summary else {
        let block = Block::default().title("Timeline").borders(Borders::ALL);
        let para = Paragraph::new("No data yet...").block(block);
        frame.render_widget(para, area);
        return;
    };

    if summary.bins.is_empty() {
        let block = Block::default().title("Timeline").borders(Borders::ALL);
        let para = Paragraph::new("Waiting for syscalls...").block(block);
        frame.render_widget(para, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),   // chart
            Constraint::Length(3), // phase legend
            Constraint::Length(3), // kind legend
        ])
        .split(area);

    draw_chart(frame, chunks[0], summary);
    draw_phase_legend(frame, chunks[1], summary);
    draw_kind_legend(frame, chunks[2], summary);
}

/// Per-kind series data with normalization info.
struct KindSeries {
    kind: SyscallKind,
    raw_data: Vec<(f64, f64)>,
    max_val: f64,
    total: u64,
}

impl KindSeries {
    fn normalized_data(&self) -> Vec<(f64, f64)> {
        if self.max_val <= 0.0 {
            return self.raw_data.iter().map(|(x, _)| (*x, 0.0)).collect();
        }
        self.raw_data
            .iter()
            .map(|(x, y)| (*x, y / self.max_val))
            .collect()
    }
}

fn build_series(summary: &RunSummary, bucket_secs: f64) -> Vec<KindSeries> {
    // Aggregate totals to find top kinds
    let mut kind_totals: HashMap<SyscallKind, u64> = HashMap::new();
    for bin in &summary.bins {
        for (kind, stats) in &bin.by_kind {
            *kind_totals.entry(*kind).or_default() += stats.count;
        }
    }

    let mut sorted_kinds: Vec<_> = kind_totals.into_iter().collect();
    sorted_kinds.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_kinds.truncate(MAX_KINDS);

    sorted_kinds
        .into_iter()
        .map(|(kind, total)| {
            let mut max_val: f64 = 0.0;
            let raw_data: Vec<(f64, f64)> = summary
                .bins
                .iter()
                .enumerate()
                .map(|(idx, bin)| {
                    let x = idx as f64 * bucket_secs;
                    let y = bin
                        .by_kind
                        .get(&kind)
                        .map(|s| s.count as f64)
                        .unwrap_or(0.0);
                    if y > max_val {
                        max_val = y;
                    }
                    (x, y)
                })
                .collect();

            KindSeries {
                kind,
                raw_data,
                max_val,
                total,
            }
        })
        .collect()
}

fn draw_chart(frame: &mut Frame, area: Rect, summary: &RunSummary) {
    let bucket_secs = summary.bucket_ms as f64 / 1000.0;
    let series = build_series(summary, bucket_secs);
    let mut datasets: Vec<Dataset> = Vec::new();
    let normalised_data = series
        .iter()
        .map(|s| s.normalized_data())
        .collect::<Vec<_>>();

    for (i, (s, d)) in series
        .iter()
        .zip(normalised_data.iter().by_ref())
        .enumerate()
    {
        let color = COLORS[i % COLORS.len()];
        let ds = Dataset::default()
            .name(format!("{:?}", s.kind))
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(color))
            .data(d);

        datasets.push(ds);
    }

    // Phase markers
    for phase in &summary.phases {
        let start_secs = phase.start.unix_timestamp() as f64
            - summary.start.map(|s| s.unix_timestamp()).unwrap_or(0) as f64;
        let end_secs = phase.end.unix_timestamp() as f64
            - summary.start.map(|s| s.unix_timestamp()).unwrap_or(0) as f64;

        let (phase_color, phase_name) = match &phase.kind {
            PhaseKind::Io { category, .. } => {
                let color = match category {
                    IoCategory::Disk => Color::Blue,
                    IoCategory::Network => Color::Magenta,
                    IoCategory::Pipe => Color::Cyan,
                    IoCategory::Tty => Color::Yellow,
                    IoCategory::Mixed => Color::White,
                };
                (color, phase.kind.short_label())
            }
            PhaseKind::Compute => (Color::Red, "CPU"),
            PhaseKind::Idle => (Color::DarkGray, "Idle"),
        };

        let phase_data: Vec<(f64, f64)> =
            vec![(start_secs.max(0.0), 0.05), (end_secs.max(0.0), 0.05)];
        let phase_data_static: &'static [(f64, f64)] = Box::leak(phase_data.into_boxed_slice());

        let ds = Dataset::default()
            .name(phase_name)
            .marker(Marker::HalfBlock)
            .graph_type(GraphType::Line)
            .style(
                Style::default()
                    .fg(phase_color)
                    .add_modifier(Modifier::BOLD),
            )
            .data(phase_data_static);

        datasets.push(ds);
    }

    let max_x = summary.bins.len() as f64 * bucket_secs;

    let x_labels = vec![
        Span::raw("0s"),
        Span::raw(format!("{:.1}s", max_x / 2.0)),
        Span::raw(format!("{:.1}s", max_x)),
    ];

    let y_labels = vec![Span::raw("0%"), Span::raw("50%"), Span::raw("100%")];

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title("Syscalls Over Time (normalized per-kind)")
                .borders(Borders::ALL),
        )
        .x_axis(
            Axis::default()
                .title("Time")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, max_x])
                .labels(x_labels),
        )
        .y_axis(
            Axis::default()
                .title("Relative activity")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, 1.1])
                .labels(y_labels),
        );

    frame.render_widget(chart, area);
}

fn draw_phase_legend(frame: &mut Frame, area: Rect, summary: &RunSummary) {
    let mut spans: Vec<Span> = vec![Span::raw(" ")];

    // Count phases by kind
    let mut phase_counts: HashMap<String, (usize, Color)> = HashMap::new();

    for phase in &summary.phases {
        let (label, color) = match &phase.kind {
            PhaseKind::Io {
                category,
                pattern: _pattern,
            } => {
                let color = match category {
                    IoCategory::Disk => Color::Blue,
                    IoCategory::Network => Color::Magenta,
                    IoCategory::Pipe => Color::Cyan,
                    IoCategory::Tty => Color::Yellow,
                    IoCategory::Mixed => Color::White,
                };
                (phase.kind.label(), color)
            }
            PhaseKind::Compute => ("Compute".to_string(), Color::Red),
            PhaseKind::Idle => ("Idle".to_string(), Color::DarkGray),
        };

        let entry = phase_counts.entry(label.clone()).or_insert((0, color));
        entry.0 += 1;
    }

    let mut phase_counts = phase_counts.into_iter().collect::<Vec<_>>();
    phase_counts.sort_by(|(left, _), (right, _)| left.cmp(right));

    for (label, (count, color)) in phase_counts {
        spans.push(Span::styled(
            "■",
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(format!(" {} ({}) ", label, count)));
    }

    let para = Paragraph::new(Line::from(spans))
        .block(Block::default().borders(Borders::ALL).title("Phases"));

    frame.render_widget(para, area);
}

fn draw_kind_legend(frame: &mut Frame, area: Rect, summary: &RunSummary) {
    let bucket_secs = summary.bucket_ms as f64 / 1000.0;
    let series = build_series(summary, bucket_secs);

    let mut spans: Vec<Span> = vec![Span::raw(" ")];

    for (i, s) in series.iter().enumerate() {
        let color = COLORS[i % COLORS.len()];
        spans.push(Span::styled(
            "━",
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
        // Show total count and peak-per-bin for context
        spans.push(Span::raw(format!(
            " {:?} (tot:{}, peak:{:.0}/bin) ",
            s.kind, s.total, s.max_val
        )));
    }

    let para = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Syscall Kinds"),
    );

    frame.render_widget(para, area);
}
