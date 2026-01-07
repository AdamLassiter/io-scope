use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame,
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Tabs},
};

use crate::{
    model::agg::LiveState,
    ui::{
        kind::draw_by_kind,
        logs::draw_log_full,
        paths::draw_paths,
        summary::draw_summary,
        timeline::draw_timeline,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Summary,
    Timeline,
    Logs,
    Kind,
    Paths,
}

impl Tab {
    fn all() -> &'static [Tab] {
        &[
            Tab::Summary,
            Tab::Timeline,
            Tab::Logs,
            Tab::Kind,
            Tab::Paths,
        ]
    }

    fn title(self) -> &'static str {
        match self {
            Tab::Summary => "Summary",
            Tab::Timeline => "Timeline",
            Tab::Logs => "Logs",
            Tab::Kind => "Kind",
            Tab::Paths => "Paths",
        }
    }

    fn index(self) -> usize {
        match self {
            Tab::Summary => 0,
            Tab::Timeline => 1,
            Tab::Logs => 2,
            Tab::Kind => 3,
            Tab::Paths => 4,
        }
    }

    fn from_index(i: usize) -> Self {
        match i {
            0 => Tab::Summary,
            1 => Tab::Timeline,
            2 => Tab::Logs,
            3 => Tab::Kind,
            4 => Tab::Paths,
            _ => Tab::Summary,
        }
    }

    fn count() -> usize {
        5
    }
}

pub fn run_live_tui(state: Arc<Mutex<LiveState>>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    stdout.execute(crossterm::terminal::EnterAlternateScreen)?;
    stdout.execute(crossterm::event::EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut current_tab = Tab::Summary;

    loop {
        let snapshot = {
            let s = state.lock().unwrap();
            s.clone()
        };

        terminal.draw(|frame| {
            draw_frame(frame, snapshot.clone(), current_tab);
        })?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,

                KeyCode::Left => {
                    let idx = current_tab.index();
                    let idx = if idx == 0 { Tab::count() - 1 } else { idx - 1 };
                    current_tab = Tab::from_index(idx);
                }
                KeyCode::Right => {
                    let idx = current_tab.index();
                    let idx = (idx + 1) % Tab::count();
                    current_tab = Tab::from_index(idx);
                }

                KeyCode::Char('1') => current_tab = Tab::Summary,
                KeyCode::Char('2') => current_tab = Tab::Timeline,
                KeyCode::Char('3') => current_tab = Tab::Logs,
                KeyCode::Char('4') => current_tab = Tab::Kind,
                KeyCode::Char('5') => current_tab = Tab::Paths,

                // optional mnemonic keys
                KeyCode::Char('s') => current_tab = Tab::Summary,
                KeyCode::Char('t') => current_tab = Tab::Timeline,
                KeyCode::Char('l') => current_tab = Tab::Logs,
                KeyCode::Char('k') => current_tab = Tab::Kind,
                KeyCode::Char('p') => current_tab = Tab::Paths,

                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    let mut stdout = std::io::stdout();
    stdout.execute(crossterm::event::DisableMouseCapture)?;
    stdout.execute(crossterm::terminal::LeaveAlternateScreen)?;

    Ok(())
}

fn draw_frame(frame: &mut Frame, state: LiveState, current_tab: Tab) {
    let size: Rect = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3), // tabs
                Constraint::Min(1),    // content
            ]
            .as_ref(),
        )
        .split(size);

    draw_tabs(frame, chunks[0], current_tab);

    match current_tab {
        Tab::Summary => draw_summary(frame, chunks[1], &state),
        Tab::Timeline => draw_timeline(frame, chunks[1], &state),
        Tab::Logs => draw_log_full(frame, chunks[1], &state),
        Tab::Kind => draw_by_kind(frame, chunks[1], &state),
        Tab::Paths => draw_paths(frame, chunks[1], &state),
    }
}

fn draw_tabs(frame: &mut Frame, area: Rect, current_tab: Tab) {
    let titles: Vec<Span> = Tab::all()
        .iter()
        .map(|t| {
            let txt = format!(" {} ", t.title());
            if *t == current_tab {
                Span::styled(
                    txt,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw(txt)
            }
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title("io-scope (←/→, 1–4, s/t/l/k/p)")
                .borders(Borders::ALL),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .select(current_tab.index());

    frame.render_widget(tabs, area);
}
