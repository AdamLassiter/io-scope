use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use crossterm::{
    ExecutableCommand,
    event::{self, Event, KeyCode, MouseButton, MouseEventKind},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame,
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Paragraph, Tabs},
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

#[derive(Default)]
pub struct UiState {
    pub scroll_offset: u16,
    pub selected_pid: Option<i32>,
    pub available_pids: Vec<i32>,
    tab_rects: Vec<Rect>,
    content_area: Rect,
}

impl UiState {
    pub fn scroll_up(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: u16, max_lines: u16) {
        let visible = self.content_area.height.saturating_sub(2); // borders
        let max_scroll = max_lines.saturating_sub(visible);
        self.scroll_offset = (self.scroll_offset + amount).min(max_scroll);
    }

    pub fn cycle_pid_forward(&mut self) {
        if self.available_pids.is_empty() {
            return;
        }
        self.selected_pid = match self.selected_pid {
            None => Some(self.available_pids[0]),
            Some(pid) => {
                let idx = self.available_pids.iter().position(|&p| p == pid);
                match idx {
                    Some(i) if i + 1 < self.available_pids.len() => {
                        Some(self.available_pids[i + 1])
                    }
                    _ => None, // wrap to "All"
                }
            }
        };
    }

    pub fn cycle_pid_backward(&mut self) {
        if self.available_pids.is_empty() {
            return;
        }
        self.selected_pid = match self.selected_pid {
            None => Some(*self.available_pids.last().unwrap()),
            Some(pid) => {
                let idx = self.available_pids.iter().position(|&p| p == pid);
                match idx {
                    Some(0) => None, // wrap to "All"
                    Some(i) => Some(self.available_pids[i - 1]),
                    None => None,
                }
            }
        };
    }

    fn click_tab(&self, x: u16, y: u16) -> Option<Tab> {
        for (i, rect) in self.tab_rects.iter().enumerate() {
            if x >= rect.x && x < rect.x + rect.width && y >= rect.y && y < rect.y + rect.height {
                return Some(Tab::from_index(i));
            }
        }
        None
    }

    fn in_content_area(&self, x: u16, y: u16) -> bool {
        x >= self.content_area.x
            && x < self.content_area.x + self.content_area.width
            && y >= self.content_area.y
            && y < self.content_area.y + self.content_area.height
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
    let mut ui_state = UiState::default();

    loop {
        let snapshot = {
            let s = state.lock().unwrap();
            s.clone()
        };

        // Update available PIDs from snapshot
        ui_state.available_pids = snapshot.child_pids.iter().copied().collect();
        ui_state.available_pids.sort();

        let max_lines = content_line_count(&snapshot, current_tab);

        terminal.draw(|frame| {
            draw_frame(frame, &snapshot, current_tab, &mut ui_state);
        })?;

        if event::poll(Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Left => {
                        let idx = current_tab.index();
                        let idx = if idx == 0 { Tab::count() - 1 } else { idx - 1 };
                        current_tab = Tab::from_index(idx);
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Right => {
                        let idx = (current_tab.index() + 1) % Tab::count();
                        current_tab = Tab::from_index(idx);
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Up => ui_state.scroll_up(1),
                    KeyCode::Down => ui_state.scroll_down(1, max_lines),
                    KeyCode::PageUp => ui_state.scroll_up(10),
                    KeyCode::PageDown => ui_state.scroll_down(10, max_lines),
                    KeyCode::Home => ui_state.scroll_offset = 0,
                    KeyCode::End => ui_state.scroll_down(u16::MAX, max_lines),
                    KeyCode::Char('1') | KeyCode::Char('s') => {
                        current_tab = Tab::Summary;
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Char('2') | KeyCode::Char('t') => {
                        current_tab = Tab::Timeline;
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Char('3') | KeyCode::Char('l') => {
                        current_tab = Tab::Logs;
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Char('4') | KeyCode::Char('k') => {
                        current_tab = Tab::Kind;
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Char('5') | KeyCode::Char('p') => {
                        current_tab = Tab::Paths;
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Char('[') | KeyCode::Char('{') => {
                        ui_state.cycle_pid_backward();
                        ui_state.scroll_offset = 0;
                    }
                    KeyCode::Char(']') | KeyCode::Char('}') => {
                        ui_state.cycle_pid_forward();
                        ui_state.scroll_offset = 0;
                    }
                    _ => {}
                },
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) => {
                        if let Some(tab) = ui_state.click_tab(mouse.column, mouse.row) {
                            current_tab = tab;
                            ui_state.scroll_offset = 0;
                        }
                    }
                    MouseEventKind::ScrollUp => {
                        if ui_state.in_content_area(mouse.column, mouse.row) {
                            ui_state.scroll_up(3);
                        }
                    }
                    MouseEventKind::ScrollDown => {
                        if ui_state.in_content_area(mouse.column, mouse.row) {
                            ui_state.scroll_down(3, max_lines);
                        }
                    }
                    _ => {}
                },
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

fn content_line_count(state: &LiveState, tab: Tab) -> u16 {
    match tab {
        Tab::Logs => state.log_lines.len() as u16,
        Tab::Kind => state
            .summary
            .as_ref()
            .map(|s| s.by_kind.len() as u16 + 2)
            .unwrap_or(1),
        Tab::Paths => state
            .summary
            .as_ref()
            .map(|s| s.by_path.len().min(20) as u16 + 2)
            .unwrap_or(1),
        _ => 0,
    }
}

fn draw_frame(frame: &mut Frame, state: &LiveState, current_tab: Tab, ui_state: &mut UiState) {
    let size: Rect = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tabs
            Constraint::Length(1), // pid selector
            Constraint::Min(1),    // content
        ])
        .split(size);

    ui_state.content_area = chunks[2];
    draw_tabs(frame, chunks[0], current_tab, ui_state);
    draw_pid_selector(frame, chunks[1], ui_state);

    // Filter state by selected PID
    let filtered_state = filter_state_by_pid(state, ui_state.selected_pid);

    match current_tab {
        Tab::Summary => draw_summary(frame, chunks[2], &filtered_state),
        Tab::Timeline => draw_timeline(frame, chunks[2], &filtered_state),
        Tab::Logs => draw_log_full(frame, chunks[2], &filtered_state, ui_state.scroll_offset),
        Tab::Kind => draw_by_kind(frame, chunks[2], &filtered_state, ui_state.scroll_offset),
        Tab::Paths => draw_paths(frame, chunks[2], &filtered_state, ui_state.scroll_offset),
    }
}

fn draw_pid_selector(frame: &mut Frame, area: Rect, ui_state: &UiState) {
    let pid_text = match ui_state.selected_pid {
        None => format!(
            " PID: All ({} processes) | [ or ] to cycle",
            ui_state.available_pids.len()
        ),
        Some(pid) => {
            let idx = ui_state
                .available_pids
                .iter()
                .position(|&p| p == pid)
                .map(|i| i + 1)
                .unwrap_or(0);
            format!(
                " PID: {} ({}/{}) | [ or ] to cycle",
                pid,
                idx,
                ui_state.available_pids.len()
            )
        }
    };

    let style = Style::default().fg(Color::Cyan);
    let span = Span::styled(pid_text, style);
    let para = Paragraph::new(span);
    frame.render_widget(para, area);
}

fn filter_state_by_pid(state: &LiveState, selected_pid: Option<i32>) -> LiveState {
    let Some(pid) = selected_pid else {
        return state.clone();
    };

    let mut filtered = state.clone();

    // Filter log lines by PID prefix if they have one, e.g., "[1234] message"
    filtered.log_lines = state
        .log_lines
        .iter()
        .filter(|line| {
            if let Some(rest) = line.strip_prefix('[')
                && let Some(end) = rest.find(']')
                && let Ok(line_pid) = rest[..end].parse::<i32>()
            {
                return line_pid == pid;
            }
            true // keep lines without PID prefix
        })
        .cloned()
        .collect();

    // Filter summary if per-PID summaries exist
    if let Some(ref summary) = state.summary
        && let Some(pid_summary) = summary.by_pid.get(&pid)
    {
        filtered.summary = Some(pid_summary.clone());
    }

    filtered
}

fn draw_tabs(frame: &mut Frame, area: Rect, current_tab: Tab, ui_state: &mut UiState) {
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

    // Calculate tab click regions (inside the border)
    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: 1,
    };

    let mut tab_rects = Vec::new();
    let mut x_offset = inner.x;
    for t in Tab::all() {
        let width = (t.title().len() + 4) as u16; // "  title  "
        tab_rects.push(Rect {
            x: x_offset,
            y: inner.y,
            width,
            height: 1,
        });
        x_offset += width + 1; // +1 for separator
    }
    ui_state.tab_rects = tab_rects;

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title("io-scope (←/→, ↑/↓, scroll)")
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
