use std::sync::Arc;
use std::sync::Mutex;

use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use ratatui::widgets::TableState;

use crate::dashboard_app::DashboardEvent;

#[derive(Debug, Clone)]
pub struct ScrollableTable<T> {
    data: Arc<Mutex<Vec<T>>>,
    state: TableState,
}

impl<T> ScrollableTable<T> {
    /// number of rows in table header (1 text row, 2 border rows).
    const TABLE_HEADER_ROWS: usize = 3;

    /// number of rows in the dashboard header/footer.
    const DASHBOARD_HEADER_FOOTER_ROWS: usize = 3;

    pub fn new(data: Arc<Mutex<Vec<T>>>) -> Self {
        let mut state = TableState::default();
        state.select(Some(Self::TABLE_HEADER_ROWS));
        Self { data, state }
    }
    pub fn state_mut(&mut self) -> &mut TableState {
        &mut self.state
    }

    fn num_items(&self) -> usize {
        self.data.lock().map(|data| data.len()).unwrap_or(0)
    }

    fn terminal_height() -> u16 {
        crossterm::terminal::size()
            .map(|(_, rows)| rows)
            .unwrap_or(1)
    }

    pub fn next(&mut self) {
        let offset = Self::TABLE_HEADER_ROWS;
        let num_items = self.num_items();
        let i = match self.state.selected() {
            Some(i) => {
                if i >= num_items + offset - 1 {
                    i
                } else {
                    i + 1
                }
            }
            None => offset,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let offset = Self::TABLE_HEADER_ROWS;
        let i = match self.state.selected() {
            Some(i) => {
                if i == offset {
                    i
                } else {
                    i - 1
                }
            }
            None => offset,
        };
        self.state.select(Some(i));
    }

    pub fn next_page(&mut self) {
        let offset = Self::TABLE_HEADER_ROWS;
        let num_items = self.num_items();
        let num_rows = Self::terminal_height() as usize
            - Self::TABLE_HEADER_ROWS
            - Self::DASHBOARD_HEADER_FOOTER_ROWS;
        let jump_height = usize::max(1, num_rows / 2);
        let i = match self.state.selected() {
            Some(i) => usize::min(num_items + offset - 1, i + jump_height),
            None => offset,
        };
        self.state.select(Some(i));
    }

    pub fn previous_page(&mut self) {
        let offset = Self::TABLE_HEADER_ROWS;
        let num_rows = Self::terminal_height() as usize
            - Self::TABLE_HEADER_ROWS
            - Self::DASHBOARD_HEADER_FOOTER_ROWS;
        let jump_height = usize::max(1, num_rows / 2);
        let i = match self.state.selected() {
            Some(i) => usize::max(offset, i.saturating_sub(jump_height)),
            None => offset,
        };
        self.state.select(Some(i));
    }

    pub fn handle_navigation(&mut self, event: &DashboardEvent) -> bool {
        if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Down => {
                        self.next();
                        return true;
                    }
                    KeyCode::Up => {
                        self.previous();
                        return true;
                    }
                    KeyCode::PageDown => {
                        self.next_page();
                        return true;
                    }
                    KeyCode::PageUp => {
                        self.previous_page();
                        return true;
                    }
                    _ => {}
                }
            }
        }
        false
    }

    pub fn data(&self) -> &Arc<Mutex<Vec<T>>> {
        &self.data
    }

    pub fn selected_data_index(&self) -> Option<usize> {
        self.state
            .selected()
            .and_then(|idx| idx.checked_sub(Self::TABLE_HEADER_ROWS))
    }
}
