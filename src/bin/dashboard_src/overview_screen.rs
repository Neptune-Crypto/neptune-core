use tui::{
    style::{Color, Style},
    text::{Span, Text},
    widgets::{Block, Borders, Paragraph, Widget},
};

use super::screen::Screen;

#[derive(Debug, Clone)]
pub struct OverviewScreen {
    active: bool,
    fg: Color,
    bg: Color,
}

impl OverviewScreen {
    pub fn new() -> Self {
        OverviewScreen {
            active: false,
            fg: Color::White,
            bg: Color::Black,
        }
    }
}

impl Default for OverviewScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen for OverviewScreen {
    fn activate(&mut self) {
        self.active = true;
    }

    fn deactivate(&mut self) {
        self.active = false;
    }

    fn focus(&mut self) {
        self.fg = Color::LightCyan;
    }

    fn unfocus(&mut self) {
        self.fg = Color::White;
    }
}

impl Widget for OverviewScreen {
    fn render(self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        // render welcome text
        let text = Span::raw("Hello, world!");
        let style = Style::default().bg(self.bg).fg(self.fg);
        let widget = Paragraph::new(Text::from(text)).style(style);
        widget
            .block(Block::default().borders(Borders::ALL).title("Overview"))
            .render(area, buf);
    }
}
