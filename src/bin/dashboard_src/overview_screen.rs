use std::sync::Arc;

use neptune_core::models::blockchain::block::block_height::BlockHeight;
use neptune_core::rpc_server::RPCClient;
use tui::{
    style::{Color, Style},
    text::{Span, Text},
    widgets::{Block, Borders, Paragraph, Widget},
};

use super::screen::Screen;

#[derive(Debug, Clone)]
pub struct OverviewData {
    block_height: BlockHeight,
}

#[derive(Debug, Clone)]
pub struct OverviewScreen {
    active: bool,
    fg: Color,
    bg: Color,
    data: Option<OverviewData>,
    server: Arc<RPCClient>,
}

impl OverviewScreen {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        OverviewScreen {
            active: false,
            fg: Color::White,
            bg: Color::Black,
            data: None,
            server: rpc_server,
        }
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
