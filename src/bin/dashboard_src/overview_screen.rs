use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
    time::Duration,
};

use neptune_core::models::blockchain::block::block_height::BlockHeight;
use neptune_core::rpc_server::RPCClient;
use tarpc::context;
use tokio::{select, task::JoinHandle, time};
use tui::{
    style::{Color, Style},
    text::{Span, Text},
    widgets::{Block, Borders, Paragraph, Widget},
};

use super::screen::Screen;

#[derive(Debug, Default, Clone)]
pub struct OverviewData {
    block_height: Option<BlockHeight>,
}

#[derive(Debug, Clone)]
pub struct OverviewScreen {
    active: bool,
    fg: Color,
    bg: Color,
    data: Arc<std::sync::Mutex<OverviewData>>,
    server: Arc<RPCClient>,
    poll_thread: Option<Arc<RefCell<JoinHandle<()>>>>,
}

impl OverviewScreen {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        OverviewScreen {
            active: false,
            fg: Color::White,
            bg: Color::Black,
            data: Arc::new(Mutex::new(OverviewData::default())),
            server: rpc_server,
            poll_thread: None,
        }
    }

    async fn run_polling_loop(
        server: Arc<RPCClient>,
        overview_data: Arc<std::sync::Mutex<OverviewData>>,
    ) {
        // Set removal of transactions from mempool that have timed out to run every P seconds
        let block_height_poller_interval = Duration::from_secs(1);
        let block_height_poller = time::sleep(block_height_poller_interval);
        tokio::pin!(block_height_poller);

        loop {
            select! {
                _ = &mut block_height_poller => {

                    let bh = server.block_height(context::current()).await.unwrap();
                    overview_data.lock().unwrap().block_height = Some(bh);

                    // Reset the timer
                    block_height_poller.as_mut().reset(tokio::time::Instant::now() + block_height_poller_interval);
                }
            }
        }
    }
}

impl Screen for OverviewScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        self.poll_thread = Some(Arc::new(RefCell::new(tokio::spawn(async move {
            OverviewScreen::run_polling_loop(server_arc, data_arc).await;
        }))));
        // _jh.abort();
    }

    fn deactivate(&mut self) {
        self.active = false;
        if let Some(thread_handle) = &self.poll_thread {
            thread_handle.borrow_mut().abort();
        }
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
        let text = Span::raw(format!(
            "Block height: {}",
            match self.data.lock().unwrap().block_height {
                Some(h) => h.to_string(),
                None => "-".to_string(),
            }
        ));
        let style = Style::default().bg(self.bg).fg(self.fg);
        let widget = Paragraph::new(Text::from(text)).style(style);
        widget
            .block(Block::default().borders(Borders::ALL).title("Overview"))
            .render(area, buf);
    }
}
