use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
    time::Duration,
};

use super::screen::Screen;
use neptune_core::{models::peer::PeerInfo, rpc_server::RPCClient};
use tarpc::context;
use tokio::time::sleep;
use tokio::{select, task::JoinHandle};
use tui::{
    style::{Color, Style},
    widgets::{Block, Borders, Widget},
};

#[derive(Debug, Clone)]
pub struct PeersScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    data: Arc<std::sync::Mutex<Vec<PeerInfo>>>,
    server: Arc<RPCClient>,
    poll_thread: Option<Arc<RefCell<JoinHandle<()>>>>,
}

impl PeersScreen {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        PeersScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            // data: Arc::new(Mutex::new(OverviewData::test())),
            data: Arc::new(Mutex::new(vec![])),
            server: rpc_server,
            poll_thread: None,
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<RPCClient>,
        peer_info: Arc<std::sync::Mutex<Vec<PeerInfo>>>,
    ) {
        // use macros to reduce boilerplate
        macro_rules! setup_poller {
            ($name: ident) => {
                let $name = sleep(Duration::from_millis(1));
                tokio::pin!($name);
            };
        }

        macro_rules! reset_poller {
            ($name: ident, $period: expr) => {
                $name.as_mut().reset(tokio::time::Instant::now() + $period);
            };
        }

        setup_poller!(balance);

        loop {
            select! {
                _ = &mut balance => {
                    let pi = rpc_client.get_peer_info(context::current()).await.unwrap();
                    *peer_info.lock().unwrap() = pi;
                    reset_poller!(balance, Duration::from_secs(10));
                }
            }
        }
    }
}

impl Screen for PeersScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        self.poll_thread = Some(Arc::new(RefCell::new(tokio::spawn(async move {
            PeersScreen::run_polling_loop(server_arc, data_arc).await;
        }))));
    }

    fn deactivate(&mut self) {
        self.active = false;
        if let Some(thread_handle) = &self.poll_thread {
            thread_handle.borrow_mut().abort();
        }
    }

    fn focus(&mut self) {
        self.fg = Color::White;
        self.in_focus = true;
    }

    fn unfocus(&mut self) {
        self.fg = Color::Gray;
        self.in_focus = false;
    }
}

impl Widget for PeersScreen {
    fn render(self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        // overview box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Peers")
            .style(style)
            .render(area, buf);
    }
}
