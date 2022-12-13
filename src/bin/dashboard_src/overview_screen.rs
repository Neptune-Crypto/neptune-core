use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
    time::Duration,
};

use itertools::Itertools;
use neptune_core::models::blockchain::{block::block_height::BlockHeight, transaction::Amount};
use neptune_core::rpc_server::RPCClient;
use tarpc::context;
use tokio::{select, task::JoinHandle, time};
use tui::{
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Widget},
};
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::screen::Screen;

#[derive(Debug, Default, Clone)]
pub struct OverviewData {
    balance: Option<Amount>,
    confirmations: Option<usize>,

    block_height: Option<BlockHeight>,
    difficulty: Option<f64>,

    mempool_size: Option<u32>,
    mempool_tx_count: Option<u32>,

    peer_count: Option<usize>,
    max_peer_count: Option<usize>,
    authenticated_peer_count: Option<usize>,
}

impl OverviewData {
    pub fn test() -> Self {
        OverviewData {
            balance: Some(Amount::new([1337, 0, 0, 0])),
            confirmations: Some(17),
            block_height: Some(BlockHeight::from(BFieldElement::new(5005))),
            difficulty: Some(241.03),
            mempool_size: Some(100), // units?
            mempool_tx_count: Some(1001),
            peer_count: Some(11),
            max_peer_count: Some(21),
            authenticated_peer_count: Some(1),
        }
    }
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
        let data = self.data.lock().unwrap();
        let mut items = vec![];
        let mut depth = 0;
        let indent = |d| format!("{}", [" "].repeat(d).concat());

        items.push("# Balance".to_string());
        items.push(" ".to_string());
        depth = depth + 1;
        let balance = format!(
            "{}balance: {} {}",
            indent(depth),
            match data.balance {
                Some(h) => h.to_string(),
                None => "-".to_string(),
            },
            match data.confirmations {
                Some(c) => format!("({} confirmations)", c),
                None => " ".to_string(),
            },
        );
        items.push(balance);
        depth -= 1;
        items.push(" ".to_string());

        items.push("# Blockchain".to_string());
        items.push(" ".to_string());
        depth += 1;
        let block_height = format!(
            "{}block height: {}",
            indent(depth),
            match data.block_height {
                Some(h) => h.to_string(),
                None => "-".to_string(),
            },
        );
        items.push(block_height);
        let difficulty = format!(
            "{}difficulty: {}",
            indent(depth),
            match data.difficulty {
                Some(d) => d.to_string(),
                None => "-".to_string(),
            },
        );
        items.push(difficulty);
        depth -= 1;
        items.push(" ".to_string());

        let style = Style::default().bg(self.bg).fg(self.fg);
        let list =
            List::new(items.iter().map(|a| ListItem::new(a.clone())).collect_vec()).style(style);
        list.block(Block::default().borders(Borders::ALL).title("Overview"))
            .render(area, buf);
    }
}
