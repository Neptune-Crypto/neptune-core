use std::time::SystemTime;
use std::{
    cell::RefCell,
    cmp::min,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytesize::ByteSize;
use chrono::DateTime;
use itertools::Itertools;
use neptune_core::models::blockchain::{block::block_height::BlockHeight, transaction::Amount};
use neptune_core::rpc_server::RPCClient;
use tarpc::context;
use tokio::{select, task::JoinHandle, time};
use tui::{
    layout::{Margin, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Widget},
};
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::screen::Screen;

#[derive(Debug, Default, Clone)]
pub struct OverviewData {
    balance: Option<Amount>,
    confirmations: Option<usize>,
    synchronization: Option<f64>,

    block_height: Option<BlockHeight>,
    block_size_limit: Option<ByteSize>,
    block_interval: Option<u64>,
    difficulty: Option<f64>,
    pow_line: Option<f64>,
    pow_family: Option<f64>,

    archive_size: Option<ByteSize>,
    archive_coverage: Option<f64>,

    mempool_size: Option<ByteSize>,
    mempool_tx_count: Option<u32>,

    peer_count: Option<usize>,
    max_peer_count: Option<usize>,
    authenticated_peer_count: Option<usize>,

    up_since: Option<u64>,
    cpu_load: Option<f64>,
    cpu_capacity: Option<f64>,
    cpu_temperature: Option<f64>,
    ram_total: Option<ByteSize>,
    ram_available: Option<ByteSize>,
    ram_used: Option<ByteSize>,
}

impl OverviewData {
    pub fn test() -> Self {
        OverviewData {
            balance: Some(Amount::new([1337, 0, 0, 0])),
            confirmations: Some(17),
            synchronization: Some(99.5),

            block_height: Some(BlockHeight::from(BFieldElement::new(5005))),
            block_size_limit: Some(ByteSize::b(1 << 20)),
            block_interval: Some(558u64),
            difficulty: Some(241.03),
            pow_line: Some(64.235),
            pow_family: Some(65.34),

            mempool_size: Some(ByteSize::b(10000)), // units?
            mempool_tx_count: Some(1001),

            archive_size: Some(ByteSize::b(100000000)),
            archive_coverage: Some(100.0),

            peer_count: Some(11),
            max_peer_count: Some(21),
            authenticated_peer_count: Some(1),

            up_since: Some(
                DateTime::parse_from_rfc2822("Tue, 1 Jul 2003 10:52:37 +0200")
                    .unwrap()
                    .naive_utc()
                    .timestamp() as u64,
            ),
            cpu_load: Some(0.15),
            cpu_capacity: Some(2.0),
            cpu_temperature: Some(293.0),
            ram_total: Some(ByteSize::b(1 << 24)),
            ram_available: Some(ByteSize::b(1 << 20)),
            ram_used: Some(ByteSize::b(1 << 19)),
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
            data: Arc::new(Mutex::new(OverviewData::test())),
            // data: Arc::new(Mutex::new(OverviewData::default())),
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

    fn report<'a>(lines: &'a [String], title: &'a str) -> List<'a> {
        let list = List::new(lines.iter().map(|a| ListItem::new(a.clone())).collect_vec());
        list.block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string()),
        )
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

struct VerticalRectifier {
    container: Rect,
    y: u16,
}

impl VerticalRectifier {
    pub fn new(container: Rect) -> Self {
        VerticalRectifier { container, y: 0 }
    }

    pub fn next(&mut self, height: u16) -> Rect {
        // use clamp height instead of height to avoid writing to
        // an out of view (and hence out of buffer) region
        let clamp_height = min(
            self.container.y + self.container.height,
            self.container.y + self.y + height,
        ) - self.container.y
            - self.y;
        let rect = Rect {
            x: self.container.x,
            y: self.container.y + self.y,
            width: self.container.width,
            height: clamp_height,
        };
        self.y += clamp_height;
        rect
    }
}

impl Widget for OverviewScreen {
    fn render(self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        let style = Style::default().bg(self.bg).fg(self.fg);
        buf.set_style(area, style);

        let inner = area.inner(&Margin {
            vertical: 1,
            horizontal: 1,
        });
        let mut vrecter = VerticalRectifier::new(inner);

        let data = self.data.lock().unwrap();
        let mut lines = vec![];

        macro_rules! dashifnotset {
            ($arg:expr) => {
                match $arg {
                    Some(thing) => thing.to_string(),
                    None => "-".to_string(),
                }
            };
        }

        // balance
        lines.push(format!(
            "balance: {} {}",
            dashifnotset!(data.balance),
            match data.confirmations {
                Some(c) => format!("({} confirmations)", c),
                None => " ".to_string(),
            },
        ));
        lines.push(format!(
            "synchronization: {}",
            match data.synchronization {
                Some(s) => format!("{}%", s),
                None => "-".to_string(),
            }
        ));
        Self::report(&lines, "Wallet").render(vrecter.next(2 + lines.len() as u16), buf);

        // blockchain
        lines = vec![];
        lines.push(format!(
            "block height: {}",
            dashifnotset!(data.block_height),
        ));
        lines.push(format!(
            "block size limit: {}",
            dashifnotset!(data.block_size_limit)
        ));
        lines.push(format!(
            "block interval: {}",
            dashifnotset!(data.block_interval)
        ));
        lines.push(format!("difficulty: {}", dashifnotset!(data.difficulty),));
        lines.push(format!("pow line: {}", dashifnotset!(data.pow_line)));
        lines.push(format!("pow family: {}", dashifnotset!(data.pow_family)));
        Self::report(&lines, "Blockchain").render(vrecter.next(2 + lines.len() as u16), buf);

        // archive
        lines = vec![];
        lines.push(format!("size {}", dashifnotset!(data.archive_size)));
        lines.push(format!(
            "coverage: {}",
            match data.archive_coverage {
                Some(percentage) => format!("{}%", percentage),
                None => "-".to_string(),
            }
        ));
        Self::report(&lines, "Archive").render(vrecter.next(2 + lines.len() as u16), buf);

        // mempool
        lines = vec![];
        lines.push(format!("size: {}", dashifnotset!(data.mempool_size)));
        lines.push(format!(
            "tx count: {}",
            dashifnotset!(data.mempool_tx_count)
        ));
        Self::report(&lines, "Mempool").render(vrecter.next(2 + lines.len() as u16), buf);

        Block::default()
            .borders(Borders::ALL)
            .title("Overview")
            .render(area, buf);

        // peers
        lines = vec![];
        lines.push(format!(
            "number: {} / {}",
            dashifnotset!(data.peer_count),
            dashifnotset!(data.max_peer_count)
        ));
        lines.push(format!(
            "↪ authenticated: {}",
            dashifnotset!(data.authenticated_peer_count)
        ));
        Self::report(&lines, "Peers").render(vrecter.next(2 + lines.len() as u16), buf);

        // machine
        lines = vec![];
        let uptime_string = if let Some(upsince) = data.up_since {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let uptime = Duration::from_secs(now - upsince);
            format!("{:?}", uptime)
        } else {
            "-".to_string()
        };
        lines.push(format!("uptime: {}", uptime_string));
        lines.push(format!(
            "cpu load: {}% / {}%",
            dashifnotset!(data.cpu_load),
            dashifnotset!(data.cpu_capacity)
        ));
        lines.push(format!(
            "cpu temperature: {} K",
            dashifnotset!(data.cpu_temperature)
        ));
        lines.push(format!(
            "ram: {} / {} (/ {}) ",
            dashifnotset!(data.ram_used),
            dashifnotset!(data.ram_available),
            dashifnotset!(data.ram_total)
        ));
        Self::report(&lines, "Machine").render(vrecter.next(2 + lines.len() as u16), buf);
    }
}
