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
    in_focus: bool,
    data: Arc<std::sync::Mutex<OverviewData>>,
    server: Arc<RPCClient>,
    poll_thread: Option<Arc<RefCell<JoinHandle<()>>>>,
}

impl OverviewScreen {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        OverviewScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            // data: Arc::new(Mutex::new(OverviewData::test())),
            data: Arc::new(Mutex::new(OverviewData::default())),
            server: rpc_server,
            poll_thread: None,
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<RPCClient>,
        overview_data: Arc<std::sync::Mutex<OverviewData>>,
    ) {
        // use macros to reduce boilerplate
        macro_rules! setup_poller {
            ($name: ident) => {
                let $name = time::sleep(Duration::from_millis(1));
                tokio::pin!($name);
            };
        }

        macro_rules! reset_poller {
            ($name: ident, $period: expr) => {
                $name.as_mut().reset(tokio::time::Instant::now() + $period);
            };
        }

        setup_poller!(balance);
        // setup_poller!(confirmations);
        // setup_poller!(synchronization);
        setup_poller!(block_height);
        // setup_poller!(block_interval);
        // setup_poller!(difficulty);
        // setup_poller!(pow_line);
        // setup_poller!(pow_family);
        // setup_poller!(archive_size);
        // setup_poller!(archive_coverage);
        setup_poller!(mempool_size);
        setup_poller!(mempool_tx_count);
        setup_poller!(peer_count);
        // setup_poller!(cpu_info);
        // setup_poller!(ram_info);

        loop {
            select! {
                _ = &mut balance => {
                    if let Ok(b) = rpc_client.get_balance(context::current()).await {
                        overview_data.lock().unwrap().balance = Some(b);
                    }
                    reset_poller!(balance, Duration::from_secs(10));
                },

                // _ = &mut confirmations => {
                //     let cons = rpc_client.get_confirmations(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().confirmations = Some(cons);
                    // reset_poller!(confirmations, Duration::from_secs(10));
                // },

                // _ = &mut synchronization => {
                //     let status = rpc_client.get_synchronization_status(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().synchronization = Some(status);
                    // reset_poller!(synchronization, Duration::from_secs(10));
                // },

                _ = &mut block_height => {
                    let bh = rpc_client.block_height(context::current()).await.unwrap();
                    overview_data.lock().unwrap().block_height = Some(bh);
                    reset_poller!(block_height, Duration::from_secs(10));
                },

                // _ = &mut block_interval => {
                //     let bh = rpc_client.block_interval(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().block_interval = Some(bh);
                    // reset_poller!(block_interval, Duration::from_secs(10));
                // },

                // _ = &mut difficulty => {
                //     let bh = rpc_client.difficulty(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().block_interval = Some(bh);
                    // reset_poller!(difficulty, Duration::from_secs(10));

                // _ = &mut pow_line => {
                //     let bh = rpc_client.pow_line(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().pow_line = Some(bh);
                    // reset_poller!(pow_line, Duration::from_secs(10));
                // },

                // _ = &mut pow_family => {
                //     let bh = rpc_client.pow_family(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().pow_family = Some(bh);
                    // reset_poller!(pow_family, Duration::from_secs(10));
                // },

                // _ = &mut archive_size => {
                //     let size = rpc_client.archive_size(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().archive_size = Some(size);
                    // reset_poller!(archive_size, Duration::from_secs(10));
                // },

                // _ = &mut archive_coverage => {
                //     let cov = rpc_client.archive_coverage(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().archive_coverage = Some(cov);
                    // reset_poller!(archive_coverage, Duration::from_secs(10));
                // },

                _ = &mut mempool_size => {
                    let ms = rpc_client.get_mempool_size(context::current()).await.unwrap();
                    overview_data.lock().unwrap().mempool_size = Some(ByteSize::b(ms.try_into().unwrap()));
                    reset_poller!(mempool_size, Duration::from_secs(10));
                }

                _ = &mut mempool_tx_count => {
                    let txc = rpc_client.get_mempool_tx_count(context::current()).await.unwrap();
                    overview_data.lock().unwrap().mempool_tx_count = Some(txc.try_into().unwrap());
                    reset_poller!(mempool_tx_count, Duration::from_secs(10));
                }

                _ = &mut peer_count => {
                    let peers = rpc_client.get_peer_info(context::current()).await.unwrap();
                    // consider doing some filter and / or separation, e.g. based on
                    //  - authentication
                    //  - standing
                    //  - latest activity
                    let num_peers = peers.len();
                    overview_data.lock().unwrap().peer_count = Some(num_peers);
                    overview_data.lock().unwrap().authenticated_peer_count = Some(0);
                    reset_poller!(peer_count, Duration::from_secs(5));
                }

                // _ = &mut max_peer_count => {
                //     let mpc = rpc_client.get_max_peer_count(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().max_peer_count = Some(mpc);
                //     reset_poller!(peer_count, Duration::from_secs(60*60*24));
                // }

                // _ = &mut up_since => {
                //     let us = rpc_client.up_since(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().up_since = Some(us);
                //     reset_poller!(up_since, Duration::from_secs(10));
                // }

                // _ = &mut cpu_info => {
                //     let ci = rpc_client.get_cpu_info(context::current()).await.unwrap();
                //     overview_data.lock().unwrap().cpu_load = Some(ci.load);
                //     overview_data.lock().unwrap().cpu_capacity = Some(ci.capacity);
                //     overview_data.lock().unwrap().cpu_temperature = Some(ci.temperature);
                //     reset_poller!(cpu_info, Duration::from_secs(10));
                // }

                // _ = &mut ram_info => {
                //     let ri = rpc_client.get_ram_info(context::current()).await.unwrap();

                //     overview_data.lock().unwrap().ram_total = Some(ri.total);
                //     overview_data.lock().unwrap().ram_available = Some(ri.available);
                //     overview_data.lock().unwrap().ram_used = Some(ri.used);
                // }
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
        self.fg = Color::White;
        self.in_focus = true;
    }

    fn unfocus(&mut self) {
        self.fg = Color::Gray;
        self.in_focus = false;
    }
}

pub struct VerticalRectifier {
    container: Rect,
    inner_y: u16,
}

impl VerticalRectifier {
    pub fn new(container: Rect) -> Self {
        VerticalRectifier {
            container,
            inner_y: 0,
        }
    }

    pub fn next(&mut self, height: u16) -> Rect {
        // use clamp height instead of height to avoid writing to
        // an out of view (and hence out of buffer) region
        let clamp_height = min(self.container.height, self.inner_y + height) - self.inner_y;
        let rect = Rect {
            x: self.container.x,
            y: self.container.y + self.inner_y,
            width: self.container.width,
            height: clamp_height,
        };
        self.inner_y += clamp_height;
        rect
    }
}

impl Widget for OverviewScreen {
    fn render(self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        // overview box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Overview")
            .style(style)
            .render(area, buf);

        // divide the overview box vertically into subboxes,
        // and render each separately
        let style = Style::default().bg(self.bg).fg(self.fg);
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
        Self::report(&lines, "Wallet")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

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
        Self::report(&lines, "Blockchain")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

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
        Self::report(&lines, "Archive")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

        // mempool
        lines = vec![];
        lines.push(format!("size: {}", dashifnotset!(data.mempool_size)));
        lines.push(format!(
            "tx count: {}",
            dashifnotset!(data.mempool_tx_count)
        ));
        Self::report(&lines, "Mempool")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

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
        Self::report(&lines, "Peers")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

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
        Self::report(&lines, "Machine")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);
    }
}
