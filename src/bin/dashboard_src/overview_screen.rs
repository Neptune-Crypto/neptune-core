use neptune_core::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use neptune_core::prelude::twenty_first;

use std::net::SocketAddr;
use std::time::SystemTime;
use std::{
    cmp::min,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytesize::ByteSize;
use chrono::DateTime;
use itertools::Itertools;
use neptune_core::config_models::network::Network;
use neptune_core::models::blockchain::block::block_header::BlockHeader;
use neptune_core::models::blockchain::block::block_height::BlockHeight;
use neptune_core::models::blockchain::shared::Hash;
use neptune_core::rpc_server::RPCClient;
use num_traits::Zero;
use ratatui::{
    layout::{Margin, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Widget},
};
use tarpc::context;
use tokio::{select, task::JoinHandle, time};
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::emojihash_trait::Emojihash;

use super::dashboard_app::DashboardEvent;
use super::screen::Screen;

#[derive(Debug, Clone)]
pub struct OverviewData {
    available_balance: Option<NeptuneCoins>,
    timelocked_balance: Option<NeptuneCoins>,
    confirmations: Option<BlockHeight>,
    synchronization_percentage: Option<f64>,

    network: Network,
    syncing: bool,
    is_mining: Option<bool>,
    block_header: Option<BlockHeader>,
    block_interval: Option<u64>,

    archive_size: Option<ByteSize>,
    archive_coverage: Option<f64>,

    mempool_size: Option<ByteSize>,
    mempool_tx_count: Option<u32>,

    listen_address: Option<SocketAddr>,
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
    pub fn new(network: Network, listen_address: Option<SocketAddr>) -> Self {
        Self {
            available_balance: Default::default(),
            timelocked_balance: Default::default(),
            confirmations: Default::default(),
            synchronization_percentage: Default::default(),
            network,
            syncing: Default::default(),
            is_mining: Default::default(),
            listen_address,
            block_header: Default::default(),
            block_interval: Default::default(),
            archive_size: Default::default(),
            archive_coverage: Default::default(),
            mempool_size: Default::default(),
            mempool_tx_count: Default::default(),
            peer_count: Default::default(),
            max_peer_count: Default::default(),
            authenticated_peer_count: Default::default(),
            up_since: Default::default(),
            cpu_load: Default::default(),
            cpu_capacity: Default::default(),
            cpu_temperature: Default::default(),
            ram_total: Default::default(),
            ram_available: Default::default(),
            ram_used: Default::default(),
        }
    }
    pub async fn test() -> Self {
        OverviewData {
            available_balance: Some(NeptuneCoins::zero()),
            timelocked_balance: Some(NeptuneCoins::zero()),
            confirmations: Some(17.into()),
            synchronization_percentage: Some(99.5),

            listen_address: None,
            network: Network::Testnet,
            is_mining: Some(false),
            syncing: false,
            block_header: Some(
                neptune_core::models::blockchain::block::Block::genesis_block()
                    .await
                    .kernel
                    .header,
            ),
            block_interval: Some(558u64),

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
    poll_thread: Option<Arc<Mutex<JoinHandle<()>>>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
}

impl OverviewScreen {
    pub fn new(
        rpc_server: Arc<RPCClient>,
        network: Network,
        listen_addr_for_peers: Option<SocketAddr>,
    ) -> Self {
        OverviewScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            data: Arc::new(Mutex::new(OverviewData::new(
                network,
                listen_addr_for_peers,
            ))),
            server: rpc_server,
            poll_thread: None,
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<RPCClient>,
        overview_data: Arc<std::sync::Mutex<OverviewData>>,
        escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
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

        setup_poller!(dashboard_overview_data);

        loop {
            select! {
                _ = &mut dashboard_overview_data => {
                        match rpc_client.dashboard_overview_data(context::current()).await {
                        Ok(resp) => {

                            {
                                let mut own_overview_data = overview_data.lock().unwrap();
                                own_overview_data.block_header = Some(resp.tip_header);
                                own_overview_data.mempool_size = Some(ByteSize::b(resp.mempool_size.try_into().unwrap()));
                                own_overview_data.mempool_tx_count = Some(resp.mempool_tx_count.try_into().unwrap());
                                own_overview_data.peer_count=resp.peer_count;
                                own_overview_data.authenticated_peer_count=Some(0);
                                own_overview_data.syncing=resp.syncing;
                                own_overview_data.available_balance = Some(resp.available_balance);
                                own_overview_data.timelocked_balance = Some(resp.timelocked_balance);
                                own_overview_data.is_mining = resp.is_mining;
                                own_overview_data.confirmations = resp.confirmations;
                            }

                            *escalatable_event.lock().unwrap() = Some(DashboardEvent::RefreshScreen);

                            reset_poller!(dashboard_overview_data, Duration::from_secs(3));
                        },
                        Err(e) => *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string())),
                    }
                }

                // _ = &mut mempool_size => {
                //     match rpc_client.get_mempool_size(context::current()).await {
                //         Ok(ms) => {
                //             overview_data.lock().unwrap().mempool_size=Some(ByteSize::b(ms.try_into().unwrap()));
                //             reset_poller!(mempool_size,Duration::from_secs(10));
                //         },
                //         Err(e) => *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string())),
                //     }
                // }

                // _ = &mut mempool_tx_count => {
                //     match rpc_client.get_mempool_tx_count(context::current()).await {
                //         Ok(txc) => {
                //             overview_data.lock().unwrap().mempool_tx_count = Some(txc.try_into().unwrap());
                //             reset_poller!(mempool_tx_count, Duration::from_secs(10));
                //         },
                //         Err(e) => *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string())),
                //     }
                // }

                // _ = &mut peer_count => {
                //     match rpc_client.get_peer_info(context::current()).await {
                //         Ok(peers) => {
                //             let num_peers=peers.len();
                //             overview_data.lock().unwrap().peer_count=Some(num_peers);
                //             overview_data.lock().unwrap().authenticated_peer_count=Some(0);
                //             reset_poller!(peer_count,Duration::from_secs(5));
                //         },
                //         Err(e) => *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string())),
                //     }
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
        let escalatable_event_arc = self.escalatable_event.clone();
        self.poll_thread = Some(Arc::new(Mutex::new(tokio::spawn(async move {
            OverviewScreen::run_polling_loop(server_arc, data_arc, escalatable_event_arc).await;
        }))));
    }

    fn deactivate(&mut self) {
        self.active = false;
        if let Some(thread_handle) = &self.poll_thread {
            (*thread_handle.lock().unwrap()).abort();
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

    fn escalatable_event(&self) -> Arc<std::sync::Mutex<Option<DashboardEvent>>> {
        self.escalatable_event.clone()
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
    fn render(self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
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
            "available balance: {} {}",
            dashifnotset!(data.available_balance),
            match data.confirmations {
                Some(c) => format!("({} confirmations)", c),
                None => " ".to_string(),
            },
        ));
        lines.push(format!(
            "time-locked balance: {}",
            dashifnotset!(data.timelocked_balance),
        ));
        lines.push(format!(
            "synchronization: {}",
            match data.synchronization_percentage {
                Some(s) => format!("{}%", s),
                None => "-".to_string(),
            }
        ));
        Self::report(&lines, "Wallet")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

        // blockchain
        lines = vec![];

        lines.push(format!("network: {}", data.network));

        lines.push(format!("synchronizing: {}", data.syncing));

        lines.push(format!("mining: {}", dashifnotset!(data.is_mining)));

        // TODO: Do we want to show the emojihash here?
        let tip_digest = data.block_header.as_ref().map(Hash::hash);
        lines.push(format!(
            "tip digest:\n{}\n{}\n\n",
            dashifnotset!(tip_digest.map(|x| x.emojihash())),
            dashifnotset!(tip_digest),
        ));

        lines.push(format!(
            "block height: {}",
            dashifnotset!(data.block_header.as_ref().map(|bh| bh.height)),
        ));
        lines.push(format!(
            "block size limit: {}",
            dashifnotset!(data.block_header.as_ref().map(|bh| bh.max_block_size)),
        ));
        lines.push(format!(
            "block interval: {}",
            dashifnotset!(data.block_interval)
        ));
        lines.push(format!(
            "difficulty: {}",
            dashifnotset!(data.block_header.as_ref().map(|bh| bh.difficulty)),
        ));
        lines.push(format!(
            "pow line: {}",
            dashifnotset!(data.block_header.as_ref().map(|bh| bh.proof_of_work_line))
        ));
        lines.push(format!(
            "pow family: {}",
            dashifnotset!(data.block_header.as_ref().map(|bh| bh.proof_of_work_family))
        ));
        Self::report(&lines, "Blockchain")
            .style(style)
            .render(vrecter.next(4 + lines.len() as u16), buf);

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
            "listen address: {}",
            dashifnotset!(data.listen_address)
        ));
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
