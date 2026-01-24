use std::cmp::min;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::SystemTime;

use bytesize::ByteSize;
use itertools::Itertools;
use libp2p::autonat::NatStatus;
use neptune_cash::application::config::network::Network;
use neptune_cash::application::network::overview::NetworkOverview;
use neptune_cash::application::rpc::auth;
use neptune_cash::protocol::consensus::block::block_header::BlockHeader;
use neptune_cash::protocol::consensus::block::block_height::BlockHeight;
use neptune_cash::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_cash::state::mining::mining_status::MiningStatus;
use neptune_cash::state::sync_status::SyncStatus;
use neptune_cash::state::transaction::tx_proving_capability::TxProvingCapability;
use ratatui::layout::Margin;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::List;
use ratatui::widgets::ListItem;
use ratatui::widgets::Widget;
use tarpc::context;
use tasm_lib::twenty_first::prelude::Digest;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time;

use super::dashboard_app::DashboardEvent;
use super::screen::Screen;
use crate::dashboard_rpc_client::DashboardRpcClient;

#[derive(Debug, Clone, Default)]
pub struct OverviewData {
    confirmed_available_balance: Option<NativeCurrencyAmount>,
    confirmed_total_balance: Option<NativeCurrencyAmount>,
    unconfirmed_available_balance: Option<NativeCurrencyAmount>,
    unconfirmed_total_balance: Option<NativeCurrencyAmount>,

    confirmations: Option<BlockHeight>,
    synchronization_percentage: Option<f64>,

    network: Network,
    sync_status: SyncStatus,
    mining_status: Option<MiningStatus>,
    tip_digest: Option<Digest>,
    block_header: Option<BlockHeader>,
    block_interval: Option<u64>,

    archive_size: Option<ByteSize>,
    archive_coverage: Option<f64>,

    mempool_size: Option<ByteSize>,
    mempool_total_tx_count: Option<u32>,
    mempool_own_tx_count: Option<u32>,

    network_overview: Option<NetworkOverview>,
    peer_count: usize,

    up_since: Option<u64>,
    cpu_load: Option<f64>,
    cpu_capacity: Option<f64>,
    proving_capability: TxProvingCapability,

    /// CPU temperature in degrees Celsius
    cpu_temperature: Option<f32>,
    ram_total: Option<ByteSize>,
    ram_available: Option<ByteSize>,
    ram_used: Option<ByteSize>,
}

impl OverviewData {
    pub fn new(network: Network) -> Self {
        Self {
            network,
            ..Default::default()
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
    server: Arc<DashboardRpcClient>,
    token: auth::Token,
    poll_task: Option<Arc<Mutex<JoinHandle<()>>>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
}

impl OverviewScreen {
    pub fn new(rpc_server: Arc<DashboardRpcClient>, network: Network, token: auth::Token) -> Self {
        Self {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            data: Arc::new(Mutex::new(OverviewData::new(network))),
            server: rpc_server,
            token,
            poll_task: None,
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<DashboardRpcClient>,
        token: auth::Token,
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
                        match rpc_client.dashboard_overview_data(context::current(), token).await {
                        Ok(Ok(resp)) => {

                            {
                                let mut own_overview_data = overview_data.lock().unwrap();
                                own_overview_data.tip_digest = Some(resp.tip_digest);
                                own_overview_data.block_header = Some(resp.tip_header);
                                own_overview_data.mempool_size = Some(ByteSize::b(resp.mempool_size.try_into().unwrap()));
                                own_overview_data.mempool_total_tx_count = Some(resp.mempool_total_tx_count.try_into().unwrap());
                                own_overview_data.mempool_own_tx_count = Some(resp.mempool_own_tx_count.try_into().unwrap());
                                own_overview_data.network_overview = resp.network_overview;
                                own_overview_data.peer_count = resp.peer_count;
                                own_overview_data.sync_status=resp.sync_status;
                                own_overview_data.confirmed_available_balance = Some(resp.confirmed_available_balance);
                                own_overview_data.confirmed_total_balance = Some(resp.confirmed_total_balance);
                                own_overview_data.unconfirmed_available_balance = Some(resp.unconfirmed_available_balance);
                                own_overview_data.unconfirmed_total_balance = Some(resp.unconfirmed_total_balance);
                                own_overview_data.mining_status = resp.mining_status;
                                own_overview_data.confirmations = resp.confirmations;
                                own_overview_data.cpu_temperature = resp.cpu_temp;
                                own_overview_data.proving_capability = resp.proving_capability;
                            }

                            *escalatable_event.lock().unwrap() = Some(DashboardEvent::RefreshScreen);

                            reset_poller!(dashboard_overview_data, Duration::from_secs(3));
                        },
                        Ok(Err(e)) => *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string())),
                        Err(e) => *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string())),
                    }
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
        let token = self.token;
        let escalatable_event_arc = self.escalatable_event.clone();
        self.poll_task = Some(Arc::new(Mutex::new(tokio::spawn(async move {
            OverviewScreen::run_polling_loop(server_arc, token, data_arc, escalatable_event_arc)
                .await;
        }))));
    }

    fn deactivate(&mut self) {
        self.active = false;
        if let Some(task_handle) = &self.poll_task {
            (*task_handle.lock().unwrap()).abort();
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

#[derive(Debug, Copy, Clone)]
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

    pub fn remaining(&mut self) -> Rect {
        let mut rect = self.container;
        rect.y = self.inner_y;
        self.inner_y = self.container.height;
        rect
    }

    pub fn set_width(&mut self, width: u16) {
        self.container.width = width;
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
        let inner = area.inner(Margin {
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

        let width = 17; // 8 whole coin digits, 1 decimal point, 8 decimal digits

        // confirmed balance
        lines.push(format!(
            "confirmed balance:   total: {:>width$}  available: {:>width$}   {}",
            dashifnotset!(data.confirmed_total_balance),
            dashifnotset!(data.confirmed_available_balance),
            match data.confirmations {
                Some(c) if c == 1.into() => format!("({c} confirmation)"),
                Some(c) => format!("({c} confirmations)"),
                None => " ".to_string(),
            },
        ));

        // we only display the unconfirmed balance row if a field is
        // different from the confirmed balance row fields.
        if data.unconfirmed_available_balance != data.confirmed_available_balance
            || data.unconfirmed_total_balance != data.confirmed_total_balance
        {
            // unconfirmed balance
            lines.push(format!(
                "unconfirmed balance: total: {:>width$}  available: {:>width$}",
                dashifnotset!(data.unconfirmed_total_balance),
                dashifnotset!(data.unconfirmed_available_balance),
            ));
        }

        lines.push(format!(
            "synchronization: {}",
            match data.synchronization_percentage {
                Some(s) => format!("{s}%"),
                None => "-".to_string(),
            }
        ));
        Self::report(&lines, "Wallet")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

        // blockchain
        lines = vec![];

        lines.push(format!("network: {}", data.network));

        lines.push(format!("sync status: {}", data.sync_status));

        lines.push(format!(
            "mining status: {}",
            dashifnotset!(data.mining_status)
        ));

        let tip_digest_hex = data.tip_digest.map(|d| d.to_hex());
        lines.push(format!("tip: {}\n", dashifnotset!(tip_digest_hex),));

        lines.push(format!(
            "latest block timestamp: {}",
            dashifnotset!(data
                .block_header
                .as_ref()
                .map(|bh| bh.timestamp.0.value())
                .and_then(|ts| i64::try_from(ts).ok())
                .and_then(neptune_cash::utc_timestamp_to_localtime)
                .map(|ts| ts.to_string())),
        ));

        lines.push(format!(
            "block height: {}",
            dashifnotset!(data.block_header.as_ref().map(|bh| bh.height)),
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
            "cumulative pow: {}",
            dashifnotset!(data
                .block_header
                .as_ref()
                .map(|bh| bh.cumulative_proof_of_work))
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
                Some(percentage) => format!("{percentage}%"),
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
            "tx count: {} ({} own)",
            dashifnotset!(data.mempool_total_tx_count),
            dashifnotset!(data.mempool_own_tx_count),
        ));
        Self::report(&lines, "Mempool")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);

        // network
        lines = vec![];
        lines.push(format!(
            "own peer id: {}",
            dashifnotset!(data.network_overview.as_ref().map(|no| no.peer_id))
        ));
        lines.push(format!(
            "NAT status: {}",
            data.network_overview
                .as_ref()
                .map(|no| match no.nat_status {
                    NatStatus::Unknown => "unknown",
                    NatStatus::Private => "natted",
                    NatStatus::Public(_) => "reachable",
                })
                .unwrap_or("-")
        ));
        lines.push(format!(
            "reachability: {}",
            data.network_overview
                .as_ref()
                .map(|no| format!("{}", no.reachability_state))
                .unwrap_or("-".to_string())
        ));
        lines.push(format!(
            "external address(es): (0/{}) {}",
            dashifnotset!(data
                .network_overview
                .as_ref()
                .map(|no| no.external_addresses.len())),
            dashifnotset!(data
                .network_overview
                .as_ref()
                .and_then(|no| no.external_addresses.first())),
        ));
        lines.push(format!(
            "# peers: {}({}) / {}",
            data.network_overview
                .as_ref()
                .map(|no| no.connection_count.to_string())
                .unwrap_or("-".to_string()),
            data.peer_count,
            dashifnotset!(data
                .network_overview
                .as_ref()
                .map(|no| no.connection_limit.to_string())),
        ));
        lines.push(format!(
            "# relays: {}",
            dashifnotset!(data
                .network_overview
                .as_ref()
                .map(|no| no.num_active_relays))
        ));
        lines.push(format!(
            "# bans: {}",
            dashifnotset!(data.network_overview.as_ref().map(|no| no.num_banned_peers))
        ));
        lines.push(format!(
            "# address book: {}",
            dashifnotset!(data
                .network_overview
                .as_ref()
                .map(|no| no.address_book_size))
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
            format!("{}", humantime::format_duration(uptime))
        } else {
            "-".to_string()
        };
        lines.push(format!("uptime: {uptime_string}"));
        lines.push(format!(
            "cpu load: {}% / {}%",
            dashifnotset!(data.cpu_load),
            dashifnotset!(data.cpu_capacity)
        ));
        lines.push(format!(
            "cpu temperature: {} °C",
            dashifnotset!(data.cpu_temperature)
        ));
        lines.push(format!(
            "ram: {} / {} (/ {}) ",
            dashifnotset!(data.ram_used),
            dashifnotset!(data.ram_available),
            dashifnotset!(data.ram_total)
        ));
        lines.push(format!("proving capability: {}", data.proving_capability));
        Self::report(&lines, "Machine")
            .style(style)
            .render(vrecter.next(2 + lines.len() as u16), buf);
    }
}
