use std::cmp::max;
use std::cmp::min;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use itertools::Itertools;
use multiaddr::Protocol;
use neptune_cash::application::rpc::auth;
use neptune_cash::protocol::peer::peer_info::PeerInfo;
use ratatui::layout::Constraint;
use ratatui::layout::Margin;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Cell;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::StatefulWidget;
use ratatui::widgets::Table;
use ratatui::widgets::TableState;
use ratatui::widgets::Widget;
use tarpc::context;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use unicode_width::UnicodeWidthStr;

use super::dashboard_app::Config;
use super::dashboard_app::DashboardEvent;
use super::overview_screen::VerticalRectifier;
use super::screen::Screen;
use crate::dashboard_rpc_client::DashboardRpcClient;

type PeerInfoArc = Arc<std::sync::Mutex<Vec<PeerInfo>>>;
type DashboardEventArc = Arc<std::sync::Mutex<Option<DashboardEvent>>>;
type JoinHandleArc = Arc<Mutex<JoinHandle<()>>>;

/// column sort order
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum SortOrder {
    /// ascending
    Ascending,

    /// descending
    Descending,
}

impl SortOrder {
    fn compare<T: Ord>(&self, a: T, b: T) -> std::cmp::Ordering {
        match self {
            Self::Ascending => a.cmp(&b),
            Self::Descending => b.cmp(&a),
        }
    }

    fn reverse(&mut self) {
        *self = match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        }
    }
}

/// column identifier
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum PeerSortColumn {
    /// the peer's IP address
    Ip,

    /// neptune-core version reported by peer
    Version,

    /// time when connection to peer was established
    ConnectionEstablished,

    /// the peer's standing score
    Standing,

    /// latest punishment for the peer
    LastPunishment,

    /// latest reward for the peer
    LastReward,
}

#[derive(Debug, Clone)]
pub struct PeersScreen {
    #[expect(dead_code)]
    config: Arc<Config>,
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    data: PeerInfoArc,
    server: Arc<DashboardRpcClient>,
    token: auth::Token,
    poll_task: Option<JoinHandleArc>,
    escalatable_event: DashboardEventArc,
    events: Events,
    sort_column: PeerSortColumn,
    sort_order: SortOrder,
}

impl PeersScreen {
    pub fn new(
        config: Arc<Config>,
        rpc_server: Arc<DashboardRpcClient>,
        token: auth::Token,
    ) -> Self {
        let data = Arc::new(Mutex::new(vec![]));
        Self {
            sort_column: config.peer_sort_column,
            sort_order: config.peer_sort_order,
            config,
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            data: data.clone(),
            server: rpc_server,
            token,
            poll_task: None,
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
            events: data.into(),
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<DashboardRpcClient>,
        token: auth::Token,
        peer_info: PeerInfoArc,
        escalatable_event_arc: DashboardEventArc,
    ) -> ! {
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
                    match rpc_client.peer_info(context::current(), token).await {
                        Ok(Ok(pi)) => {

                            *peer_info.lock().unwrap() = pi;

                            *escalatable_event_arc.lock().unwrap() = Some(DashboardEvent::RefreshScreen);
                            reset_poller!(balance, Duration::from_secs(10));
                        },
                        Ok(Err(e)) => {
                            *escalatable_event_arc.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string()));
                        }
                        Err(e) => {
                            *escalatable_event_arc.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string()));
                        }
                    }
                }
            }
        }
    }

    fn char_to_column(c: char) -> Option<PeerSortColumn> {
        match c {
            'i' => Some(PeerSortColumn::Ip),
            'v' => Some(PeerSortColumn::Version),
            's' => Some(PeerSortColumn::Standing),
            'c' => Some(PeerSortColumn::ConnectionEstablished),
            'p' => Some(PeerSortColumn::LastPunishment),
            'r' => Some(PeerSortColumn::LastReward),
            _ => None,
        }
    }

    /// Set sort column to the column indicated by the given char. Also reverse
    /// the order.
    fn set_sort_column(&mut self, c: char) {
        if let Some(column) = Self::char_to_column(c) {
            self.sort_column = column;
            self.sort_order.reverse();
        }
    }

    /// handle a DashboardEvent
    ///
    /// In particular we handle Up/Down keypress for scrolling
    /// the history table.
    pub fn handle(&mut self, event: DashboardEvent) -> Option<DashboardEvent> {
        let mut escalate_event = None;

        if self.in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Down => self.events.next(),
                        KeyCode::Up => self.events.previous(),
                        KeyCode::PageDown => self.events.next_page(),
                        KeyCode::PageUp => self.events.previous_page(),
                        KeyCode::Char(c) if Self::char_to_column(c).is_some() => {
                            self.set_sort_column(c);
                            return None;
                        }
                        KeyCode::Char('x') => {
                            self.clear_selected_peer_standing();
                            return None;
                        }
                        _ => {
                            escalate_event = Some(event);
                        }
                    }
                }
            }
        }
        escalate_event
    }

    /// clear the selected peer standing
    ///
    /// spawns a task to call the dashboard rpc client to clear the standing
    /// for the selected peer.
    pub fn clear_selected_peer_standing(&self) {
        let selected_index = match self.events.state.selected() {
            Some(idx) if idx >= Events::TABLE_HEADER_ROWS => idx,
            _ => return,
        };

        let peer_ip = {
            let items = self.events.items.lock().unwrap();
            items
                .get(selected_index - Events::TABLE_HEADER_ROWS)
                .and_then(|peer| {
                    peer.address().iter().find_map(|component| match component {
                        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                        _ => None,
                    })
                })
        };

        let Some(ip) = peer_ip else { return };

        let (rpc_client, token, data_arc, event_arc) = (
            self.server.clone(),
            self.token,
            self.data.clone(),
            self.escalatable_event.clone(),
        );

        tokio::spawn(async move {
            if rpc_client
                .clear_peer_standing(context::current(), token, ip)
                .await
                .is_ok()
            {
                if let Ok(Ok(peer_info)) = rpc_client.peer_info(context::current(), token).await {
                    *data_arc.lock().unwrap() = peer_info;
                    *event_arc.lock().unwrap() = Some(DashboardEvent::RefreshScreen);
                }
            }
        });
    }
}

impl Screen for PeersScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        let escalatable_event_arc = self.escalatable_event.clone();
        let token = self.token;
        self.poll_task = Some(Arc::new(Mutex::new(tokio::spawn(async move {
            PeersScreen::run_polling_loop(server_arc, token, data_arc, escalatable_event_arc).await;
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

    fn escalatable_event(&self) -> DashboardEventArc {
        self.escalatable_event.clone()
    }
}

impl Widget for PeersScreen {
    fn render(mut self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
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

        let inner = area.inner(Margin {
            vertical: 2,
            horizontal: 2,
        });

        let mut vrecter = VerticalRectifier::new(inner);
        let peer_count_rect = vrecter.next((5).try_into().unwrap());

        let num_peers = self.data.lock().unwrap().len();

        let peer_count_buf = if self.in_focus {
            format!("Peers connected: {num_peers}           sort-keys: i, v, c, s, p, r           clear-peer-standing: x")
        } else {
            format!("Peers connected: {num_peers}           press enter for options")
        };

        let peer_count = Line::from(vec![Span::from(peer_count_buf)]);
        let peer_count_widget = Paragraph::new(peer_count).style(style);
        peer_count_widget.render(peer_count_rect, buf);

        // table
        let style = Style::default().fg(self.fg).bg(self.bg);
        let selected_style = style.add_modifier(Modifier::REVERSED);

        let header = vec![
            "ip",
            "version",
            "connection established",
            "standing",
            "last punishment",
            "last reward",
        ];

        let mut pi = self.data.lock().unwrap();

        match self.sort_column {
            PeerSortColumn::Ip => {
                pi.sort_by(|a, b| self.sort_order.compare(a.address(), b.address()))
            }
            PeerSortColumn::Version => {
                pi.sort_by(|a, b| self.sort_order.compare(a.version(), b.version()))
            }
            PeerSortColumn::Standing => pi.sort_by(|a, b| {
                self.sort_order
                    .compare(a.standing().standing, b.standing().standing)
            }),
            PeerSortColumn::ConnectionEstablished => pi.sort_by(|a, b| {
                self.sort_order
                    .compare(a.connection_established(), b.connection_established())
            }),
            PeerSortColumn::LastPunishment => pi.sort_by(|a, b| {
                self.sort_order.compare(
                    a.standing()
                        .latest_punishment
                        .map(|p| p.0.to_string())
                        .unwrap_or_default(),
                    b.standing()
                        .latest_punishment
                        .map(|p| p.0.to_string())
                        .unwrap_or_default(),
                )
            }),
            PeerSortColumn::LastReward => pi.sort_by(|a, b| {
                self.sort_order.compare(
                    a.standing()
                        .latest_reward
                        .map(|r| r.0.to_string())
                        .unwrap_or_default(),
                    b.standing()
                        .latest_reward
                        .map(|r| r.0.to_string())
                        .unwrap_or_default(),
                )
            }),
        };

        let matrix = pi
            .iter()
            .map(|pi| {
                let latest_punishment: Option<String> = pi
                    .standing()
                    .latest_punishment
                    .map(|(peer_sanction, _timestamp)| peer_sanction.to_string());
                let latest_reward: Option<String> = pi
                    .standing()
                    .latest_reward
                    .map(|(peer_sanction, _timestamp)| peer_sanction.to_string());
                let connection_established = pi
                    .connection_established()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap();
                vec![
                    pi.address().to_string(),
                    pi.version().to_string(),
                    neptune_cash::utc_timestamp_to_localtime(connection_established.as_millis())
                        .map(|ts| ts.to_string())
                        .unwrap_or("-".to_string()),
                    format!("{:>8}", pi.standing().to_string()),
                    latest_punishment.unwrap_or_default(),
                    latest_reward.unwrap_or_default(),
                ]
            })
            .collect_vec();
        let ncols = header.len();
        let mut widths: Vec<usize> = header.iter().map(|h| h.width()).collect();
        for (i, w) in widths.iter_mut().enumerate() {
            if let Some(body_max) = matrix.iter().map(|row| row[i].width()).max() {
                *w = max(*w, body_max);
            }
        }
        let mut widths_with_bars = vec![1];
        widths_with_bars.append(
            &mut widths
                .iter()
                .zip(vec![1; ncols].iter())
                .map(|(w, o)| vec![*w, *o])
                .collect_vec()
                .concat(),
        );
        let mut header_with_bars = vec!["│".to_string()];
        header_with_bars.append(
            &mut header
                .clone()
                .into_iter()
                .zip(vec!["│"; ncols].iter())
                .map(|(h, &b)| vec![h.to_string(), b.to_string()])
                .collect_vec()
                .concat(),
        );
        let mut top_with_bars = widths_with_bars
            .iter()
            .enumerate()
            .map(|(i, w)| {
                if i % 2 == 0 {
                    "┬".to_string()
                } else {
                    "─".to_string().repeat(*w)
                }
            })
            .collect_vec();
        top_with_bars[0] = "╭".to_string();
        *top_with_bars.last_mut().unwrap() = "╮".to_string();
        let mut separator_with_bars = widths_with_bars
            .iter()
            .enumerate()
            .map(|(i, w)| {
                if i % 2 == 0 {
                    "┼".to_string()
                } else {
                    "─".to_string().repeat(*w)
                }
            })
            .collect_vec();
        separator_with_bars[0] = "├".to_string();
        *separator_with_bars.last_mut().unwrap() = "┤".to_string();
        let mut footer_with_bars = widths_with_bars
            .iter()
            .enumerate()
            .map(|(i, w)| {
                if i % 2 == 0 {
                    "┴".to_string()
                } else {
                    "─".to_string().repeat(*w)
                }
            })
            .collect_vec();
        footer_with_bars[0] = "╰".to_string();
        *footer_with_bars.last_mut().unwrap() = "╯".to_string();

        let mut body = matrix
            .iter()
            .map(|row| {
                let mut row_with_bars = vec!["│".to_string()];
                row_with_bars.append(
                    &mut row
                        .iter()
                        .zip(vec!["│"; ncols].iter())
                        .map(|(r, &b)| vec![r.to_string(), b.to_string()])
                        .collect_vec()
                        .concat(),
                );
                row_with_bars
            })
            .map(|row| Row::new(row.iter().map(|c| Cell::from(c.to_string()))))
            .collect_vec();
        for (i, item) in body.iter_mut().enumerate() {
            if i % 2 == 0 {
                *item = item.clone().style(Style::default().bg(Color::DarkGray));
            }
        }
        let mut rows: Vec<Row> = vec![
            Row::new(top_with_bars),
            Row::new(header_with_bars),
            Row::new(separator_with_bars),
        ];
        rows.append(&mut body);
        rows.push(Row::new(footer_with_bars));

        let width_constraints = widths_with_bars
            .iter()
            .map(|w| Constraint::Length(*w as u16))
            .collect_vec();
        let table = Table::new(rows, width_constraints)
            .style(style)
            .row_highlight_style(selected_style);
        vrecter.set_width(min(
            inner.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        ));

        let mut table_rect = vrecter.remaining();
        table_rect.height -= 2; // shouldn't be necessary???

        table_rect.width = min(
            table_rect.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        );
        StatefulWidget::render(table, table_rect, buf, &mut self.events.state);
    }
}

// Define some events to display.
// note: based on ratatui scrollable table example at:
//   https://github.com/ratatui-org/ratatui/blob/main/examples/table.rs
#[derive(Debug, Clone)]
struct Events {
    // `items` is the state managed by the application.
    items: PeerInfoArc,
    // `state` is the state that can be modified by the UI. It stores the index of the selected
    // item as well as the offset computed during the previous draw call (used to implement
    // natural scrolling).
    state: TableState,
}

impl From<PeerInfoArc> for Events {
    fn from(items: PeerInfoArc) -> Self {
        Events {
            items,
            state: Default::default(),
        }
    }
}

impl Events {
    // # of rows in table header (1 text row, 2 border rows).
    // this is used to avoid selecting the header rows.
    // kind of a hack, but appears to be necessary for now.
    // ratatui seems to be redesigning scrollable widgets at present.
    const TABLE_HEADER_ROWS: usize = 3;

    /// Number of rows in the dashboard, not counting the rows allocated to the
    /// screen. Phrased differently, subtracting this number from the terminal
    /// height gives the screen height.
    const DASHBOARD_HEADER_FOOTER_ROWS: usize = 3;

    // Select the next item. This will not be reflected until the widget is drawn
    // with `Frame::render_stateful_widget`.
    pub fn next(&mut self) {
        let offset = Self::TABLE_HEADER_ROWS;
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.lock().unwrap().len() + offset - 1 {
                    i // end on last entry.  (no wrap to start)
                } else {
                    i + 1
                }
            }
            None => offset,
        };
        self.state.select(Some(i));
    }

    // Select the previous item. This will not be reflected until the widget is drawn
    // with `Frame::render_stateful_widget`.
    pub fn previous(&mut self) {
        let offset = Self::TABLE_HEADER_ROWS;
        let i = match self.state.selected() {
            Some(i) => {
                if i == offset {
                    i // stay at first entry.  (no wrap to end.)
                } else {
                    i - 1
                }
            }
            None => offset,
        };
        self.state.select(Some(i));
    }

    /// Get the height of the terminal.
    fn terminal_height() -> u16 {
        if let Ok((_cols, rows)) = crossterm::terminal::size() {
            rows
        } else {
            1
        }
    }

    /// Jump the selector down by a page.
    ///
    /// By convention, one page is half the number of visible rows.
    pub fn next_page(&mut self) {
        let offset = Self::TABLE_HEADER_ROWS;
        let num_rows = Self::terminal_height() as usize
            - Self::TABLE_HEADER_ROWS
            - Self::DASHBOARD_HEADER_FOOTER_ROWS;
        let jump_height = usize::max(1, num_rows / 2);
        let i = match self.state.selected() {
            Some(i) => usize::min(
                self.items.lock().unwrap().len() + offset - 1,
                i + jump_height,
            ),
            None => offset,
        };
        self.state.select(Some(i));
    }

    // Jump the selector up by a page.
    ///
    /// By convention, one page is half the number of visible rows.
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
}
