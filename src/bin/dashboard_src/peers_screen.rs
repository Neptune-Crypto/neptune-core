use std::cmp::max;
use std::cmp::min;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use itertools::Itertools;
use neptune_cash::models::peer::peer_info::PeerInfo;
use neptune_cash::rpc_auth;
use neptune_cash::rpc_server::RPCClient;
use ratatui::layout::Constraint;
use ratatui::layout::Margin;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Cell;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::Widget;
use tarpc::context;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use unicode_width::UnicodeWidthStr;

use super::dashboard_app::DashboardEvent;
use super::overview_screen::VerticalRectifier;
use super::screen::Screen;

#[derive(Debug, Clone)]
pub struct PeersScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    data: Arc<std::sync::Mutex<Vec<PeerInfo>>>,
    server: Arc<RPCClient>,
    token: rpc_auth::Token,
    poll_task: Option<Arc<Mutex<JoinHandle<()>>>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
}

impl PeersScreen {
    pub fn new(rpc_server: Arc<RPCClient>, token: rpc_auth::Token) -> Self {
        Self {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            data: Arc::new(Mutex::new(vec![])),
            server: rpc_server,
            token,
            poll_task: None,
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<RPCClient>,
        token: rpc_auth::Token,
        peer_info: Arc<std::sync::Mutex<Vec<PeerInfo>>>,
        escalatable_event_arc: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
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
                    // dummy data for testing
                    // let pi = vec![
                    //     PeerInfo{
                    //         address_for_incoming_connections: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)),
                    //         connected_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                    //         instance_id: 893457,
                    //         inbound: true,
                    //         last_seen: SystemTime::now(),
                    //         standing: PeerStanding::default(),
                    //         version: "hello".to_string(),
                    //         is_archival_node: true,
                    //     },
                    //     PeerInfo{
                    //         address_for_incoming_connections: None,
                    //         connected_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 255, 0, 1)), 8080),
                    //         instance_id: 90564,
                    //         inbound: false,
                    //         last_seen: SystemTime::now(),
                    //         standing: PeerStanding::default(),
                    //         version: "world".to_string(),
                    //         is_archival_node: false,
                    //     }
                    // ];
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

    fn escalatable_event(&self) -> Arc<std::sync::Mutex<Option<DashboardEvent>>> {
        self.escalatable_event.clone()
    }
}

impl Widget for PeersScreen {
    fn render(self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
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

        let peer_count = Line::from(vec![Span::from(format!("Peers connected: {}", num_peers))]);
        let peer_count_widget = Paragraph::new(peer_count).style(style);
        peer_count_widget.render(peer_count_rect, buf);

        // table
        let style = Style::default().fg(self.fg).bg(self.bg);
        let header = vec![
            "ip",
            "connection established",
            "standing",
            "last punishment",
            "last reward",
        ];

        let matrix = self
            .data
            .lock()
            .unwrap()
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
                    pi.connected_address().to_string(),
                    neptune_cash::utc_timestamp_to_localtime(connection_established.as_millis())
                        .to_string(),
                    pi.standing().to_string(),
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
                .map(|(h, b)| vec![h.to_string(), b.to_string()])
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
                        .map(|(r, b)| vec![r.to_string(), b.to_string()])
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
        let table = Table::new(rows, width_constraints).style(style);
        vrecter.set_width(min(
            inner.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        ));
        let mut table_rect = vrecter.remaining();
        table_rect.height -= 2; // shouldn't be necessary???
        table.render(table_rect, buf);
    }
}
