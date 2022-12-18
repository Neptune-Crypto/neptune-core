use std::{
    cell::RefCell,
    cmp::{max, min},
    sync::{Arc, Mutex},
    time::Duration,
};

use super::screen::Screen;
use chrono::{DateTime, Utc};
use itertools::Itertools;
use neptune_core::{models::peer::PeerInfo, rpc_server::RPCClient};
use tarpc::context;
use tokio::time::sleep;
use tokio::{select, task::JoinHandle};
use tui::{
    layout::{Constraint, Margin},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Row, Table, Widget},
};
use unicode_width::UnicodeWidthStr;

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
            data: Arc::new(Mutex::new(vec![])),
            server: rpc_server,
            poll_thread: None,
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<RPCClient>,
        peer_info: Arc<std::sync::Mutex<Vec<PeerInfo>>>,
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
                    let pi = rpc_client.get_peer_info(context::current()).await.unwrap();
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

        let mut inner = area.inner(&Margin {
            vertical: 2,
            horizontal: 2,
        });

        // table
        let style = Style::default().fg(self.fg).bg(self.bg);
        let header = vec![
            "ip",
            "last seen",
            "standing",
            "archival",
            "authenticated",
            "alias",
        ];
        let matrix = self
            .data
            .lock()
            .unwrap()
            .iter()
            .map(|pi| {
                vec![
                    pi.connected_address.to_string(),
                    DateTime::<Utc>::from(pi.last_seen).to_string(),
                    pi.standing.standing.to_string(),
                    if pi.is_archival_node {
                        "✓".to_string()
                    } else {
                        "".to_string()
                    },
                    "✕".to_string(), // no support for authentication yet
                    "-".to_string(),   // no support for aliases yes
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
        let table = Table::new(rows).widths(&width_constraints).style(style);
        inner.width = min(
            inner.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        );
        table.render(inner, buf);
    }
}
