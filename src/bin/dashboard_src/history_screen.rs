use std::{
    cell::RefCell,
    cmp::{max, min},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::screen::Screen;
use chrono::{DateTime, Utc};
use itertools::Itertools;
use neptune_core::{models::blockchain::transaction::Amount, rpc_server::RPCClient};
use tokio::time::sleep;
use tokio::{select, task::JoinHandle};
use tui::{
    layout::{Constraint, Margin},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Row, Table, Widget},
};
use unicode_width::UnicodeWidthStr;

#[derive(Debug, PartialEq, Eq)]
pub enum Sign {
    In,
    Out,
}

type BalanceUpdate = (SystemTime, Amount, Sign, Amount);

#[derive(Debug, Clone)]
pub struct HistoryScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    data: Arc<std::sync::Mutex<Vec<BalanceUpdate>>>,
    server: Arc<RPCClient>,
    poll_thread: Option<Arc<RefCell<JoinHandle<()>>>>,
}

impl HistoryScreen {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        HistoryScreen {
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
        _rpc_client: Arc<RPCClient>,
        balance_updates: Arc<std::sync::Mutex<Vec<BalanceUpdate>>>,
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

        setup_poller!(balance_history);

        loop {
            select! {
                _ = &mut balance_history => {
                    // let bh = rpc_client.get_balance_history(context::current()).await.unwrap();
                    // placeholder until the above RPC call is implemented
                    let bh = vec![
                    (UNIX_EPOCH, Amount::from(2500), Sign::In, Amount::from(2500)),
                    (UNIX_EPOCH+Duration::from_secs(60*60*24*365*20), Amount::from(1500), Sign::Out, Amount::from(1000)),
                    (UNIX_EPOCH+Duration::from_secs(60*60*24*365*25), Amount::from(500), Sign::Out, Amount::from(500)),];
                    *balance_updates.lock().unwrap() = bh;
                    reset_poller!(balance_history, Duration::from_secs(10));
                }
            }
        }
    }
}

impl Screen for HistoryScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        self.poll_thread = Some(Arc::new(RefCell::new(tokio::spawn(async move {
            HistoryScreen::run_polling_loop(server_arc, data_arc).await;
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

impl Widget for HistoryScreen {
    fn render(self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        // history box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("History")
            .style(style)
            .render(area, buf);

        // subdivide into two parts
        let mut table_canvas = area.inner(&Margin {
            vertical: 2,
            horizontal: 2,
        });

        // chart
        // ?
        // todo

        // table
        let style = Style::default().fg(self.fg).bg(self.bg);
        let header = vec!["date", " ", "amount", "balance after"];
        let matrix = self
            .data
            .lock()
            .unwrap()
            .iter()
            .rev()
            .map(|bu| {
                vec![
                    DateTime::<Utc>::from(bu.0).to_string(),
                    if bu.2 == Sign::In {
                        "↘".to_string()
                    } else {
                        "↗".to_string()
                    },
                    bu.1.to_string(),
                    bu.3.to_string(),
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
        table_canvas.width = min(
            table_canvas.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        );
        table.render(table_canvas, buf);
    }
}
