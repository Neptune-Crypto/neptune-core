use std::cmp::max;
use std::cmp::min;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use itertools::Itertools;
use neptune_core::rpc_server::MempoolTransactionInfo;
use neptune_core::rpc_server::RPCClient;
use num_traits::CheckedSub;
use ratatui::layout::Constraint;
use ratatui::layout::Margin;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Cell;
use ratatui::widgets::Row;
use ratatui::widgets::Table;
use ratatui::widgets::Widget;
use tarpc::context;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use unicode_width::UnicodeWidthStr;

use super::dashboard_app::DashboardEvent;
use super::screen::Screen;

const PAGE_SIZE: usize = 20;

#[derive(Debug, Clone)]
pub struct MempoolScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    data: Arc<std::sync::Mutex<Vec<MempoolTransactionInfo>>>,
    server: Arc<RPCClient>,
    poll_task: Option<Arc<std::sync::Mutex<JoinHandle<()>>>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
    page_start: Arc<std::sync::Mutex<usize>>,
}

impl MempoolScreen {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        MempoolScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            data: Arc::new(Mutex::new(vec![])),
            server: rpc_server,
            poll_task: None,
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
            page_start: Arc::new(std::sync::Mutex::new(0)),
        }
    }

    async fn run_polling_loop(
        page_start: Arc<std::sync::Mutex<usize>>,
        rpc_client: Arc<RPCClient>,
        mempool_transaction_info: Arc<std::sync::Mutex<Vec<MempoolTransactionInfo>>>,
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
                    let page_start_clone = *page_start.lock().unwrap();
                    match rpc_client.mempool_overview(context::current(), page_start_clone, PAGE_SIZE).await {
                        Ok(mo) => {
                            *mempool_transaction_info.lock().unwrap() = mo;

                            *escalatable_event_arc.lock().unwrap() = Some(DashboardEvent::RefreshScreen);
                            reset_poller!(balance, Duration::from_secs(10));
                        },
                        Err(e) => {
                            *escalatable_event_arc.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string()));
                        }
                    }
                }
            }
        }
    }
}

impl Screen for MempoolScreen {
    fn activate(&mut self) {
        self.active = true;
        let page_start_arc = self.page_start.clone();
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        let escalatable_event_arc = self.escalatable_event.clone();
        self.poll_task = Some(Arc::new(Mutex::new(tokio::spawn(async move {
            MempoolScreen::run_polling_loop(
                page_start_arc,
                server_arc,
                data_arc,
                escalatable_event_arc,
            )
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

impl Widget for MempoolScreen {
    fn render(self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
        // overview box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Mempool")
            .style(style)
            .render(area, buf);

        let mut inner = area.inner(Margin {
            vertical: 2,
            horizontal: 2,
        });

        // table
        let style = Style::default().fg(self.fg).bg(self.bg);
        let header = vec![
            "id",
            "proof type",
            "#inputs",
            "#outputs",
            "+ effect on balance",
            "- effect on balance",
            "Δ balance",
            "fee",
            "synced",
        ];
        let matrix = self
            .data
            .lock()
            .unwrap()
            .iter()
            .map(|mptxi| {
                let balance_delta = if mptxi.positive_balance_effect > mptxi.negative_balance_effect
                {
                    mptxi
                        .positive_balance_effect
                        .checked_sub(&mptxi.negative_balance_effect)
                        .unwrap()
                } else {
                    -mptxi
                        .negative_balance_effect
                        .checked_sub(&mptxi.positive_balance_effect)
                        .unwrap()
                };
                vec![
                    mptxi.id.to_string(),
                    mptxi.proof_type.to_string(),
                    mptxi.num_inputs.to_string(),
                    mptxi.num_outputs.to_string(),
                    mptxi.positive_balance_effect.to_string(),
                    mptxi.negative_balance_effect.to_string(),
                    balance_delta.to_string(),
                    mptxi.fee.to_string(),
                    if mptxi.synced {
                        "✓".to_string()
                    } else {
                        "✕".to_string()
                    },
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
        inner.width = min(
            inner.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        );
        table.render(inner, buf);
    }
}
