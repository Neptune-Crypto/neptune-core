use std::cmp::max;
use std::cmp::min;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::dashboard_app::DashboardEvent;
use crate::dashboard_rpc_client::DashboardRpcClient;
use crate::screen::Screen;
use crate::scrollable_table::ScrollableTable;
use crossterm::event::Event;
use crossterm::event::KeyEventKind;
use itertools::Itertools;
use neptune_cash::application::rpc::auth;
use neptune_cash::application::rpc::server::ui_utxo::UiUtxo;
use ratatui::layout::Constraint;
use ratatui::layout::Margin;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Cell;
use ratatui::widgets::Row;
use ratatui::widgets::StatefulWidget;
use ratatui::widgets::Table;
use ratatui::widgets::Widget;
use tarpc::context;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone)]
pub struct UtxosScreen {
    active: bool,
    in_focus: bool,
    data: Arc<std::sync::Mutex<Vec<UiUtxo>>>,
    fg: Color,
    bg: Color,
    server: Arc<DashboardRpcClient>,
    token: auth::Token,
    poll_task: Option<Arc<Mutex<JoinHandle<()>>>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
    scrollable_table: ScrollableTable<UiUtxo>,
}

impl UtxosScreen {
    pub fn new(rpc_server: Arc<DashboardRpcClient>, token: auth::Token) -> Self {
        let data = Arc::new(Mutex::new(vec![]));
        Self {
            active: false,
            in_focus: false,
            data: data.clone(),
            fg: Color::Gray,
            bg: Color::Black,
            server: rpc_server,
            token,
            poll_task: None,
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
            scrollable_table: ScrollableTable::new(data),
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<DashboardRpcClient>,
        token: auth::Token,
        data_arc: Arc<Mutex<Vec<UiUtxo>>>,
        escalatable_event: Arc<Mutex<Option<DashboardEvent>>>,
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
                    match rpc_client.list_utxos(context::current(), token).await {
                        Ok(Ok(coins)) => {

                            *data_arc.lock().unwrap() = coins;

                            *escalatable_event.lock().unwrap() = Some(DashboardEvent::RefreshScreen);

                            reset_poller!(balance, Duration::from_secs(10));
                        },
                        Ok(Err(e)) => {
                            *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string()));
                        }
                        Err(e) => {
                            *escalatable_event.lock().unwrap() = Some(DashboardEvent::Shutdown(e.to_string()));
                        }
                    }
                },

            }
        }
    }

    /// Handle Up/Down keypress for scrolling
    pub fn handle(&mut self, event: DashboardEvent) -> Option<DashboardEvent> {
        let mut escalate_event = None;

        if self.in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
                if key.kind == KeyEventKind::Press {
                    if self.scrollable_table.handle_navigation(&event) {
                        return None;
                    }

                    escalate_event = Some(event);
                }
            }
        }
        escalate_event
    }
}

impl Screen for UtxosScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        let escalatable_event_arc = self.escalatable_event.clone();
        let token = self.token;
        self.poll_task = Some(Arc::new(Mutex::new(tokio::spawn(async move {
            UtxosScreen::run_polling_loop(server_arc, token, data_arc, escalatable_event_arc).await;
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

    fn escalatable_event(&self) -> Arc<Mutex<Option<DashboardEvent>>> {
        self.escalatable_event.clone()
    }
}

impl Widget for UtxosScreen {
    fn render(mut self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
        // address box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("UTXOs")
            .style(style)
            .render(area, buf);

        // subdivide into two parts
        let mut table_canvas = area.inner(Margin {
            vertical: 2,
            horizontal: 2,
        });

        // chart
        // ?
        // todo

        // table
        let style = Style::default().fg(self.fg).bg(self.bg);
        let selected_style = style.add_modifier(Modifier::REVERSED);
        let header = vec!["received", "id", "amount", "release date", "spent"];

        let matrix = self
            .data
            .lock()
            .unwrap()
            .iter()
            .map(|c| {
                [
                    c.received.to_string(),
                    c.aocl_leaf_index
                        .map(|li| format!("{li}"))
                        .unwrap_or("".to_string()),
                    c.amount.display_lossless(),
                    c.release_date
                        .map(|rd| rd.standard_format())
                        .unwrap_or_else(|| "-".to_string()),
                    c.spent.to_string(),
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
        table_canvas.width = min(
            table_canvas.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        );
        StatefulWidget::render(table, table_canvas, buf, self.scrollable_table.state_mut());
    }
}
