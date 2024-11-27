use std::cmp::max;
use std::cmp::min;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use itertools::Itertools;
use neptune_cash::config_models::network::Network;
use neptune_cash::models::state::wallet::address::KeyType;
use neptune_cash::models::state::wallet::address::SpendingKey;
use neptune_cash::rpc_server::RPCClient;
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
use ratatui::widgets::TableState;
use ratatui::widgets::Widget;
use tarpc::context;
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use unicode_width::UnicodeWidthStr;

use super::dashboard_app::DashboardEvent;
use super::screen::Screen;

type AddressUpdate = SpendingKey;
type AddressUpdateArc = Arc<std::sync::Mutex<Vec<AddressUpdate>>>;
type DashboardEventArc = Arc<std::sync::Mutex<Option<DashboardEvent>>>;
type JoinHandleArc = Arc<Mutex<JoinHandle<()>>>;

// Define some events to display.
// note: based on ratatui scrollable table example at:
//   https://github.com/ratatui-org/ratatui/blob/main/examples/table.rs
#[derive(Debug, Clone)]
struct Events {
    // `items` is the state managed by the application.
    items: AddressUpdateArc,
    // `state` is the state that can be modified by the UI. It stores the index of the selected
    // item as well as the offset computed during the previous draw call (used to implement
    // natural scrolling).
    state: TableState,
}

impl From<AddressUpdateArc> for Events {
    fn from(items: AddressUpdateArc) -> Self {
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
}

#[derive(Debug, Clone)]
pub struct AddressScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    data: AddressUpdateArc,
    server: Arc<RPCClient>,
    poll_task: Option<JoinHandleArc>,
    escalatable_event: DashboardEventArc,
    events: Events,
    network: Network,
}

impl AddressScreen {
    pub fn new(rpc_server: Arc<RPCClient>, network: Network) -> Self {
        let data = Arc::new(Mutex::new(vec![]));
        AddressScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            data: data.clone(),
            server: rpc_server,
            poll_task: None,
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
            events: data.into(),
            network,
        }
    }

    async fn run_polling_loop(
        rpc_client: Arc<RPCClient>,
        address_updates: AddressUpdateArc,
        escalatable_event: DashboardEventArc,
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

        setup_poller!(addresses);

        loop {
            select! {
                _ = &mut addresses => {
                    let keys = rpc_client.known_keys(context::current()).await.unwrap();

                    *address_updates.lock().unwrap() = keys;

                    *escalatable_event.lock().unwrap() = Some(DashboardEvent::RefreshScreen);

                    reset_poller!(addresses, Duration::from_secs(10));
                },
            }
        }
    }

    /// handle a DashboardEvent
    ///
    /// In particular we handle Up/Down keypress for scrolling
    /// the address table.
    pub fn handle(
        &mut self,
        event: DashboardEvent,
    ) -> Result<Option<DashboardEvent>, Box<dyn std::error::Error>> {
        let mut escalate_event = None;

        if self.in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Down => self.events.next(),
                        KeyCode::Up => self.events.previous(),
                        // todo: PgUp,PgDn.  (but how to determine page size?  fixed n?)
                        _ => {
                            escalate_event = Some(event);
                        }
                    }
                }
            }
        }
        Ok(escalate_event)
    }
}

impl Screen for AddressScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        let escalatable_event_arc = self.escalatable_event.clone();
        self.poll_task = Some(Arc::new(Mutex::new(tokio::spawn(async move {
            AddressScreen::run_polling_loop(server_arc, data_arc, escalatable_event_arc).await;
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

impl Widget for AddressScreen {
    fn render(mut self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
        // address box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Known Addresses")
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
        let header = vec!["type", "address (abbreviated)"];

        let matrix = self
            .data
            .lock()
            .unwrap()
            .iter()
            .rev()
            .map(|key| {
                vec![
                    KeyType::from(key).to_string(),
                    key.to_address()
                        .to_bech32m_abbreviated(self.network)
                        .unwrap(),
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
        let table = Table::new(rows, width_constraints)
            // .widths(&width_constraints)
            .style(style)
            .row_highlight_style(selected_style);
        table_canvas.width = min(
            table_canvas.width,
            widths.iter().sum::<usize>() as u16 + 3 * widths.len() as u16 + 1,
        );
        StatefulWidget::render(table, table_canvas, buf, &mut self.events.state);
    }
}
