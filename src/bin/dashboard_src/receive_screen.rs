use std::{
    cmp::max,
    error::Error,
    sync::{Arc, Mutex},
};

use super::{
    dashboard_app::{ConsoleIO, DashboardEvent},
    overview_screen::VerticalRectifier,
    screen::Screen,
};
use crossterm::event::{Event, KeyCode, KeyEventKind};
use neptune_core::{config_models::network::Network, rpc_server::RPCClient};
use ratatui::{
    layout::{Alignment, Margin},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph, Widget},
};
use tarpc::context;

#[derive(Debug, PartialEq, Eq)]
pub enum Sign {
    In,
    Out,
}

#[derive(Debug, Clone)]
pub struct ReceiveScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    data: Arc<std::sync::Mutex<Option<String>>>,
    server: Arc<RPCClient>,
    generating: Arc<Mutex<bool>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
    network: Network,
}

impl ReceiveScreen {
    pub fn new(rpc_server: Arc<RPCClient>, network: Network) -> Self {
        ReceiveScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            data: Arc::new(Mutex::new(None)),
            server: rpc_server,
            generating: Arc::new(Mutex::new(false)),
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
            network,
        }
    }

    fn populate_receiving_address_async(
        &self,
        rpc_client: Arc<RPCClient>,
        data: Arc<Mutex<Option<String>>>,
    ) {
        if data.lock().unwrap().is_none() {
            let network = self.network;
            tokio::spawn(async move {
                // TODO: change to receive most recent wallet
                let receiving_address = rpc_client
                    .get_receiving_address(context::current())
                    .await
                    .unwrap();
                *data.lock().unwrap() = Some(receiving_address.to_bech32m(network).unwrap());
            });
        }
    }

    fn generate_new_receiving_address_async(
        &self,
        rpc_client: Arc<RPCClient>,
        data: Arc<Mutex<Option<String>>>,
        generating: Arc<Mutex<bool>>,
    ) {
        let network = self.network;
        tokio::spawn(async move {
            *generating.lock().unwrap() = true;
            let receiving_address = rpc_client
                .get_receiving_address(context::current())
                .await
                .unwrap();
            *data.lock().unwrap() = Some(receiving_address.to_bech32m(network).unwrap());
            *generating.lock().unwrap() = false;
        });
    }

    pub fn handle(
        &mut self,
        event: DashboardEvent,
    ) -> Result<Option<DashboardEvent>, Box<dyn Error>> {
        let mut escalate_event = None;
        if self.in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Enter => {
                            self.generate_new_receiving_address_async(
                                self.server.clone(),
                                self.data.clone(),
                                self.generating.clone(),
                            );
                            escalate_event = None;
                        }
                        KeyCode::Char('c') => {
                            if let Some(address) = self.data.lock().unwrap().as_ref() {
                                return Ok(Some(DashboardEvent::ConsoleMode(
                                    ConsoleIO::InputRequested(format!("{}\n\n", address)),
                                )));
                            }
                        }
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

impl Screen for ReceiveScreen {
    fn activate(&mut self) {
        self.active = true;
        let server_arc = self.server.clone();
        let data_arc = self.data.clone();
        self.populate_receiving_address_async(server_arc, data_arc);
    }

    fn deactivate(&mut self) {
        self.active = false;
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

impl Widget for ReceiveScreen {
    fn render(self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
        // receive box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Receive")
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

        // display address
        let mut address = match self.data.lock().unwrap().to_owned() {
            Some(str) => str,
            None => "-".to_string(),
        };
        let width = max(0, inner.width as isize - 2) as usize;
        if width > 0 {
            let mut address_lines = vec![];
            while address.len() > width {
                let (line, remainder) = address.split_at(width);
                address_lines.push(line.to_owned());
                address = remainder.to_owned();
            }
            address_lines.push(address);

            let address_rect = vrecter.next((address_lines.len() + 2).try_into().unwrap());
            if address_rect.height > 0 {
                let address_display = Paragraph::new(Text::from(address_lines.join("\n")))
                    .style(style)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(Span::styled("Receiving Address", Style::default())),
                    )
                    .alignment(Alignment::Left);
                address_display.render(address_rect, buf);
            }

            // display generation instructions
            if *self.generating.lock().unwrap() {
                let generating_text =
                    Paragraph::new(Span::from("Generating ...")).alignment(Alignment::Left);
                generating_text.render(vrecter.next(1), buf);
            } else {
                let action = if self.in_focus {
                    "generate a new address"
                } else {
                    "focus"
                };
                let instructions = Line::from(vec![
                    Span::from("Press "),
                    Span::styled("Enter ↵", Style::default().fg(Color::LightCyan)),
                    Span::from(" to "),
                    Span::from(action),
                    Span::from("."),
                ]);
                let style = Style::default().fg(self.fg);
                let generate_instructions = Paragraph::new(instructions).style(style);
                generate_instructions.render(vrecter.next(1), buf);
            }

            // display copy instructions
            if self.in_focus {
                let style = Style::default().fg(self.fg);
                let instructions = Line::from(vec![
                    Span::from("Press "),
                    Span::styled(
                        "C",
                        if self.in_focus {
                            Style::default().fg(Color::LightCyan)
                        } else {
                            style
                        },
                    ),
                    Span::from(" display in console mode."),
                ]);
                let generate_instructions = Paragraph::new(instructions).style(style);
                generate_instructions.render(vrecter.next(1), buf);
            }
        }
    }
}
