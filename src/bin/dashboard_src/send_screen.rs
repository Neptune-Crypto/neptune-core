use std::{
    borrow::{Borrow, BorrowMut},
    cmp::max,
    error::Error,
    sync::{Arc, Mutex},
};

use super::{
    dashboard_app::{ConsoleIO, DashboardEvent},
    overview_screen::VerticalRectifier,
    screen::Screen,
};
use crossterm::event::{Event, KeyCode};
use neptune_core::rpc_server::RPCClient;

use tui::{
    layout::{Alignment, Margin},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, Borders, Paragraph, Widget},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendScreenWidget {
    Address,
    Amount,
    Ok,
    Notice,
}

#[derive(Debug, Clone)]
pub struct SendScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    address: Arc<Mutex<Option<String>>>,
    server: Arc<RPCClient>,
    focus: SendScreenWidget,
    amount: Arc<Mutex<String>>,
}

impl SendScreen {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        SendScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            address: Arc::new(Mutex::new(None)),
            server: rpc_server,
            focus: SendScreenWidget::Address,
            amount: Arc::new(Mutex::new("".to_string())),
        }
    }

    pub fn handle(
        &mut self,
        event: DashboardEvent,
    ) -> Result<Option<DashboardEvent>, Box<dyn Error>> {
        let mut escalate_event = None;
        if self.in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
                match key.code {
                    KeyCode::Enter => {
                        match self.focus {
                            SendScreenWidget::Address => {
                                return Ok(Some(DashboardEvent::ConsoleMode(ConsoleIO::Input(
                                    "Please enter recipient address:\n".to_string(),
                                ))));
                            }
                            SendScreenWidget::Amount => {
                                self.focus = SendScreenWidget::Ok;
                                escalate_event = None;
                            }
                            SendScreenWidget::Ok => {
                                // send payment
                                // switch screen
                                self.focus = SendScreenWidget::Notice;
                                escalate_event = None;
                            }
                            _ => {
                                escalate_event = None;
                            }
                        }
                    }
                    KeyCode::Up => {
                        self.focus = match self.focus {
                            SendScreenWidget::Address => SendScreenWidget::Ok,
                            SendScreenWidget::Amount => SendScreenWidget::Address,
                            SendScreenWidget::Ok => SendScreenWidget::Amount,
                            SendScreenWidget::Notice => SendScreenWidget::Ok,
                        };
                        escalate_event = None;
                    }
                    KeyCode::Down => {
                        self.focus = match self.focus {
                            SendScreenWidget::Address => SendScreenWidget::Amount,
                            SendScreenWidget::Amount => SendScreenWidget::Ok,
                            SendScreenWidget::Ok => SendScreenWidget::Address,
                            SendScreenWidget::Notice => SendScreenWidget::Address,
                        };
                        escalate_event = None;
                    }
                    KeyCode::Char(c) => {
                        if self.focus == SendScreenWidget::Amount {
                            let amount: String = self.amount.lock().unwrap().to_string();
                            let mut amount_mut = self.amount.lock().unwrap();
                            *amount_mut = format!("{}{}", amount, c);
                            escalate_event = None;
                        }
                    }
                    KeyCode::Backspace => {
                        if self.focus == SendScreenWidget::Amount {
                            let amount: String = self.amount.lock().unwrap().to_string();
                            let mut amount_mut = self.amount.lock().unwrap();
                            amount_mut.drain(amount.len() - 1..);
                            escalate_event = None;
                        }
                    }
                    _ => {
                        escalate_event = Some(event);
                    }
                }
            }
        }
        Ok(escalate_event)
    }
}

impl Screen for SendScreen {
    fn activate(&mut self) {
        self.active = true;
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
}

impl Widget for SendScreen {
    fn render(self, area: tui::layout::Rect, buf: &mut tui::buffer::Buffer) {
        // receive box
        let style: Style = if self.in_focus {
            Style::default().fg(Color::LightCyan).bg(self.bg)
        } else {
            Style::default().fg(Color::Gray).bg(self.bg)
        };
        Block::default()
            .borders(Borders::ALL)
            .title("Send")
            .style(style)
            .render(area, buf);

        // divide the overview box vertically into subboxes,
        // and render each separately
        let style = Style::default().bg(self.bg).fg(self.fg);
        let focus_style = Style::default().bg(self.bg).fg(Color::LightCyan);
        let inner = area.inner(&Margin {
            vertical: 1,
            horizontal: 1,
        });
        let width = max(0, inner.width as isize - 2) as usize;
        if width > 0 {
            let mut vrecter = VerticalRectifier::new(inner);

            // display address widget
            let mut address = match self.address.lock().unwrap().to_owned() {
                Some(str) => str,
                None => "-".to_string(),
            };
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
                    .style(
                        if self.focus == SendScreenWidget::Address && self.in_focus {
                            focus_style
                        } else {
                            style
                        },
                    )
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(Span::styled("Recipient Address", Style::default())),
                    )
                    .alignment(Alignment::Left);
                address_display.render(address_rect, buf);
            }
            let instruction_rect = vrecter.next(1);
            if instruction_rect.height > 0 {
                let instructions = if self.in_focus && self.focus == SendScreenWidget::Address {
                    Spans::from(vec![
                        Span::from("Press "),
                        Span::styled("Enter ↵", Style::default().fg(Color::LightCyan)),
                        Span::from(" to enter address via console mode."),
                    ])
                } else {
                    Spans::from(vec![])
                };
                let instructions_widget = Paragraph::new(instructions).style(style);
                instructions_widget.render(instruction_rect, buf);
            }

            // display amount widget
            let amount = self.amount.lock().unwrap();
            let amount_rect = vrecter.next(3);
            let amount_widget = Paragraph::new(Spans::from(vec![
                Span::from(amount.to_string()),
                Span::styled(
                    "|",
                    if self.focus == SendScreenWidget::Amount {
                        Style::default().add_modifier(Modifier::RAPID_BLINK)
                    } else {
                        style
                    },
                ),
            ]))
            .style(if self.focus == SendScreenWidget::Amount {
                focus_style
            } else {
                style
            })
            .block(Block::default().borders(Borders::ALL).title("Amount"));
            amount_widget.render(amount_rect, buf);
        }
    }
}
