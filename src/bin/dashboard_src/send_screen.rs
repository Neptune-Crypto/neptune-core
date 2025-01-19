use std::cmp::max;
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use neptune_cash::config_models::network::Network;
use neptune_cash::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use neptune_cash::models::state::wallet::address::ReceivingAddress;
use neptune_cash::models::state::wallet::utxo_notification::UtxoNotificationMedium;
use neptune_cash::rpc_auth;
use neptune_cash::rpc_server::RPCClient;
use num_traits::Zero;
use ratatui::layout::Alignment;
use ratatui::layout::Margin;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::text::Text;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Widget;
use ratatui::widgets::Wrap;
use tarpc::context;
use tokio::sync::Mutex;

use super::dashboard_app::ConsoleIO;
use super::dashboard_app::DashboardEvent;
use super::overview_screen::VerticalRectifier;
use super::screen::Screen;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendScreenWidget {
    Address,
    Amount,
    Ok,
    Notice,
}

#[derive(Default, Debug, Clone)]
enum ResetType {
    #[default]
    None,
    Form,
    Notice,
}

#[derive(Debug, Clone)]
pub struct SendScreen {
    active: bool,
    fg: Color,
    bg: Color,
    in_focus: bool,
    address: String,
    rpc_client: Arc<RPCClient>,
    focus: Arc<Mutex<SendScreenWidget>>,
    amount: String,
    notice: Arc<Mutex<String>>,
    reset_me: Arc<Mutex<ResetType>>,
    escalatable_event: Arc<std::sync::Mutex<Option<DashboardEvent>>>,
    network: Network,
    token: rpc_auth::Token,
}

impl SendScreen {
    pub fn new(rpc_server: Arc<RPCClient>, network: Network, token: rpc_auth::Token) -> Self {
        SendScreen {
            active: false,
            fg: Color::Gray,
            bg: Color::Black,
            in_focus: false,
            address: "".to_string(),
            rpc_client: rpc_server,
            focus: Arc::new(Mutex::new(SendScreenWidget::Address)),
            amount: "".to_string(),
            notice: Arc::new(Mutex::new("".to_string())),
            reset_me: Arc::new(Mutex::new(Default::default())),
            escalatable_event: Arc::new(std::sync::Mutex::new(None)),
            network,
            token,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn check_and_pay_sequence(
        rpc_client: Arc<RPCClient>,
        token: rpc_auth::Token,
        address: String,
        amount: String,
        notice_arc: Arc<Mutex<String>>,
        reset_me: Arc<Mutex<ResetType>>,
        network: Network,
        refresh_tx: tokio::sync::mpsc::Sender<()>,
    ) {
        //        *focus_arc.lock().await = SendScreenWidget::Notice;

        *notice_arc.lock().await = "sending ...".to_string();
        refresh_tx.send(()).await.unwrap();

        // TODO: Let user specify this number
        let fee = NeptuneCoins::zero();

        let valid_amount = match NeptuneCoins::from_str(&amount) {
            Ok(a) => a,
            Err(e) => {
                *notice_arc.lock().await = format!("amount: {}", e);
                *reset_me.lock().await = ResetType::Notice;
                refresh_tx.send(()).await.unwrap();
                return;
            }
        };

        let valid_address = match ReceivingAddress::from_bech32m(&address, network) {
            Ok(a) => a,
            Err(e) => {
                *notice_arc.lock().await = format!("address: {}", e);
                *reset_me.lock().await = ResetType::Notice;
                refresh_tx.send(()).await.unwrap();
                return;
            }
        };

        // Allow the generation of proves to take some time...
        let mut send_ctx = context::current();
        const SEND_DEADLINE_IN_SECONDS: u64 = 40;
        send_ctx.deadline = SystemTime::now() + Duration::from_secs(SEND_DEADLINE_IN_SECONDS);
        let send_result = rpc_client
            .send(
                send_ctx,
                token,
                valid_amount,
                valid_address,
                UtxoNotificationMedium::OnChain,
                UtxoNotificationMedium::OnChain,
                fee,
            )
            .await
            .unwrap();

        match send_result {
            Ok(_) => {
                *notice_arc.lock().await = "Payment broadcast".to_string();
                *reset_me.lock().await = ResetType::Form;
            }
            Err(e) => {
                *notice_arc.lock().await = format!("send error.  {e}");
                *reset_me.lock().await = ResetType::Notice;
            }
        }
        refresh_tx.send(()).await.unwrap();
    }

    pub fn handle(
        &mut self,
        event: DashboardEvent,
        refresh_tx: tokio::sync::mpsc::Sender<()>,
    ) -> Result<Option<DashboardEvent>, Box<dyn Error>> {
        let mut escalate_event = None;
        if let Ok(mut reset_me_mutex_guard) = self.reset_me.try_lock() {
            match *reset_me_mutex_guard {
                ResetType::Form => {
                    self.amount = "".to_string();
                    self.address = "".to_string();
                    if let Ok(mut n) = self.notice.try_lock() {
                        *n = "".to_string();
                    }
                }
                ResetType::Notice => {
                    if let Ok(mut n) = self.notice.try_lock() {
                        *n = "".to_string();
                    }
                }
                _ => {}
            }
            *reset_me_mutex_guard = ResetType::None;
        }
        if self.in_focus {
            match event {
                DashboardEvent::ConsoleEvent(Event::Key(key))
                    if key.kind == KeyEventKind::Press =>
                {
                    match key.code {
                        KeyCode::Enter => {
                            if let Ok(mut own_focus) = self.focus.try_lock() {
                                match own_focus.to_owned() {
                                    SendScreenWidget::Address => {
                                        return Ok(Some(DashboardEvent::ConsoleMode(
                                            ConsoleIO::InputRequested(
                                                "Please enter recipient address:\n".to_string(),
                                            ),
                                        )));
                                    }
                                    SendScreenWidget::Amount => {
                                        *own_focus = SendScreenWidget::Ok;
                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    SendScreenWidget::Ok => {
                                        // clone outside of async section
                                        let rpc_client = self.rpc_client.clone();
                                        let address = self.address.clone();
                                        let amount = self.amount.clone();
                                        let notice = self.notice.clone();
                                        let reset_me = self.reset_me.clone();
                                        let network = self.network;
                                        let token = self.token;

                                        tokio::spawn(Self::check_and_pay_sequence(
                                            rpc_client, token, address, amount, notice, reset_me,
                                            network, refresh_tx,
                                        ));
                                        //                                        escalate_event = Some(DashboardEvent::RefreshScreen);
                                    }
                                    _ => {
                                        escalate_event = None;
                                    }
                                }
                            }
                        }
                        KeyCode::Up => {
                            if let Ok(mut own_focus) = self.focus.try_lock() {
                                *own_focus = match own_focus.to_owned() {
                                    SendScreenWidget::Address => SendScreenWidget::Ok,
                                    SendScreenWidget::Amount => SendScreenWidget::Address,
                                    SendScreenWidget::Ok => SendScreenWidget::Amount,
                                    SendScreenWidget::Notice => SendScreenWidget::Notice,
                                };
                                escalate_event = Some(DashboardEvent::RefreshScreen);
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        KeyCode::Down => {
                            if let Ok(mut own_focus) = self.focus.try_lock() {
                                *own_focus = match own_focus.to_owned() {
                                    SendScreenWidget::Address => SendScreenWidget::Amount,
                                    SendScreenWidget::Amount => SendScreenWidget::Ok,
                                    SendScreenWidget::Ok => SendScreenWidget::Address,
                                    SendScreenWidget::Notice => SendScreenWidget::Notice,
                                };
                                escalate_event = Some(DashboardEvent::RefreshScreen);
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        KeyCode::Char(c) => {
                            if let Ok(own_focus) = self.focus.try_lock() {
                                if own_focus.to_owned() == SendScreenWidget::Amount {
                                    self.amount = format!("{}{}", self.amount, c);
                                    escalate_event = Some(DashboardEvent::RefreshScreen);
                                } else {
                                    escalate_event = Some(event);
                                }
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        KeyCode::Backspace => {
                            if let Ok(own_focus) = self.focus.try_lock() {
                                if own_focus.to_owned() == SendScreenWidget::Amount {
                                    if !self.amount.is_empty() {
                                        self.amount.drain(self.amount.len() - 1..);
                                    }
                                    escalate_event = Some(DashboardEvent::RefreshScreen);
                                }
                            } else {
                                escalate_event = Some(event);
                            }
                        }
                        _ => {
                            escalate_event = Some(event);
                        }
                    }
                }
                DashboardEvent::ConsoleMode(ConsoleIO::InputSupplied(string)) => {
                    if let Ok(mut own_focus) = self.focus.try_lock() {
                        string.trim().clone_into(&mut self.address);
                        *own_focus = SendScreenWidget::Amount;
                        escalate_event = Some(DashboardEvent::RefreshScreen);
                    } else {
                        escalate_event = Some(DashboardEvent::ConsoleMode(
                            ConsoleIO::InputSupplied(string),
                        ));
                    }
                }
                _ => {
                    escalate_event = None;
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

    fn escalatable_event(&self) -> Arc<std::sync::Mutex<Option<DashboardEvent>>> {
        self.escalatable_event.clone()
    }
}

impl Widget for SendScreen {
    fn render(self, area: ratatui::layout::Rect, buf: &mut ratatui::buffer::Buffer) {
        let own_focus = if let Ok(of) = self.focus.try_lock() {
            of.to_owned()
        } else {
            SendScreenWidget::Notice
        };
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
        let inner = area.inner(Margin {
            vertical: 1,
            horizontal: 1,
        });
        let width = max(0, inner.width as isize - 2) as usize;
        if width > 0 {
            let mut vrecter = VerticalRectifier::new(inner);

            // display address widget
            let mut address = self.address.clone();
            let mut address_lines = vec![];

            // TODO: Not sure how to handle this linting problem, as clippy suggestion doesn't work.
            #[allow(clippy::assigning_clones)]
            while address.len() > width {
                let (line, remainder) = address.split_at(width);
                address_lines.push(line.to_owned());
                address = remainder.to_owned();
            }
            address_lines.push(address);

            let address_rect = vrecter.next((address_lines.len() + 2).try_into().unwrap());
            if address_rect.height > 0 {
                let address_display = Paragraph::new(Text::from(address_lines.join("\n")))
                    .style(if own_focus == SendScreenWidget::Address && self.in_focus {
                        focus_style
                    } else {
                        style
                    })
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
                let instructions = if self.in_focus && own_focus == SendScreenWidget::Address {
                    Line::from(vec![
                        Span::from("Press "),
                        Span::styled("Enter ↵", Style::default().fg(Color::LightCyan)),
                        Span::from(" to enter address via console mode."),
                    ])
                } else {
                    Line::from(vec![])
                };
                let instructions_widget = Paragraph::new(instructions).style(style);
                instructions_widget.render(instruction_rect, buf);
            }

            // display amount widget
            let amount = self.amount;
            let amount_rect = vrecter.next(3);
            let amount_widget = Paragraph::new(Line::from(vec![
                Span::from(amount),
                if own_focus == SendScreenWidget::Amount {
                    Span::styled(
                        "|",
                        if self.in_focus {
                            Style::default().add_modifier(Modifier::RAPID_BLINK)
                        } else {
                            style
                        },
                    )
                } else {
                    Span::from(" ")
                },
            ]))
            .style(if own_focus == SendScreenWidget::Amount && self.in_focus {
                focus_style
            } else {
                style
            })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Amount")
                    .style(if own_focus == SendScreenWidget::Amount && self.in_focus {
                        focus_style
                    } else {
                        style
                    }),
            );
            amount_widget.render(amount_rect, buf);

            // send button
            let mut button_rect = vrecter.next(3);
            button_rect.width = 8;
            let button_widget = Paragraph::new(Span::styled(
                " SEND ",
                if own_focus == SendScreenWidget::Ok && self.in_focus {
                    focus_style
                } else {
                    style
                },
            ))
            .block(Block::default().borders(Borders::ALL).style(
                if own_focus == SendScreenWidget::Ok && self.in_focus {
                    focus_style
                } else {
                    style
                },
            ));
            button_widget.render(button_rect, buf);

            // notice
            if let Ok(notice_text) = self.notice.try_lock() {
                vrecter.next(1);
                let notice_rect = vrecter.next(10);
                let notice_widget = Paragraph::new(notice_text.as_str()).wrap(Wrap { trim: true });
                notice_widget.render(notice_rect, buf);
            }
        }
    }
}
