use core::fmt;
use std::cell::RefCell;
use std::cell::RefMut;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::io::Stdout;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event;
use crossterm::event::DisableMouseCapture;
use crossterm::event::EnableMouseCapture;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use crossterm::execute;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::enable_raw_mode;
use crossterm::terminal::EnterAlternateScreen;
use crossterm::terminal::LeaveAlternateScreen;
use neptune_cash::config_models::network::Network;
use neptune_cash::rpc_auth;
use neptune_cash::rpc_server::RPCClient;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::style::Color;
use ratatui::style::Modifier;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::text::Text;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::List;
use ratatui::widgets::ListItem;
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use ratatui::Terminal;
use strum::EnumCount;
use strum::EnumIter;
use strum::IntoEnumIterator;
use tokio::sync::Mutex;
use tokio::time::sleep;

use super::address_screen::AddressScreen;
use super::history_screen::HistoryScreen;
use super::mempool_screen::MempoolScreen;
use super::overview_screen::OverviewScreen;
use super::peers_screen::PeersScreen;
use super::receive_screen::ReceiveScreen;
use super::screen::Screen;
use super::send_screen::SendScreen;

#[derive(Debug, Clone, Copy, EnumIter, PartialEq, Eq, EnumCount, Hash)]
enum MenuItem {
    Overview,
    Peers,
    History,
    Receive,
    Send,
    Address,
    Mempool,
    Quit,
}

impl MenuItem {
    pub fn next(&self) -> Self {
        MenuItem::from((usize::from(*self) + 1) % MenuItem::COUNT)
    }
    pub fn previous(&self) -> Self {
        MenuItem::from((usize::from(*self) + MenuItem::COUNT - 1) % MenuItem::COUNT)
    }
}

impl From<MenuItem> for usize {
    fn from(mi: MenuItem) -> Self {
        match mi {
            MenuItem::Overview => 0,
            MenuItem::Peers => 1,
            MenuItem::History => 2,
            MenuItem::Receive => 3,
            MenuItem::Send => 4,
            MenuItem::Address => 5,
            MenuItem::Mempool => 6,
            MenuItem::Quit => 7,
        }
    }
}

impl From<usize> for MenuItem {
    fn from(u: usize) -> Self {
        for mi in MenuItem::iter() {
            if mi as usize == u {
                return mi;
            }
        }
        panic!("Should not get here.");
    }
}

impl fmt::Display for MenuItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MenuItem::Overview => write!(f, "Overview"),
            MenuItem::Peers => write!(f, "Peers"),
            MenuItem::History => write!(f, "History"),
            MenuItem::Receive => write!(f, "Receive"),
            MenuItem::Send => write!(f, "Send"),
            MenuItem::Address => write!(f, "Addresses"),
            MenuItem::Mempool => write!(f, "Mempool"),
            MenuItem::Quit => write!(f, "Quit"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConsoleIO {
    Output(String),
    InputRequested(String),
    InputSupplied(String),
}

/// Events that widgets can pass to/from each other
#[derive(Debug, Clone)]
pub enum DashboardEvent {
    RefreshScreen,
    ConsoleEvent(Event),
    ConsoleMode(ConsoleIO),
    Shutdown(String),
}

/// App holds the state of the application
pub struct DashboardApp {
    running: bool,
    current_menu_item: MenuItem,
    menu_in_focus: bool,
    overview_screen: Rc<RefCell<OverviewScreen>>,
    peers_screen: Rc<RefCell<PeersScreen>>,
    address_screen: Rc<RefCell<AddressScreen>>,
    history_screen: Rc<RefCell<HistoryScreen>>,
    receive_screen: Rc<RefCell<ReceiveScreen>>,
    send_screen: Rc<RefCell<SendScreen>>,
    mempool_screen: Rc<RefCell<MempoolScreen>>,
    screens: HashMap<MenuItem, Rc<RefCell<dyn Screen>>>,
    output: String,
    console_io: Arc<Mutex<Vec<ConsoleIO>>>,
    network: Network,
}

impl DashboardApp {
    pub fn new(
        rpc_server: Arc<RPCClient>,
        network: Network,
        token: rpc_auth::Token,
        listen_addr_for_peers: Option<SocketAddr>,
    ) -> Self {
        let mut screens = HashMap::<MenuItem, Rc<RefCell<dyn Screen>>>::new();

        let overview_screen = Rc::new(RefCell::new(OverviewScreen::new(
            rpc_server.clone(),
            network,
            token,
            listen_addr_for_peers,
        )));
        let overview_screen_dyn = Rc::clone(&overview_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Overview, Rc::clone(&overview_screen_dyn));

        let peers_screen = Rc::new(RefCell::new(PeersScreen::new(rpc_server.clone(), token)));
        let peers_screen_dyn = Rc::clone(&peers_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Peers, Rc::clone(&peers_screen_dyn));

        let history_screen = Rc::new(RefCell::new(HistoryScreen::new(rpc_server.clone(), token)));
        let history_screen_dyn = Rc::clone(&history_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::History, Rc::clone(&history_screen_dyn));

        let receive_screen = Rc::new(RefCell::new(ReceiveScreen::new(
            rpc_server.clone(),
            network,
            token,
        )));
        let receive_screen_dyn = Rc::clone(&receive_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Receive, Rc::clone(&receive_screen_dyn));

        let send_screen = Rc::new(RefCell::new(SendScreen::new(
            rpc_server.clone(),
            network,
            token,
        )));
        let send_screen_dyn = Rc::clone(&send_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Send, Rc::clone(&send_screen_dyn));

        let address_screen = Rc::new(RefCell::new(AddressScreen::new(
            rpc_server.clone(),
            network,
            token,
        )));
        let address_screen_dyn = Rc::clone(&address_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Address, Rc::clone(&address_screen_dyn));

        let mempool_screen = Rc::new(RefCell::new(MempoolScreen::new(rpc_server.clone(), token)));
        let mempool_screen_dyn = Rc::clone(&mempool_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Mempool, Rc::clone(&mempool_screen_dyn));

        Self {
            running: false,
            current_menu_item: MenuItem::Overview,
            menu_in_focus: true,
            overview_screen,
            peers_screen,
            history_screen,
            receive_screen,
            send_screen,
            address_screen,
            mempool_screen,
            screens,
            output: "".to_string(),
            console_io: Arc::new(Mutex::new(vec![])),
            network,
        }
    }

    pub fn start(&mut self) {
        self.running = true;
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn enable_raw_mode() -> Result<Terminal<CrosstermBackend<Stdout>>, Box<dyn Error>> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;
        Ok(terminal)
    }

    pub fn disable_raw_mode(
        mut terminal: Terminal<CrosstermBackend<Stdout>>,
    ) -> Result<(), Box<dyn Error>> {
        // restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        Ok(())
    }

    pub fn current_screen(&mut self) -> RefMut<dyn Screen> {
        self.screens
            .get(&self.current_menu_item)
            .unwrap()
            .as_ref()
            .borrow_mut()
    }

    pub fn have_current_screen(&mut self) -> bool {
        self.screens.contains_key(&self.current_menu_item)
    }

    pub async fn run(
        client: RPCClient,
        network: Network,
        token: rpc_auth::Token,
        listen_addr_for_peers: Option<SocketAddr>,
    ) -> Result<String, Box<dyn Error>> {
        // create app
        let mut app = DashboardApp::new(Arc::new(client), network, token, listen_addr_for_peers);
        let (refresh_tx, mut refresh_rx) = tokio::sync::mpsc::channel::<()>(2);

        // setup terminal
        let mut terminal = Self::enable_raw_mode()?;

        app.start();
        if app.have_current_screen() {
            app.current_screen().activate();
        }

        // initial draw.
        terminal.draw(|f| app.render(f))?;

        let mut continue_running = true;
        while continue_running {
            let mut console_input = None;
            {
                let mut draw = false;
                let mut console_queue = app.console_io.lock().await;
                if !console_queue.is_empty() {
                    match console_queue.first().unwrap() {
                        ConsoleIO::Output(string) => {
                            Self::disable_raw_mode(terminal)?;

                            sleep(Duration::from_millis(200)).await;
                            println!("{}", string);
                            let mut str = "".to_string();
                            io::stdin().read_line(&mut str)?;

                            terminal = Self::enable_raw_mode()?;
                            draw = true;
                        }
                        ConsoleIO::InputRequested(string) => {
                            Self::disable_raw_mode(terminal)?;

                            sleep(Duration::from_millis(200)).await;
                            println!("{}", string);
                            let mut str = "".to_string();
                            io::stdin().read_line(&mut str)?;
                            console_input = Some(str);

                            terminal = Self::enable_raw_mode()?;
                            draw = true;
                        }
                        _ => {
                            panic!("Should not get here.");
                        }
                    }
                    console_queue.remove(0);
                }
                drop(console_queue);
                if draw {
                    terminal.draw(|f| app.render(f))?;
                }
            }

            if let Some(string) = console_input {
                app.handle(
                    &mut terminal,
                    DashboardEvent::ConsoleMode(ConsoleIO::InputSupplied(string)),
                    refresh_tx.clone(),
                )
                .await?;
            }

            if refresh_rx.try_recv().is_ok() {
                terminal.draw(|f| app.render(f))?;
            }

            // note: setting a low duration like 100 can cause high CPU usage
            if event::poll(Duration::from_millis(200))? {
                if let Ok(event) = event::read() {
                    app.handle(
                        &mut terminal,
                        DashboardEvent::ConsoleEvent(event),
                        refresh_tx.clone(),
                    )
                    .await?;
                    terminal.draw(|f| app.render(f))?;
                }
            }

            // handle events triggered downstream and escalated here (if any)
            if app.have_current_screen() {
                let maybe_event_arc = app.current_screen().escalatable_event();
                if maybe_event_arc.lock().unwrap().is_some() {
                    let event = maybe_event_arc.lock().unwrap().clone().unwrap();
                    app.handle(&mut terminal, event, refresh_tx.clone()).await?;

                    // mark handled
                    *maybe_event_arc.lock().unwrap() = None;
                };
            }

            continue_running = app.is_running();
        }
        app.stop();

        // clean up terminal
        Self::disable_raw_mode(terminal)?;

        Ok(app.output.to_string())
    }

    async fn handle(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        event: DashboardEvent,
        refresh_tx: tokio::sync::mpsc::Sender<()>,
    ) -> Result<Option<Event>, Box<dyn Error>> {
        if let DashboardEvent::RefreshScreen = event {
            terminal.draw(|f| self.render(f))?;
        } else if let DashboardEvent::Shutdown(error_message) = event {
            self.stop();
            self.output = error_message + "\n";
        } else if self.menu_in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if self.current_menu_item != MenuItem::Quit {
                                self.current_menu_item = MenuItem::Quit;
                            } else {
                                self.running = false;
                            }
                        }
                        KeyCode::Enter => {
                            if self.current_menu_item == MenuItem::Quit {
                                self.running = false;
                            } else {
                                self.menu_in_focus = false;
                                if self.have_current_screen() {
                                    self.current_screen().focus();
                                }
                            }
                        }
                        KeyCode::Up => {
                            if self.have_current_screen() {
                                self.current_screen().deactivate();
                            }
                            self.current_menu_item = self.current_menu_item.previous();
                            if self.have_current_screen() {
                                self.current_screen().activate();
                            }
                        }
                        KeyCode::Down => {
                            if self.have_current_screen() {
                                self.current_screen().deactivate();
                            }
                            self.current_menu_item = self.current_menu_item.next();
                            if self.have_current_screen() {
                                self.current_screen().activate();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        // menu not in focus
        else {
            // delegate
            let escalated: Option<DashboardEvent> = match self.current_menu_item {
                // MenuItem::Overview => todo!(),
                // MenuItem::Peers => todo!(),
                MenuItem::Address => {
                    let mut address_screen = self.address_screen.as_ref().borrow_mut();
                    address_screen.handle(event)?
                }
                MenuItem::History => {
                    let mut history_screen = self.history_screen.as_ref().borrow_mut();
                    history_screen.handle(event)?
                }
                MenuItem::Peers => {
                    let mut peers_screen = self.peers_screen.as_ref().borrow_mut();
                    peers_screen.handle(event)?
                }
                MenuItem::Receive => {
                    let mut receive_screen = self.receive_screen.as_ref().borrow_mut();
                    receive_screen.handle(event)?
                }
                MenuItem::Send => {
                    let mut send_screen = self.send_screen.as_ref().borrow_mut();
                    send_screen.handle(event, refresh_tx)?
                }
                // MenuItem::Quit => todo!(),
                _ => Some(event),
            };

            match escalated {
                Some(DashboardEvent::RefreshScreen) => {
                    terminal.draw(|f| self.render(f))?;
                }
                Some(DashboardEvent::ConsoleEvent(Event::Key(key)))
                    if key.kind == KeyEventKind::Press =>
                {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if self.have_current_screen() {
                                self.current_screen().unfocus();
                            }
                            self.menu_in_focus = true;
                        }
                        _ => {}
                    }
                }
                Some(DashboardEvent::ConsoleEvent(_non_key_event)) => {}
                Some(DashboardEvent::ConsoleMode(console_io)) => {
                    let mut console_io_mut = self.console_io.lock().await;
                    console_io_mut.push(console_io);
                }
                _ => {
                    // unknown event
                }
            }
        }
        Ok(None)
    }

    fn render(&mut self, f: &mut Frame) {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(f.area());
        let header_chunk = main_chunks[0];
        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints([Constraint::Length(20), Constraint::Min(0)].as_ref())
            .split(main_chunks[1]);
        let menu_chunk = body_chunks[0];
        let screen_chunk = body_chunks[1];

        // render title
        let network = self.network;
        let title = format!("♆ neptune-dashboard — {network}");
        let title = Line::from(title);
        let title_style = Style::default()
            .add_modifier(Modifier::BOLD)
            .bg(Color::Black)
            .fg(Color::Cyan);
        let title_widget = Paragraph::new(Text::from(title)).style(title_style);
        f.render_widget(title_widget, header_chunk);

        // render menu
        let default_style = Style::default().bg(Color::Black).fg(Color::Gray);
        let focus_style = default_style.fg(Color::LightCyan);
        let selection_style = Style::default().fg(Color::Black).bg(Color::Gray);
        let focus_selection_style = selection_style.bg(Color::LightCyan);

        let menu_styles: Vec<_> = MenuItem::iter()
            .map(|i| {
                if i == self.current_menu_item && self.menu_in_focus {
                    focus_selection_style
                } else if i == self.current_menu_item {
                    selection_style
                } else if self.menu_in_focus {
                    focus_style
                } else {
                    default_style
                }
            })
            .collect();
        let menu_items: Vec<ListItem> = MenuItem::iter()
            .zip(menu_styles.iter())
            .map(|(i, s)| ListItem::new(i.to_string()).style(*s))
            .collect();
        let menu = List::new(menu_items)
            .style(match self.menu_in_focus {
                true => focus_style,
                false => default_style,
            })
            .block(Block::default().borders(Borders::ALL).title("Menu"));
        f.render_widget(menu, menu_chunk);

        // render menu screen
        match self.current_menu_item {
            MenuItem::Overview => {
                f.render_widget::<OverviewScreen>(
                    self.overview_screen.borrow().to_owned(),
                    screen_chunk,
                );
            }
            MenuItem::Peers => {
                f.render_widget::<PeersScreen>(self.peers_screen.borrow().to_owned(), screen_chunk);
            }
            MenuItem::Address => {
                f.render_widget::<AddressScreen>(
                    self.address_screen.borrow().to_owned(),
                    screen_chunk,
                );
            }
            MenuItem::History => {
                f.render_widget::<HistoryScreen>(
                    self.history_screen.borrow().to_owned(),
                    screen_chunk,
                );
            }
            MenuItem::Receive => {
                f.render_widget::<ReceiveScreen>(
                    self.receive_screen.borrow().to_owned(),
                    screen_chunk,
                );
            }
            MenuItem::Send => {
                f.render_widget::<SendScreen>(self.send_screen.borrow().to_owned(), screen_chunk);
            }
            MenuItem::Mempool => {
                f.render_widget::<MempoolScreen>(
                    self.mempool_screen.borrow().to_owned(),
                    screen_chunk,
                );
            }
            // MenuItem::Quit => todo!(),
            _ => {
                let messages: Vec<ListItem> = [
                    ListItem::new(Line::from(Span::raw("Press enter, `q`, or Esc to quit."))),
                    ListItem::new(Line::from(Span::raw("🌊"))),
                ]
                .to_vec();
                let messages = List::new(messages)
                    .style(match self.menu_in_focus {
                        true => default_style,
                        false => focus_style,
                    })
                    .block(Block::default().borders(Borders::ALL).title("Quit"));

                f.render_widget(messages, screen_chunk);
            }
        };
    }
}
