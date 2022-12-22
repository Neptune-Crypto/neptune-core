use core::fmt;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use neptune_core::rpc_server::RPCClient;
use std::{
    cell::{RefCell, RefMut},
    collections::HashMap,
    error::Error,
    io::{self, Stdout},
    rc::Rc,
    sync::Arc,
    time::Duration,
};
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};
use tokio::{sync::Mutex, time::sleep};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};

use super::{
    history_screen::HistoryScreen, overview_screen::OverviewScreen, peers_screen::PeersScreen,
    receive_screen::ReceiveScreen, screen::Screen, send_screen::SendScreen,
};

#[derive(Debug, Clone, Copy, EnumIter, PartialEq, Eq, EnumCount, Hash)]
enum MenuItem {
    Overview,
    Peers,
    History,
    Receive,
    Send,
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
            MenuItem::Quit => 5,
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
            MenuItem::Quit => write!(f, "Quit"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConsoleIO {
    Output(String),
    Input(String),
}

/// Events that widgets can pass to/from each other
#[derive(Debug, Clone)]
pub enum DashboardEvent {
    ConsoleEvent(Event),
    Output(String),
}

/// App holds the state of the application
pub struct DashboardApp {
    running: bool,
    current_menu_item: MenuItem,
    menu_in_focus: bool,
    overview_screen: Rc<RefCell<OverviewScreen>>,
    peers_screen: Rc<RefCell<PeersScreen>>,
    history_screen: Rc<RefCell<HistoryScreen>>,
    receive_screen: Rc<RefCell<ReceiveScreen>>,
    send_screen: Rc<RefCell<SendScreen>>,
    screens: HashMap<MenuItem, Rc<RefCell<dyn Screen>>>,
    output: String,
    console_io: Arc<Mutex<Vec<ConsoleIO>>>,
}

impl DashboardApp {
    pub fn new(rpc_server: Arc<RPCClient>) -> Self {
        let mut screens = HashMap::<MenuItem, Rc<RefCell<dyn Screen>>>::new();

        let overview_screen = Rc::new(RefCell::new(OverviewScreen::new(rpc_server.clone())));
        let overview_screen_dyn = Rc::clone(&overview_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Overview, Rc::clone(&overview_screen_dyn));

        let peers_screen = Rc::new(RefCell::new(PeersScreen::new(rpc_server.clone())));
        let peers_screen_dyn = Rc::clone(&peers_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Peers, Rc::clone(&peers_screen_dyn));

        let history_screen = Rc::new(RefCell::new(HistoryScreen::new(rpc_server.clone())));
        let history_screen_dyn = Rc::clone(&history_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::History, Rc::clone(&history_screen_dyn));

        let receive_screen = Rc::new(RefCell::new(ReceiveScreen::new(rpc_server.clone())));
        let receive_screen_dyn = Rc::clone(&receive_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Receive, Rc::clone(&receive_screen_dyn));

        let send_screen = Rc::new(RefCell::new(SendScreen::new(rpc_server)));
        let send_screen_dyn = Rc::clone(&send_screen) as Rc<RefCell<dyn Screen>>;
        screens.insert(MenuItem::Send, Rc::clone(&send_screen_dyn));

        Self {
            running: false,
            current_menu_item: MenuItem::Overview,
            menu_in_focus: true,
            overview_screen,
            peers_screen,
            history_screen,
            receive_screen,
            send_screen,
            screens,
            output: "".to_string(),
            console_io: Arc::new(Mutex::new(vec![])),
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

    pub async fn run(client: RPCClient) -> Result<String, Box<dyn Error>> {
        // create app
        let mut app = DashboardApp::new(Arc::new(client));

        // setup terminal
        let mut terminal = Self::enable_raw_mode()?;

        app.start();
        if app.have_current_screen() {
            app.current_screen().activate();
        }

        let mut continue_running = true;
        while continue_running {
            {
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
                        }
                        ConsoleIO::Input(_string) => {}
                    }
                    console_queue.remove(0);
                }
                drop(console_queue);
            }

            terminal.draw(|f| app.render(f))?;

            if event::poll(Duration::from_millis(100))? {
                if let Ok(event) = event::read() {
                    app.handle(DashboardEvent::ConsoleEvent(event)).await?;
                }
            }

            continue_running = app.is_running();
        }
        app.stop();

        // clean up terminal
        Self::disable_raw_mode(terminal)?;

        Ok(app.output.to_string())
    }

    async fn handle(&mut self, event: DashboardEvent) -> Result<Option<Event>, Box<dyn Error>> {
        if self.menu_in_focus {
            if let DashboardEvent::ConsoleEvent(Event::Key(key)) = event {
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
        // menu not in focus
        else {
            // delegate
            let escalated: Option<DashboardEvent> = match self.current_menu_item {
                // MenuItem::Overview => todo!(),
                // MenuItem::Peers => todo!(),
                // MenuItem::History => todo!(),
                MenuItem::Receive => {
                    let mut receive_screen = self.receive_screen.as_ref().borrow_mut();
                    receive_screen.handle(event)?
                }
                MenuItem::Send => {
                    let mut send_screen = self.send_screen.as_ref().borrow_mut();
                    send_screen.handle(event)?
                }
                // MenuItem::Quit => todo!(),
                _ => Some(event),
            };

            match escalated {
                Some(DashboardEvent::ConsoleEvent(Event::Key(key))) => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if self.have_current_screen() {
                            self.current_screen().unfocus();
                        }
                        self.menu_in_focus = true;
                    }
                    _ => {}
                },
                Some(DashboardEvent::ConsoleEvent(_non_key_event)) => {}
                Some(DashboardEvent::Output(string)) => {
                    // self.disable_raw_mode().await?;
                    // println!("Receiving address:");
                    // println!("{}", string);
                    // println!();
                    // println!("Press any key to return to dashboard . . .");
                    // let mut stdin = io::stdin();
                    // let _ = stdin.read(&mut [0u8]);
                    // self.enable_raw_mode()?;
                    self.output = format!(
                        "Receiving address:\n{}\nPress ENTER ↲ to return to dashboard . . .\n",
                        string
                    );
                    let mut console_io_mut = self.console_io.lock().await;
                    console_io_mut.push(ConsoleIO::Output(self.output.clone()));
                    //self.output = format!("{}{}", self.output, string);
                }
                _ => {
                    // unknown event
                }
            }
        }
        Ok(None)
    }

    fn render<B: Backend>(&mut self, f: &mut Frame<B>) {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(0)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(f.size());
        let header_chunk = main_chunks[0];
        let body_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .margin(0)
            .constraints([Constraint::Length(20), Constraint::Min(0)].as_ref())
            .split(main_chunks[1]);
        let menu_chunk = body_chunks[0];
        let screen_chunk = body_chunks[1];

        // render title
        let title = Span::raw(" ♆ neptune-dashboard");
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
            // MenuItem::Quit => todo!(),
            _ => {
                let messages: Vec<ListItem> = [ListItem::new(Spans::from(Span::raw(
                    "-placeholder-".to_string(),
                )))]
                .to_vec();
                let messages = List::new(messages)
                    .style(match self.menu_in_focus {
                        true => default_style,
                        false => focus_style,
                    })
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title("Generic Screen"),
                    );

                f.render_widget(messages, screen_chunk);
            }
        };
    }
}
