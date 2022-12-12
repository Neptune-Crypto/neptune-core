use core::fmt;
use crossterm::event::{self, Event, KeyCode};
use std::{cell::RefCell, collections::HashMap, error::Error, io::Stdout, rc::Rc};
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::{EnumCount, EnumIter};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};

use super::{overview_screen::OverviewScreen, screen::Screen};

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

/// App holds the state of the application
pub struct DashboardApp {
    running: bool,
    current_menu_item: MenuItem,
    menu_in_focus: bool,
    overview_screen: Rc<RefCell<OverviewScreen>>,
    screens: HashMap<MenuItem, Rc<RefCell<dyn Screen>>>,
}

impl DashboardApp {
    pub fn new() -> Self {
        let overview_screen = Rc::new(RefCell::new(OverviewScreen::new()));
        let overview_screen_dyn = Rc::clone(&overview_screen) as Rc<RefCell<dyn Screen>>;
        let mut screens = HashMap::<MenuItem, Rc<RefCell<dyn Screen>>>::new();
        screens.insert(MenuItem::Overview, Rc::clone(&overview_screen_dyn));
        Self {
            running: false,
            current_menu_item: MenuItem::Overview,
            menu_in_focus: true,
            overview_screen,
            screens,
        }
    }

    pub fn run(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    ) -> Result<(), Box<dyn Error>> {
        self.running = true;

        while self.running {
            terminal.draw(|f| self.render(f))?;

            if let Ok(event) = event::read() {
                self.handle(event)?;
            }
        }
        Ok(())
    }

    fn handle(&mut self, event: Event) -> Result<Option<Event>, Box<dyn Error>> {
        if self.menu_in_focus {
            if let Event::Key(key) = event {
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
                            if let Some(screen) = self.screens.get(&self.current_menu_item) {
                                screen.borrow_mut().focus();
                            }
                        }
                    }
                    KeyCode::Up => {
                        if let Some(screen) = self.screens.get(&self.current_menu_item) {
                            screen.borrow_mut().deactivate();
                        }
                        self.current_menu_item = self.current_menu_item.previous();
                        if let Some(screen) = self.screens.get(&self.current_menu_item) {
                            screen.borrow_mut().activate();
                        }
                    }
                    KeyCode::Down => {
                        if let Some(screen) = self.screens.get(&self.current_menu_item) {
                            screen.borrow_mut().deactivate();
                        }
                        self.current_menu_item = self.current_menu_item.next();
                        if let Some(screen) = self.screens.get(&self.current_menu_item) {
                            screen.borrow_mut().activate();
                        }
                    }
                    _ => {}
                }
            }
        }
        // menu not in focus
        else {
            // delegate
            let escalated: Option<Event> = match self.current_menu_item {
                // MenuItem::Overview => todo!(),
                // MenuItem::Peers => todo!(),
                // MenuItem::History => todo!(),
                // MenuItem::Receive => todo!(),
                // MenuItem::Send => todo!(),
                // MenuItem::Quit => todo!(),
                _ => Some(event),
            };
            // handle if escalated
            if let Some(event) = escalated {
                if let Event::Key(key) = event {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            self.menu_in_focus = true;
                            if let Some(screen) = self.screens.get(&self.current_menu_item) {
                                screen.borrow_mut().unfocus();
                            }
                        }
                        _ => {}
                    }
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
        let default_style = Style::default().bg(Color::Black).fg(Color::White);
        let focus_style = default_style.fg(Color::LightCyan);
        let selection_style = Style::default().fg(Color::Black).bg(Color::White);
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
            // MenuItem::Peers => todo!(),
            // MenuItem::History => todo!(),
            // MenuItem::Receive => todo!(),
            // MenuItem::Send => todo!(),
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

impl Default for DashboardApp {
    fn default() -> Self {
        Self::new()
    }
}
