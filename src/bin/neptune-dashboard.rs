/// A simple example demonstrating how to handle user input. This is
/// a bit out of the scope of the library as it does not provide any
/// input handling out of the box. However, it may helps some to get
/// started.
///
/// This is a very simple example:
///   * A input box always focused. Every character you type is registered
///   here
///   * Pressing Backspace erases a character
///   * Pressing Enter pushes the current input in the history of previous
///   messages
///
use anyhow::{bail, Result};
use clap::Parser;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dashboard_src::dashboard_app::DashboardApp;
use neptune_core::rpc_server::RPCClient;
use std::{
    io::{self},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tarpc::{client, context};
use tokio_serde::formats::Json;
use tui::{backend::CrosstermBackend, Terminal};

pub mod dashboard_src;

#[derive(Debug, Parser, Clone)]
#[clap(name = "neptune-dashboard", about = "Terminal user interface")]
struct Config {
    /// Sets the server address to connect to.
    #[clap(long, default_value = "9799", value_name = "PORT")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create connection to RPC server
    let args: Config = Config::parse();
    let server_socket = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let transport = tarpc::serde_transport::tcp::connect(server_socket, Json::default).await;
    let transport = match transport {
        Ok(transp) => transp,
        Err(err) => {
            eprintln!("{err}");
            bail!("Connection to neptune-core failed. Is a node running?");
        }
    };
    let client = RPCClient::new(client::Config::default(), transport).spawn();

    // Block height functions as our ping endpoint
    let ping = client.block_height(context::current()).await;
    match ping {
        Ok(_pong) => {}
        Err(err) => {
            eprintln!("{err}");
            bail!("Could not ping neptune-core. Do configurations match?");
        }
    }

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app
    let mut app = DashboardApp::new(Arc::new(client));

    // run app until quit
    let res = app.run(&mut terminal);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}
