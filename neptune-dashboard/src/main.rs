
mod address_screen;
mod dashboard_app;
mod history_screen;
mod mempool_screen;
mod overview_screen;
mod peers_screen;
mod receive_screen;
mod screen;
mod send_screen;

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;

use clap::Parser;
use crossterm::event::DisableMouseCapture;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::LeaveAlternateScreen;
use neptune_cash::config_models::data_directory::DataDirectory;
use neptune_cash::rpc_auth;
use neptune_cash::rpc_server::error::RpcError;
use neptune_cash::rpc_server::RPCClient;
use tarpc::client;
use tarpc::context;
use tarpc::tokio_serde::formats::Json;



#[derive(Debug, Parser, Clone)]
#[clap(name = "neptune-dashboard", about = "Terminal user interface")]
pub struct Config {
    /// Sets the neptune-core rpc server localhost port to connect to.
    #[clap(short, long, default_value = "9799", value_name = "port")]
    port: u16,

    /// neptune-core data directory containing wallet and blockchain state
    #[clap(long)]
    data_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    // we set this panic hook so we can drop out of raw mode in order to
    // display the panic message.  else there is wicked screen corruption.
    set_panic_hook();

    // Create connection to RPC server
    let args: Config = Config::parse();
    let server_socket = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let transport = tarpc::serde_transport::tcp::connect(server_socket, Json::default).await;
    let transport = match transport {
        Ok(transp) => transp,
        Err(err) => {
            eprintln!("{err}");
            eprintln!(
                "Connection to neptune-core failed. Is a node running? Or is it still starting up?"
            );
            process::exit(1);
        }
    };
    let client = RPCClient::new(client::Config::default(), transport).spawn();

    // Read what network the client is running and ensure that client is up and running
    let rpc_auth::CookieHint {
        data_directory,
        network,
    } = match get_cookie_hint(&client, &args).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            eprintln!(
                "Could not ping neptune-core. Do configurations match? Or is it still starting up?"
            );
            process::exit(1);
        }
    };

    let token: rpc_auth::Token = match rpc_auth::Cookie::try_load(&data_directory).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Unable to load RPC auth cookie. error = {}", e);
            process::exit(2)
        }
    }
    .into();

    let listen_addr_for_peers = match client
        .own_listen_address_for_peers(context::current(), token)
        .await
    {
        Ok(Ok(la)) => la,
        Ok(Err(err)) => {
            eprintln!("Could not get listen address from client. error = {err}");
            process::exit(1);
        }
        Err(err) => {
            eprintln!("Could not get listen address from client. error = {err}");
            process::exit(1);
        }
    };

    // run app until quit
    let res = crate::dashboard_app::DashboardApp::run(client, network, token, listen_addr_for_peers).await;

    restore_text_mode(); // just in case.

    match res {
        Err(err) => {
            eprintln!("{:?}", err);
            process::exit(1);
        }
        Ok(output) => {
            print!("{}", output);
        }
    }
}

// returns result with a CookieHint{ data_directory, network }.
//
// We use the data-dir provided by user if present.
//
// Otherwise, we call cookie_hint() RPC to obtain data-dir.
// But the API might be disabled, which we detect and fallback to the default data-dir.
async fn get_cookie_hint(
    client: &RPCClient,
    args: &Config,
) -> anyhow::Result<rpc_auth::CookieHint> {
    async fn fallback(client: &RPCClient, args: &Config) -> anyhow::Result<rpc_auth::CookieHint> {
        let network = client.network(context::current()).await??;
        let data_directory = DataDirectory::get(args.data_dir.clone(), network)?;
        Ok(rpc_auth::CookieHint {
            data_directory,
            network,
        })
    }

    if args.data_dir.is_some() {
        return fallback(client, args).await;
    }

    let result = client.cookie_hint(context::current()).await?;

    match result {
        Ok(hint) => Ok(hint),
        Err(RpcError::CookieHintDisabled) => fallback(client, args).await,
        Err(e) => Err(e.into()),
    }
}

fn set_panic_hook() {
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // get out of raw mode, and back to a happy text-mode state of affairs.
        restore_text_mode();

        previous_hook(info);
    }));
}

fn restore_text_mode() {
    // restore terminal
    disable_raw_mode().unwrap();
    crossterm::execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture).unwrap();
}
