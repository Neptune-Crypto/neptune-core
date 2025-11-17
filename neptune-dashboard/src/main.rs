mod address_screen;
mod dashboard_app;
mod dashboard_rpc_client;
mod history_screen;
mod mempool_screen;
#[cfg(feature = "mock")]
mod mock_rpc_client;
mod overview_screen;
mod peers_screen;
mod receive_screen;
mod screen;
mod scrollable_table;
mod send_screen;
mod utxos_screen;

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::process;

use clap::Parser;
use crossterm::event::DisableMouseCapture;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::LeaveAlternateScreen;
use dashboard_app::Config;
use dashboard_app::DashboardApp;
use neptune_cash::application::config::data_directory::DataDirectory;
use neptune_cash::application::rpc::auth;
use neptune_cash::application::rpc::server::error::RpcError;
use neptune_cash::application::rpc::server::RPCClient;
use tarpc::client;
use tarpc::context;
use tarpc::tokio_serde::formats::Json;

use crate::dashboard_rpc_client::DashboardRpcClient;

#[tokio::main]
async fn main() {
    // we set this panic hook so we can drop out of raw mode in order to
    // display the panic message.  else there is wicked screen corruption.
    set_panic_hook();

    // Create connection to RPC server
    let args: Config = Config::parse();
    let server_socket = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let transport = tarpc::serde_transport::tcp::connect(server_socket, Json::default).await;
    let client = match transport {
        Ok(transp) => {
            DashboardRpcClient::Authentic(RPCClient::new(client::Config::default(), transp).spawn())
        }
        Err(err) => {
            #[cfg(feature = "mock")]
            {
                println!("Could not connect to neptune-core: {err}");
                println!("Switching to Mock RPC interface.");
                DashboardRpcClient::Mock(crate::mock_rpc_client::MockRpcClient::new())
            }
            #[cfg(not(feature = "mock"))]
            {
                eprintln!("{err}");
                eprintln!(
                    "Connection to neptune-core failed. Is a node running? Or is it still starting up?"
                );
                process::exit(1);
            }
        }
    };

    // Read what network the client is running and ensure that client is up and running
    let auth::CookieHint {
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

    let token: auth::Token = match auth::Cookie::try_load(&data_directory).await {
        Ok(t) => t,

        // if we are mocking the RPC server, and we get here, then we do not
        // care about cookies
        #[cfg(feature = "mock")]
        Err(_e) => auth::Cookie::new_in_mem(),

        // otherwise, big problem. report, crash, and burn.
        #[cfg(not(feature = "mock"))]
        Err(e) => {
            eprintln!("Unable to load RPC auth cookie. error = {e}");
            process::exit(2)
        }
    }
    .into();

    // run app until quit
    let res = DashboardApp::run(args, client, network, token).await;

    restore_text_mode(); // just in case.

    match res {
        Err(err) => {
            eprintln!("{err:?}");
            process::exit(1);
        }
        Ok(output) => {
            print!("{output}");
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
    client: &DashboardRpcClient,
    args: &Config,
) -> anyhow::Result<auth::CookieHint> {
    async fn fallback(
        client: &DashboardRpcClient,
        args: &Config,
    ) -> anyhow::Result<auth::CookieHint> {
        let network = client.network(context::current()).await??;
        let data_directory = DataDirectory::get(args.data_dir.clone(), network)?;
        Ok(auth::CookieHint {
            data_directory,
            network,
        })
    }

    #[cfg(feature = "mock")]
    if let DashboardRpcClient::Mock(_) = client {
        let network = client.network(context::current()).await??;
        return Ok(auth::CookieHint {
            data_directory: DataDirectory::get(Some(std::path::PathBuf::new()), network).unwrap(),
            network,
        });
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
