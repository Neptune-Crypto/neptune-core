//! `neptune-sofun`, the SOFuN plugin of `neptune-defi`.
//!
//! It connects to `neptune-defi`, keeps the order book of SOFuN orders in step
//! with the chain, and has `neptune-core` fill the best order in every block
//! it composes.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use neptune_defi::plugin;
use neptune_defi::plugin::Event;
use neptune_defi::standing_swap_order::sofun::plugin::SofunPlugin;
use neptune_defi::standing_swap_order::sofun::plugin::SUBSCRIPTIONS;
use neptune_primitives::data_directory::DataDirectory;
use neptune_primitives::network::Network;
use neptune_rpc_client::http::HttpClient;

#[derive(Debug, Parser)]
#[clap(about)]
struct Args {
    /// The network neptune-core runs on, as given to neptune-defi.
    #[clap(long, short, default_value = "main")]
    network: Network,

    /// neptune-core's data directory, as given to neptune-defi, which holds
    /// the plugin cookie.
    #[clap(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Where neptune-defi listens for plugins.
    #[clap(long, default_value_t = plugin::DEFAULT_ADDRESS, value_name = "ADDR")]
    plugin_address: SocketAddr,

    /// How many blocks deep a reorganization may go for the book to follow
    /// it, and how long the book keeps closed orders.
    #[clap(long, default_value = "100")]
    depth: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let cookie_path = match DataDirectory::get(args.data_dir, args.network) {
        Ok(data_directory) => plugin::cookie_path(&data_directory),
        Err(error) => {
            eprintln!("Cannot determine neptune-core's data directory: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut connection = match plugin::connect(
        args.plugin_address,
        &cookie_path,
        "sofun",
        SUBSCRIPTIONS.to_vec(),
    )
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!(
                "Cannot connect to neptune-defi on {}: {error}",
                args.plugin_address
            );
            return ExitCode::FAILURE;
        }
    };
    let client = HttpClient::new(format!("http://{}", connection.rpc()));
    let mut sofun = match SofunPlugin::new(client, args.network, args.depth).await {
        Ok(sofun) => sofun,
        Err(error) => {
            eprintln!("Cannot start: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Start at the tip, as if notifications had been missed.
    let mut event = Some(Event::Lagged(0));
    while let Some(current) = event {
        match sofun.on_event(&current).await {
            Ok(outcome) => eprintln!("neptune-sofun: {outcome:?}"),
            Err(error) => eprintln!("neptune-sofun: {error}"),
        }
        event = match connection.next().await {
            Ok(event) => event,
            Err(error) => {
                eprintln!("neptune-sofun: lost neptune-defi: {error}");
                return ExitCode::FAILURE;
            }
        };
    }

    eprintln!("neptune-sofun: neptune-defi closed the connection");
    ExitCode::SUCCESS
}
