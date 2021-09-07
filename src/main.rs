use anyhow::Result;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod args;

#[paw::main]
#[tokio::main]
pub async fn main(args: args::Args) -> Result<()> {
    // Configure logger to use ISO-8601, of which rfc3339 is a subset.
    // install global collector configured based on RUST_LOG env var.
    // Accepted `RUST_LOG` values are `trace`, `debug`, `info`, `warn`,
    // and `error`.
    let subscriber = FmtSubscriber::builder()
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc3339())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_err| eprintln!("Unable to set global default subscriber"))
        .expect("Failed to set log subscriber");

    // Bind socket to port on this machine
    let listener = TcpListener::bind((args.listen_addr, args.port))
        .await
        .unwrap_or_else(|_| panic!("Failed to bind to local TCP port {}:{}. Is an instance of this program already running?", args.listen_addr, args.port));

    // Connect to peers
    for peer in args.peers {
        tokio::spawn(async move {
            neptune_core::initiate_connection(peer).await;
        });
    }

    // Handle incoming connections
    loop {
        // The second item contains the IP and port of the new connection.
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            neptune_core::receive_connection(stream).await;
        });
    }
}
