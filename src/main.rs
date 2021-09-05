use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, instrument};
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

    // Bind socket to port on network
    let listener = TcpListener::bind((args.listen_addr, args.port))
        .await
        .unwrap();

    loop {
        // The second item contains the IP and port of the new connection.
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            handle_connection(stream).await;
        });
    }
}

#[instrument]
async fn handle_connection(stream: TcpStream) {
    let peer_address = stream.peer_addr();
    info!("Connection established with {:?}", peer_address);

    match neptune_core::run(stream).await {
        Ok(()) => (),
        Err(e) => error!("An error occurred: {}. Connection closing", e),
    };

    info!("Connection with {:?} closing", peer_address);
}
