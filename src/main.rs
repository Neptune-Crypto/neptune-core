use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, instrument};

mod args;

#[paw::main]
#[tokio::main]
pub async fn main(args: args::Args) -> Result<()> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();

    let listener = TcpListener::bind((args.listen_addr, args.port))
        .await
        .unwrap();

    loop {
        // The second item contains the IP and port of the new connection.
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            handle_connection(socket).await;
        });
    }
}

#[instrument]
async fn handle_connection(stream: TcpStream) {
    info!("Connection established");

    match neptune_core::run(stream).await {
        Ok(()) => (),
        Err(e) => error!("An error occurred: {}. Connection closing", e),
    };

    info!("Connection closing");
}
