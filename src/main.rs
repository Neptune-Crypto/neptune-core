use anyhow::Result;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[paw::main]
#[tokio::main]
pub async fn main(args: neptune_core::config_models::cli_args::Args) -> Result<()> {
    // Configure logger to use ISO-8601, of which rfc3339 is a subset.
    // install global collector configured based on RUST_LOG env var.
    // Accepted `RUST_LOG` values are `trace`, `debug`, `info`, `warn`,
    // and `error`.
    let subscriber = FmtSubscriber::builder()
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_err| eprintln!("Unable to set global default subscriber"))
        .expect("Failed to set log subscriber");

    neptune_core::initialize(args).await
}
