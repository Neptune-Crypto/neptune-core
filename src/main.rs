use std::process;

use anyhow::Result;
use clap::Parser;
use neptune_cash::config_models::cli_args;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

pub fn main() -> Result<()> {
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not create tokio runtime");

    let res = tokio_runtime.block_on(async {
        // Fetch the CLI arguments
        let args: cli_args::Args = cli_args::Args::parse();

        if args.tokio_console {
            #[cfg(feature = "tokio-console")]
            console_subscriber::init();

            #[cfg(not(feature = "tokio-console"))]
            anyhow::bail!("tokio-console support not included in this build.  try building with tokio-console feature-flag.");

        } else {
            // Set up logger.
            // Configure logger to use ISO-8601, of which rfc3339 is a subset.
            // install global collector configured based on RUST_LOG env var.
            // Accepted `RUST_LOG` values are `trace`, `debug`, `info`, `warn`,
            // and `error`.

            let info_env_filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tarpc=warn"));
            let subscriber = FmtSubscriber::builder()
                .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
                .with_env_filter(info_env_filter)
                .with_thread_ids(true)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .map_err(|_err| eprintln!("Unable to set global default subscriber"))
                .expect("Failed to set trace subscriber");
        }

        neptune_cash::initialize(args).await
    });

    tokio_runtime.shutdown_timeout(tokio::time::Duration::from_secs(10));

    if let Ok(exit_code) = res {
        process::exit(exit_code)
    } else {
        res.map(|_| ())
    }
}
