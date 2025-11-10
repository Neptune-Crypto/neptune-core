use std::process;

use anyhow::Result;
use clap::Parser;
use neptune_cash::application::config::cli_args;
use neptune_cash::display_banner;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

pub fn main() -> Result<()> {
    display_banner();
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not create tokio runtime");

    let run_result = tokio_runtime.block_on(async {
        // Fetch the CLI arguments
        let args = cli_args::Args::parse();

        #[cfg(not(feature = "tokio-console"))]
        {
            use std::io::Write;
            if args.tokio_console {
                let mut stderr = std::io::BufWriter::new(std::io::stderr().lock());
                writeln!(stderr, "tokio-console support not included in this build.")?;
                writeln!(stderr, "To use the tokio-console command-line argument,")?;
                writeln!(stderr, "please build with the tokio-console feature-flag.")?;
                stderr.flush()?;
                anyhow::bail!("tokio-console not included. Build with tokio-console feature-flag.");
            }

            set_up_logger();
        }

        #[cfg(feature = "tokio-console")]
        if args.tokio_console {
            console_subscriber::init();
        } else {
            set_up_logger();
        }

        let mut main_loop_handler = neptune_cash::initialize(args).await?;
        main_loop_handler.run().await
    });

    tokio_runtime.shutdown_timeout(tokio::time::Duration::from_secs(10));

    if let Ok(exit_code) = run_result {
        process::exit(exit_code)
    } else {
        run_result.map(|_| ())
    }
}

/// Configure logger to use ISO-8601, of which rfc3339 is a subset. Install
/// global collector configured based on RUST_LOG env var. Accepted `RUST_LOG`
/// values are `trace`, `debug`, `info`, `warn`, and `error`.
fn set_up_logger() {
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
