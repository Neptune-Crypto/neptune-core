use std::process;

use anyhow::Result;
use clap::Parser;
use neptune_cash::application::config::cli_args;
use neptune_cash::display_banner;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::prelude::__tracing_subscriber_SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_throttle::Policy;
use tracing_throttle::TracingRateLimitLayer;

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

        let mut main_loop_handler = neptune_cash::initialize(args, None).await?;
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
    // Use the log level set by the environment (which defaults to INFO) for
    // messages logged in this crate. In upstream crates, hardcode it.
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tarpc=warn".parse().unwrap())
        .add_directive("libp2p=error".parse().unwrap())
        .add_directive("libp2p_ping=off".parse().unwrap())
        .add_directive("libp2p_kad=warn".parse().unwrap())
        .add_directive("quinn_udp=trace".parse().unwrap());

    // Throttle bounce messages to no more than 1 per 20s per connection.
    let bounce_throttle = TracingRateLimitLayer::builder()
        .with_policy(Policy::token_bucket(1.0, 0.05).unwrap())
        .build()
        .unwrap();

    let bounce_layer = tracing_subscriber::fmt::layer()
        .with_timer(UtcTime::rfc_3339())
        .with_thread_ids(true)
        .with_filter(Targets::new().with_target("net::bounce", LevelFilter::WARN))
        .with_filter(bounce_throttle);

    // Throttle abrupt closure messages to no more than 1 per 20s per peer.
    let abrupt_closure_throttle = TracingRateLimitLayer::builder()
        .with_policy(Policy::token_bucket(1.0, 0.05).unwrap())
        .build()
        .unwrap();

    let abrupt_closure_layer = tracing_subscriber::fmt::layer()
        .with_timer(UtcTime::rfc_3339())
        .with_thread_ids(true)
        .with_filter(Targets::new().with_target("net::abrupt_closure", LevelFilter::WARN))
        .with_filter(abrupt_closure_throttle);

    // Let everything not filtered through
    let main_layer = tracing_subscriber::fmt::layer()
        .with_timer(UtcTime::rfc_3339())
        .with_thread_ids(true)
        .with_filter(
            Targets::new()
                .with_target("net::bounce", LevelFilter::OFF)
                .with_target("net::abrupt_closure", LevelFilter::OFF)
                .with_default(LevelFilter::TRACE),
        );

    tracing_subscriber::registry()
        .with(env_filter)
        .with(bounce_layer)
        .with(abrupt_closure_layer)
        .with(main_layer)
        .init();
}
