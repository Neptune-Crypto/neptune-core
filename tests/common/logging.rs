use std::path::Path;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

/// the #[traced_test] decorator does not work well with integration
/// tests because each test modules runs in its own crate, and the
/// decorator macro filters out events from neptune_cash.
///
/// A solution is to NOT use #[traced_test] and instead call this
/// method at start of each test.
///
/// note that one cannot do both as there can be only one global
/// default subscriber.
#[track_caller]
pub fn tracing_logger() {
    if std::env::var("NOCAPTURE").is_err() {
        return; // Return early if NOCAPTURE is not set
    }

    let file_path = core::panic::Location::caller().file();

    let info_env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // integration tests are in a separate crate whose name matches
        // the source file without .rs extension.

        let crate_name = Path::new(file_path).file_stem().unwrap().to_str().unwrap();

        let filter = format!("{}=trace,neptune_cash=trace,tarpc=warn", crate_name);

        EnvFilter::new(filter)
    });

    let subscriber = FmtSubscriber::builder()
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
        .with_env_filter(info_env_filter)
        .with_thread_ids(true)
        .finish();

    // this will fail if global default was already set. this typically
    // happens because tests are run in the same process. so we just ignore the
    // error.
    let _result = tracing::subscriber::set_global_default(subscriber);
}
