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
pub fn tracing_logger() {
    let info_env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("self=trace,neptune_cash=trace,tarpc=warn"));
    let subscriber = FmtSubscriber::builder()
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
        .with_env_filter(info_env_filter)
        .with_thread_ids(true)
        .finish();

    // this will fail if global default was already set.  this typically
    // happens because tests are run in the same process.  so we just ignore the
    // error.
    let _result = tracing::subscriber::set_global_default(subscriber);
}
