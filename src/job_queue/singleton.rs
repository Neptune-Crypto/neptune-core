/// Generates a newtype wrapper for a given `JobQueue<P>` that is a singleton
/// equivalent, meaning the differences are:
///  - `start()` is made private, thus preventing accidental construction of
///    more than one object.
///  - `instance()` is added, which gives the caller a reference to the one
///    instance, and creates it first if necessary.
///
/// # Example Use
///
/// ```
/// use neptune_cash::{job_queue::JobQueue, singleton_job_queue};
///
/// #[derive(PartialEq, Eq, PartialOrd, Ord,)]
/// pub enum ExamplePriority {
///     High = 1,
///     Low = 2,
/// }
///
/// singleton_job_queue!(ExampleJobQueue = JobQueue<ExamplePriority>);
/// ```
///
/// If you want to include a doc string:
/// ```
/// use neptune_cash::{job_queue::JobQueue, singleton_job_queue};
///
/// #[derive(PartialEq, Eq, PartialOrd, Ord,)]
/// pub enum ExamplePriority {
///     High = 1,
///     Low = 2,
/// }
///
/// singleton_job_queue! {
///     #[doc = "A singleton job queue example."]
///     ExampleJobQueue = JobQueue<ExamplePriority>
/// }
/// ```
#[macro_export]
macro_rules! singleton_job_queue {
    (
        $(#[$meta:meta])*
        $wrapper:ident = $base:ident < $($generics:ty),+ >
    ) => {

            $(#[$meta])*
            pub struct $wrapper($base<$($generics),+>);

            impl std::ops::Deref for $wrapper {
                type Target = $base<$($generics),+>;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl $wrapper {
                // Override Deref to <$wrapper>::start(); make it private.
                fn start() -> Self {
                    $wrapper($base::start())
                }

                pub fn instance() -> &'static  $wrapper {
                    static INSTANCE : std::sync::OnceLock<$wrapper> = std::sync::OnceLock::new();
                    INSTANCE.get_or_init(|| <$wrapper>::start())
                }
            }
    };
}
