//! Provides simplified lock types for sharing data between threads
#![cfg_attr(feature = "track-lock-location", feature(async_fn_track_caller))]

pub mod std;
pub mod tokio;

#[cfg(test)]
mod test_utils {
    use std::sync::OnceLock;

    use tokio::runtime::Runtime;

    pub fn tokio_runtime() -> &'static Runtime {
        static RUNTIME: OnceLock<Runtime> = OnceLock::new();
        RUNTIME.get_or_init(|| Runtime::new().unwrap())
    }

    /// Runs an `async fn` test on a shared, multi-thread tokio runtime.
    ///
    /// Apply with `#[apply(shared_tokio_runtime)]` (from `macro_rules_attr`).
    macro_rules! shared_tokio_runtime {
        (
            $(#[$fn_meta:meta])*
            $vis:vis async fn $fn_name:ident() $(-> $ret:ty)? {
                $($tt:tt)*
            }
        ) => {
            $(#[$fn_meta])*
            #[test]
            // Propagate the return type and visibility to the #[test] fn.
            $vis fn $fn_name() $(-> $ret)? {
                let runtime = $crate::test_utils::tokio_runtime();
                runtime.block_on(async {
                    $vis async fn __inner() $(-> $ret)? {
                        $($tt)*
                    }
                    __inner().await // Return the awaited result
                })
            }
        };
    }

    pub(crate) use shared_tokio_runtime;
}
