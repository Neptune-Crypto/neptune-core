use std::sync::OnceLock;

use tokio::runtime::Runtime;

pub fn tokio_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().unwrap())
}

#[cfg(test)]
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
            let runtime = $crate::proof_abstractions::test_runtime::tokio_runtime();
            runtime.block_on(async {
                $vis async fn __inner() $(-> $ret)? {
                    $($tt)*
                }
                __inner().await // Return the awaited result
            })
        }
    };
}

#[cfg(test)]
pub(crate) use shared_tokio_runtime;
