pub mod shared;

use std::sync::OnceLock;

use tokio::runtime::Runtime;

pub fn tokio_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().unwrap())
}

macro_rules! shared_tokio_runtime {
    (
        $(#[$fn_meta:meta])*
        $vis:vis async fn $fn_name:ident() $(-> $ret:ty)? {
            $($tt:tt)*
        }
    ) => {
        $(#[$fn_meta])*
        #[test]
        fn $fn_name() $(-> $ret)? { // Propagate the return type to the #[test] fn
            let runtime = $crate::tests::tokio_runtime();
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
