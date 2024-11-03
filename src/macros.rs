/// returns name of current function.
macro_rules! fn_name_bare {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        type_name_of(f)
            .rsplit("::")
            .find(|&part| part != "f" && part != "{{closure}}")
            .expect("Short function name")
    }};
}

/// returns name of current function plus "()"
macro_rules! fn_name {
    () => {{
        format!("{}()", crate::macros::fn_name_bare!())
    }};
}

/// executes an expression, times duration, and emits trace! message
///
/// The trace level is `tracing::Level::TRACE` by default.
///
/// Accepts arguments in 3 forms:
///   duration!(myfunc())
///   duration!(myfunc(), message)
///   duration!(myfunc(), message, trace_level)
#[allow(unused_macros)]
macro_rules! duration {
    ($target: expr, $message: expr, $lvl: expr) => {{
        let (output, duration) = $crate::time_fn_call(|| $target);
        let msg = format!(
            "at {}:{}{}\n-- executed expression --\n{}\n -- duration: {} secs --",
            file!(),
            line!(),
            if $message.len() > 0 {
                format! {"\n{}", $message}
            } else {
                "".to_string()
            },
            stringify!($target),
            duration
        );
        match $lvl {
            tracing::Level::INFO => tracing::info!("{}", msg),
            tracing::Level::TRACE => tracing::trace!("{}", msg),
            tracing::Level::DEBUG => tracing::trace!("{}", msg),
            tracing::Level::WARN => tracing::warn!("{}", msg),
            tracing::Level::ERROR => tracing::error!("{}", msg),
        }
        output
    }};
    ($target: expr, $message: expr) => {
        $crate::macros::duration!($target, $message, tracing::Level::TRACE)
    };
    ($target: expr) => {
        $crate::macros::duration!($target, "", tracing::Level::TRACE)
    };
}

/// executes an expression, times duration, and emits info! message
///
/// Accepts arguments in 2 forms:
///   duration!(myfunc())
///   duration!(myfunc(), message)
#[allow(unused_macros)]
macro_rules! duration_info {
    ($target: expr) => {
        $crate::macros::duration!($target, "", tracing::Level::INFO)
    };
    ($target: expr, $message: expr) => {
        $crate::macros::duration!($target, $message, tracing::Level::INFO)
    };
}

/// executes an expression, times duration, and emits debug! message
///
/// Accepts arguments in 2 forms:
///   duration!(myfunc())
///   duration!(myfunc(), message)
#[allow(unused_macros)]
macro_rules! duration_debug {
    ($target: expr) => {
        $crate::macros::duration!($target, "", tracing::Level::DEBUG)
    };
    ($target: expr, $message: expr) => {
        $crate::macros::duration!($target, $message, tracing::Level::DEBUG)
    };
}

/// executes an async expression, times duration, and emits trace! message
///
/// Accepts arguments in 3 forms:
///   duration!(myfunc())
///   duration!(myfunc(), message)
///   duration!(myfunc(), message, trace_level)
#[allow(unused_macros)]
macro_rules! duration_async {
    ($target: expr, $message: expr, $lvl: expr) => {{
        let (output, duration) = $crate::time_fn_call_async({ $target }).await;
        let msg = format!(
            "at {}:{}{}\n-- executed expression --\n{}\n -- duration: {} secs --",
            file!(),
            line!(),
            if $message.len() > 0 {
                format! {"\n{}", $message}
            } else {
                "".to_string()
            },
            stringify!($target),
            duration
        );
        match $lvl {
            tracing::Level::INFO => tracing::info!("{}", msg),
            tracing::Level::TRACE => tracing::trace!("{}", msg),
            tracing::Level::DEBUG => tracing::trace!("{}", msg),
            tracing::Level::WARN => tracing::warn!("{}", msg),
            tracing::Level::ERROR => tracing::error!("{}", msg),
        }
        output
    }};
    ($target: expr, $message: expr) => {
        $crate::macros::duration_async!($target, $message, tracing::Level::TRACE)
    };
    ($target: expr) => {
        $crate::macros::duration_async!($target, "", tracing::Level::TRACE)
    };
}

/// executes an async expression, times duration, and emits info! message
///
/// Accepts arguments in 2 forms:
///   duration!(myfunc())
///   duration!(myfunc(), message)
#[allow(unused_macros)]
macro_rules! duration_async_info {
    ($target: expr) => {
        $crate::macros::duration_async!($target, "", tracing::Level::INFO)
    };
    ($target: expr, $message: expr) => {
        $crate::macros::duration_async!($target, $message, tracing::Level::INFO)
    };
}

/// executes an async expression, times duration, and emits debug! message
///
/// Accepts arguments in 2 forms:
///   duration!(myfunc())
///   duration!(myfunc(), message)
#[allow(unused_macros)]
macro_rules! duration_async_debug {
    ($target: expr) => {
        $crate::macros::duration_async!($target, "", tracing::Level::DEBUG)
    };
    ($target: expr, $message: expr) => {
        $crate::macros::duration_async!($target, $message, tracing::Level::DEBUG)
    };
}

// These allow the macros to be used as
// use crate::macros::xxxxx;
//
// see: https://stackoverflow.com/a/67140319/10087197

#[allow(unused_imports)]
pub(crate) use duration;
#[allow(unused_imports)]
pub(crate) use duration_async;
#[allow(unused_imports)]
pub(crate) use duration_async_debug;
#[allow(unused_imports)]
pub(crate) use duration_async_info;
#[allow(unused_imports)]
pub(crate) use duration_debug;
#[allow(unused_imports)]
pub(crate) use duration_info;
#[allow(unused_imports)]
pub(crate) use fn_name;
#[allow(unused_imports)]
pub(crate) use fn_name_bare;

#[cfg(test)]
mod test {

    use tracing::Level;

    use super::*;

    fn fibonacci(n: u32) -> u32 {
        match n {
            0 => 1,
            1 => 1,
            _ => fibonacci(n - 1) + fibonacci(n - 2),
        }
    }

    async fn fibonacci_async(n: u32) -> u32 {
        match n {
            0 => 1,
            1 => 1,
            _ => fibonacci(n - 1) + fibonacci(n - 2),
        }
    }

    #[test]
    fn duration_tests() {
        duration!(fibonacci(1));
        duration!(fibonacci(2), "fibonacci - 2".to_string());
        duration!(fibonacci(3), "fibonacci - 3", Level::INFO);

        duration_info!(fibonacci(4));
        duration_info!(fibonacci(5), "fibonacci - 5");
        duration_info!(fibonacci(6), "fibonacci - 6".to_string());

        duration_debug!(fibonacci(7));
        duration_debug!(fibonacci(8), "fibonacci - 8");
        duration_debug!(fibonacci(9), "fibonacci - 9".to_string());
    }

    #[tokio::test]
    async fn duration_async_tests() {
        duration_async!(fibonacci_async(1));
        duration_async!(fibonacci_async(2), "fibonacci_async - 2".to_string());
        duration_async!(fibonacci_async(3), "fibonacci_async - 3", Level::INFO);

        duration_async_info!(fibonacci_async(4));
        duration_async_info!(fibonacci_async(5), "fibonacci_async - 5");
        duration_async_info!(fibonacci_async(6), "fibonacci_async - 6".to_string());

        duration_async_debug!(fibonacci_async(7));
        duration_async_debug!(fibonacci_async(8), "fibonacci_async - 8");
        duration_async_debug!(fibonacci_async(9), "fibonacci_async - 9".to_string());
    }
}
