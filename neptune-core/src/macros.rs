/// for calling a mutable async callback fn with correct StateLock variant
/// this appears impossible to do without a macro.
macro_rules! state_lock_call_mut_async {
    ($state_lock:expr, $func:expr, $($arg:expr),*) => {
        async {
            match $state_lock {
                StateLock::Lock(ref mut global_state_lock) => {
                    $func(&mut *global_state_lock.lock_guard_mut().await, $($arg,)*).await
                }
                StateLock::WriteGuard(ref mut gsm) => {
                    $func(&mut *gsm, $($arg,)*).await
                }
                StateLock::ReadGuard(_) => {
                    panic!("can't call a mutable function on a read-guard")
                }
            }
        }
    };
}

/// for calling an immutable async callback fn with correct StateLock variant
/// this appears impossible to do without a macro.
macro_rules! state_lock_call_async {
    ($state_lock:expr, $func:expr, $($arg:expr),*) => {
        async {
            match $state_lock {
                StateLock::Lock(ref global_state_lock) => {
                    $func(&*global_state_lock.lock_guard().await, $($arg,)*).await
                }
                StateLock::WriteGuard(ref gsm) => {
                    $func(&*gsm, $($arg,)*).await
                }
                StateLock::ReadGuard(ref gs) => {
                    $func(&*gs, $($arg,)*).await
                }
            }
        }
    };
}

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

/// logs a warning if scope duration exceeds a threshold.
/// See [crate::ScopeDurationLogger]
macro_rules! log_slow_scope {
    () => {
        let log_slow_scope_desc = $crate::macros::fn_name!();
        let _____x = $crate::ScopeDurationLogger::new_default_threshold(&log_slow_scope_desc);
    };
    ($description: expr) => {
        let log_slow_scope_desc = $description;
        let _____x = $crate::ScopeDurationLogger::new_default_threshold(&log_slow_scope_desc);
    };
    ($description: expr, $threshold: expr) => {
        let log_slow_scope_desc = $description;
        let _____x =
            $crate::ScopeDurationLogger::new_with_threshold(&log_slow_scope_desc, $threshold);
    };
}

/// logs a warning if scope duration exceeds a threshold.
/// See [crate::ScopeDurationLogger]
macro_rules! log_scope_duration {
    () => {
        let log_scope_desc = $crate::macros::fn_name!();
        let _____x = $crate::ScopeDurationLogger::new_without_threshold(&log_scope_desc);
    };
    ($description: expr) => {
        let log_scope_desc = $description;
        let _____x = $crate::ScopeDurationLogger::new_without_threshold(&log_scope_desc);
    };
}

// These allow the macros to be used as
// use crate::macros::xxxxx;
//
// see: https://stackoverflow.com/a/67140319/10087197
pub(crate) use fn_name;
pub(crate) use fn_name_bare;
pub(crate) use log_scope_duration;
pub(crate) use log_slow_scope;
pub(crate) use state_lock_call_async;
pub(crate) use state_lock_call_mut_async;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    fn fibonacci(n: u32) -> u32 {
        match n {
            0 => 1,
            1 => 1,
            _ => fibonacci(n - 1) + fibonacci(n - 2),
        }
    }

    #[test]
    fn duration_test() {
        log_scope_duration!();
        log_scope_duration!(fn_name!());
        fibonacci(10);
    }

    #[test]
    fn log_slow_scope_test() {
        log_slow_scope!();
        log_slow_scope!(fn_name!());
        log_slow_scope!(fn_name!(), 0.00001);

        fibonacci(10);
    }
}
