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

macro_rules! digest_newtype {
    ($target: ident) => {
        #[derive(
            Copy,
            Debug,
            Clone,
            Default,
            Hash,
            GetSize,
            PartialEq,
            Eq,
            Serialize,
            Deserialize,
            BFieldCodec,
            Arbitrary,
        )]
        pub struct $target(Digest);
        impl std::ops::Deref for $target {
            type Target = Digest;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl std::fmt::Display for $target {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl From<Digest> for $target {
            fn from(d: Digest) -> Self {
                Self(d)
            }
        }
        impl From<$target> for Digest {
            fn from(sr: $target) -> Self {
                *sr
            }
        }
        impl Distribution<$target> for Standard {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> $target {
                $target(rng.gen())
            }
        }

        impl FromStr for $target {
            type Err = TryFromDigestError;

            fn from_str(string: &str) -> Result<Self, Self::Err> {
                Ok(Digest::from_str(string)?.into())
            }
        }

        impl TryFrom<&[BFieldElement]> for $target {
            type Error = TryFromDigestError;

            fn try_from(value: &[BFieldElement]) -> Result<Self, Self::Error> {
                Ok(Digest::try_from(value)?.into())
            }
        }

        impl TryFrom<Vec<BFieldElement>> for $target {
            type Error = TryFromDigestError;

            fn try_from(value: Vec<BFieldElement>) -> Result<Self, Self::Error> {
                Ok(Digest::try_from(value)?.into())
            }
        }

        impl From<$target> for Vec<BFieldElement> {
            fn from(val: $target) -> Self {
                val.0.into()
            }
        }

        impl From<$target> for [u8; Digest::BYTES] {
            fn from(item: $target) -> Self {
                item.0.into()
            }
        }

        impl TryFrom<[u8; Digest::BYTES]> for $target {
            type Error = TryFromDigestError;

            fn try_from(item: [u8; Digest::BYTES]) -> Result<Self, Self::Error> {
                Ok(Self(Digest::try_from(item)?))
            }
        }

        impl TryFrom<&[u8]> for $target {
            type Error = TryFromDigestError;

            fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(Digest::try_from(slice)?))
            }
        }

        impl TryFrom<BigUint> for $target {
            type Error = TryFromDigestError;

            fn try_from(value: BigUint) -> Result<Self, Self::Error> {
                Ok(Self(Digest::try_from(value)?))
            }
        }

        impl From<$target> for BigUint {
            fn from(digest: $target) -> Self {
                digest.0.into()
            }
        }
    };
}

// These allow the macros to be used as
// use crate::macros::xxxxx;
//
// see: https://stackoverflow.com/a/67140319/10087197

#[allow(unused_imports)]
pub(crate) use digest_newtype;
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

#[cfg(test)]
mod test {

    use super::*;
    use tracing::Level;

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
