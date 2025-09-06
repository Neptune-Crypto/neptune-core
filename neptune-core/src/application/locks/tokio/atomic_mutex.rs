use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;

use super::now;
use super::LockAcquisition;
use super::LockCallbackFn;
use super::LockCallbackInfo;
use super::LockEvent;
use super::LockType;

/// An `Arc<Mutex<T>>` wrapper to make data thread-safe and easy to work with.
///
/// # Examples
/// ```
/// # use neptune_cash::application::locks::tokio::AtomicMutex;
/// struct Car {
///     year: u16,
/// };
/// # tokio_test::block_on(async {
/// let mut atomic_car = AtomicMutex::from(Car{year: 2016});
/// atomic_car.lock(|c| {println!("year: {}", c.year)}).await;
/// atomic_car.lock_mut(|mut c| {c.year = 2023}).await;
/// # })
/// ```
///
/// It is also possible to provide a name and callback fn
/// during instantiation.  In this way, the application
/// can easily trace lock acquisitions.
///
/// # Examples
/// ```
/// # use neptune_cash::application::locks::tokio::{AtomicMutex, LockEvent, LockCallbackFn};
/// struct Car {
///     year: u16,
/// };
///
/// pub fn log_lock_event(lock_event: LockEvent) {
///     let (event, info, acquisition) =
///     match lock_event {
///         LockEvent::TryAcquire{info, acquisition, ..} => ("TryAcquire", info, acquisition),
///         LockEvent::Acquire{info, acquisition, ..} => ("Acquire", info, acquisition),
///         LockEvent::Release{info, acquisition, ..} => ("Release", info, acquisition),
///     };
///
///     println!(
///         "{} lock `{}` of type `{}` for `{}` by\n\t|-- thread {}, `{:?}`",
///         event,
///         info.name().unwrap_or("?"),
///         info.lock_type(),
///         acquisition,
///         std::thread::current().name().unwrap_or("?"),
///         std::thread::current().id(),
///     );
/// }
/// const LOG_TOKIO_LOCK_EVENT_CB: LockCallbackFn = log_lock_event;
///
/// # tokio_test::block_on(async {
/// let mut atomic_car = AtomicMutex::<Car>::from((Car{year: 2016}, Some("car"), Some(LOG_TOKIO_LOCK_EVENT_CB)));
/// atomic_car.lock(|c| {println!("year: {}", c.year)}).await;
/// atomic_car.lock_mut(|mut c| {c.year = 2023}).await;
/// # })
/// ```
///
/// results in:
/// ```text
/// TryAcquire lock `car` of type `Mutex` for `Read` by
///     |-- thread main, `ThreadId(1)`
/// Acquire lock `car` of type `Mutex` for `Read` by
///     |-- thread main, `ThreadId(1)`
/// year: 2016
/// Release lock `car` of type `Mutex` for `Read` by
///     |-- thread main, `ThreadId(1)`
/// TryAcquire lock `car` of type `Mutex` for `Write` by
///     |-- thread main, `ThreadId(1)`
/// Acquire lock `car` of type `Mutex` for `Write` by
///     |-- thread main, `ThreadId(1)`
/// Release lock `car` of type `Mutex` for `Write` by
///     |-- thread main, `ThreadId(1)`
/// ```
#[derive(Debug)]
pub struct AtomicMutex<T> {
    inner: Arc<Mutex<T>>,
    lock_callback_info: LockCallbackInfo,
}

impl<T: Default> Default for AtomicMutex<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            lock_callback_info: LockCallbackInfo::new(LockType::Mutex, None, None),
        }
    }
}

impl<T> From<T> for AtomicMutex<T> {
    #[inline]
    fn from(t: T) -> Self {
        Self {
            inner: Arc::new(Mutex::new(t)),
            lock_callback_info: LockCallbackInfo::new(LockType::Mutex, None, None),
        }
    }
}
impl<T> From<(T, Option<String>, Option<LockCallbackFn>)> for AtomicMutex<T> {
    /// Create from an optional name and an optional callback function, which
    /// is called when a lock event occurs.
    #[inline]
    fn from(v: (T, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(Mutex::new(v.0)),
            lock_callback_info: LockCallbackInfo::new(LockType::Mutex, v.1, v.2),
        }
    }
}
impl<T> From<(T, Option<&str>, Option<LockCallbackFn>)> for AtomicMutex<T> {
    /// Create from a name ref and an optional callback function, which
    /// is called when a lock event occurs.
    #[inline]
    fn from(v: (T, Option<&str>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(Mutex::new(v.0)),
            lock_callback_info: LockCallbackInfo::new(
                LockType::Mutex,
                v.1.map(|s| s.to_owned()),
                v.2,
            ),
        }
    }
}

impl<T> Clone for AtomicMutex<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            lock_callback_info: self.lock_callback_info.clone(),
        }
    }
}

impl<T> From<Mutex<T>> for AtomicMutex<T> {
    #[inline]
    fn from(t: Mutex<T>) -> Self {
        Self {
            inner: Arc::new(t),
            lock_callback_info: LockCallbackInfo::new(LockType::Mutex, None, None),
        }
    }
}
impl<T> From<(Mutex<T>, Option<String>, Option<LockCallbackFn>)> for AtomicMutex<T> {
    /// Create from a `Mutex<T>` plus an optional name
    /// and an optional callback function, which is called
    /// when a lock event occurs.
    #[inline]
    fn from(v: (Mutex<T>, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(v.0),
            lock_callback_info: LockCallbackInfo::new(LockType::Mutex, v.1, v.2),
        }
    }
}

impl<T> TryFrom<AtomicMutex<T>> for Mutex<T> {
    type Error = Arc<Mutex<T>>;
    fn try_from(t: AtomicMutex<T>) -> Result<Mutex<T>, Self::Error> {
        Arc::<Mutex<T>>::try_unwrap(t.inner)
    }
}

impl<T> From<Arc<Mutex<T>>> for AtomicMutex<T> {
    #[inline]
    fn from(t: Arc<Mutex<T>>) -> Self {
        Self {
            inner: t,
            lock_callback_info: LockCallbackInfo::new(LockType::Mutex, None, None),
        }
    }
}
impl<T> From<(Arc<Mutex<T>>, Option<String>, Option<LockCallbackFn>)> for AtomicMutex<T> {
    /// Create from an `Arc<Mutex<T>>` plus an optional name and
    /// an optional callback function, which is called when a lock
    /// event occurs.
    #[inline]
    fn from(v: (Arc<Mutex<T>>, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: v.0,
            lock_callback_info: LockCallbackInfo::new(LockType::Mutex, v.1, v.2),
        }
    }
}

impl<T> From<AtomicMutex<T>> for Arc<Mutex<T>> {
    #[inline]
    fn from(t: AtomicMutex<T>) -> Self {
        t.inner
    }
}

// note: we impl the Atomic trait methods here also so they
// can be used without caller having to use the trait.
impl<T> AtomicMutex<T> {
    /// Acquire read lock and return an `AtomicMutexGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicMutex;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// let year = atomic_car.lock_guard().await.year;
    /// # })
    /// ```
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_guard(&self) -> AtomicMutexGuard<'_, T> {
        self.try_acquire_read_cb();

        let try_acquire_at = now();
        let guard = self.inner.lock().await;
        AtomicMutexGuard::new(
            guard,
            &self.lock_callback_info,
            LockAcquisition::Read,
            try_acquire_at,
        )
    }

    /// Attempt to return a read lock and return an `AtomicMutextGuard`. Returns
    /// an error if the lock is already held, otherwise returns Ok(lock).
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub fn try_lock_guard(&self) -> Result<AtomicMutexGuard<'_, T>, tokio::sync::TryLockError> {
        self.try_acquire_try_acquire();

        let try_acquire_at = now();
        let guard = self.inner.try_lock()?;
        Ok(AtomicMutexGuard::new(
            guard,
            &self.lock_callback_info,
            LockAcquisition::TryAcquire,
            try_acquire_at,
        ))
    }

    /// Acquire write lock and return an `AtomicMutexGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicMutex;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let mut atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_guard_mut().await.year = 2022;
    /// # })
    /// ```
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_guard_mut(&mut self) -> AtomicMutexGuard<'_, T> {
        self.try_acquire_write_cb();

        let try_acquire_at = now();
        let guard = self.inner.lock().await;
        AtomicMutexGuard::new(
            guard,
            &self.lock_callback_info,
            LockAcquisition::Write,
            try_acquire_at,
        )
    }

    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicMutex;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock(|c| println!("year: {}", c.year)).await;
    /// let year = atomic_car.lock(|c| c.year).await;
    /// })
    /// ```
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        self.try_acquire_read_cb();

        let try_acquire_at = now();
        let inner_guard = self.inner.lock().await;
        let guard = AtomicMutexGuard::new(
            inner_guard,
            &self.lock_callback_info,
            LockAcquisition::Read,
            try_acquire_at,
        );
        f(&guard)
    }

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicMutex;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let mut atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_mut(|mut c| c.year = 2022).await;
    /// let year = atomic_car.lock_mut(|mut c| {c.year = 2023; c.year}).await;
    /// })
    /// ```
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_mut<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        self.try_acquire_write_cb();

        let try_acquire_at = now();
        let inner_guard = self.inner.lock().await;
        let mut guard = AtomicMutexGuard::new(
            inner_guard,
            &self.lock_callback_info,
            LockAcquisition::Write,
            try_acquire_at,
        );
        f(&mut guard)
    }

    /// Immutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicMutex;
    /// # use futures::future::FutureExt;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_async(|c| async {println!("year: {}", c.year)}.boxed()).await;
    /// let year = atomic_car.lock_async(|c| async {c.year}.boxed()).await;
    /// })
    /// ```
    // design background: https://stackoverflow.com/a/77657788/10087197
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_async<R>(&self, f: impl FnOnce(&T) -> BoxFuture<'_, R>) -> R {
        self.try_acquire_read_cb();

        let try_acquire_at = now();
        let inner_guard = self.inner.lock().await;
        let guard = AtomicMutexGuard::new(
            inner_guard,
            &self.lock_callback_info,
            LockAcquisition::Read,
            try_acquire_at,
        );
        f(&guard).await
    }

    /// Mutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicMutex;
    /// # use futures::future::FutureExt;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let mut atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_mut_async(|mut c| async {c.year = 2022}.boxed()).await;
    /// let year = atomic_car.lock_mut_async(|mut c| async {c.year = 2023; c.year}.boxed()).await;
    /// })
    /// ```
    // design background: https://stackoverflow.com/a/77657788/10087197
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_mut_async<R>(&mut self, f: impl FnOnce(&mut T) -> BoxFuture<'_, R>) -> R {
        self.try_acquire_write_cb();

        let try_acquire_at = now();
        let inner_guard = self.inner.lock().await;
        let mut guard = AtomicMutexGuard::new(
            inner_guard,
            &self.lock_callback_info,
            LockAcquisition::Write,
            try_acquire_at,
        );
        f(&mut guard).await
    }

    #[cfg_attr(feature = "track-lock-location", track_caller)]
    fn try_acquire_try_acquire(&self) {
        if let Some(cb) = self.lock_callback_info.lock_callback_fn {
            cb(LockEvent::TryAcquire {
                info: self.lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::TryAcquire,

                #[cfg(feature = "track-lock-location")]
                location: Some(core::panic::Location::caller()),
                #[cfg(not(feature = "track-lock-location"))]
                location: None,
            });
        }
    }

    #[cfg_attr(feature = "track-lock-location", track_caller)]
    fn try_acquire_read_cb(&self) {
        if let Some(cb) = self.lock_callback_info.lock_callback_fn {
            cb(LockEvent::TryAcquire {
                info: self.lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Read,

                #[cfg(feature = "track-lock-location")]
                location: Some(core::panic::Location::caller()),
                #[cfg(not(feature = "track-lock-location"))]
                location: None,
            });
        }
    }

    #[cfg_attr(feature = "track-lock-location", track_caller)]
    fn try_acquire_write_cb(&self) {
        if let Some(cb) = self.lock_callback_info.lock_callback_fn {
            cb(LockEvent::TryAcquire {
                info: self.lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Write,

                #[cfg(feature = "track-lock-location")]
                location: Some(core::panic::Location::caller()),
                #[cfg(not(feature = "track-lock-location"))]
                location: None,
            });
        }
    }
}

/// A wrapper for [MutexGuard] that can optionally call a callback to notify
/// when the lock event occurs.
#[derive(Debug)]
pub struct AtomicMutexGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    lock_callback_info: &'a LockCallbackInfo,
    acquisition: LockAcquisition,
    try_acquire_at: Option<std::time::Instant>,
    acquire_at: Option<std::time::Instant>,
    location: Option<&'static core::panic::Location<'static>>,
}

impl<'a, T> AtomicMutexGuard<'a, T> {
    fn new(
        guard: MutexGuard<'a, T>,
        lock_callback_info: &'a LockCallbackInfo,
        acquisition: LockAcquisition,
        try_acquire_at: Option<std::time::Instant>,
    ) -> Self {
        let my_guard = Self {
            guard,
            lock_callback_info,
            acquisition,
            try_acquire_at,

            #[cfg(feature = "track-lock-time")]
            acquire_at: Some(std::time::Instant::now()),
            #[cfg(not(feature = "track-lock-time"))]
            acquire_at: None,

            #[cfg(feature = "track-lock-location")]
            location: Some(core::panic::Location::caller()),
            #[cfg(not(feature = "track-lock-location"))]
            location: None,
        };

        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Acquire {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition,
                try_acquire_at: my_guard.try_acquire_at,
                acquire_at: my_guard.acquire_at,
                location: my_guard.location,
            });
        }

        my_guard
    }
}

impl<T> Drop for AtomicMutexGuard<'_, T> {
    fn drop(&mut self) {
        let lock_callback_info = self.lock_callback_info;
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Release {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: self.acquisition,
                try_acquire_at: self.try_acquire_at,
                acquire_at: self.acquire_at,
                location: self.location,
            });
        }
    }
}

impl<T> Deref for AtomicMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for AtomicMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use futures::future::FutureExt;
    use macro_rules_attr::apply;
    use tracing_test::traced_test;

    use super::*;
    use crate::tests::shared_tokio_runtime;

    /// Verify (compile-time) that AtomicMutex:.lock() and :.lock_mut() accept
    /// mutable values. (FnMut)
    #[apply(shared_tokio_runtime)]
    async fn mutable_assignment() {
        let name = "Jim".to_string();
        let mut atomic_name = AtomicMutex::from(name);

        let mut new_name = String::new();
        atomic_name.lock_mut(|n| *n = "Sally".to_string()).await;
        atomic_name.lock_mut(|n| new_name = (*n).to_string()).await;
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn try_acquire_no_log() {
        let unit = ();
        let atomic_unit = AtomicMutex::<()>::from(unit);
        assert!(
            atomic_unit.try_lock_guard().is_ok(),
            "Must succeed when no lock is held"
        );

        let _held_lock = atomic_unit.try_lock_guard().unwrap();
        assert!(
            atomic_unit.try_lock_guard().is_err(),
            "Must fail when lock is held"
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn try_acquire_with_log() {
        pub fn log_lock_event(lock_event: LockEvent) {
            let (event, info, acquisition) = match lock_event {
                LockEvent::TryAcquire {
                    info, acquisition, ..
                } => ("TryAcquire", info, acquisition),
                LockEvent::Acquire {
                    info, acquisition, ..
                } => ("Acquire", info, acquisition),
                LockEvent::Release {
                    info, acquisition, ..
                } => ("Release", info, acquisition),
            };

            println!(
                "{} lock `{}` of type `{}` for `{}` by\n\t|-- thread {}, `{:?}`",
                event,
                info.name().unwrap_or("?"),
                info.lock_type(),
                acquisition,
                std::thread::current().name().unwrap_or("?"),
                std::thread::current().id(),
            );
        }

        const LOG_TOKIO_LOCK_EVENT_CB: LockCallbackFn = log_lock_event;
        let name = "Jim".to_string();
        let atomic_name =
            AtomicMutex::<String>::from((name, Some("name"), Some(LOG_TOKIO_LOCK_EVENT_CB)));
        assert!(
            atomic_name.try_lock_guard().is_ok(),
            "Must succeed when no lock is held"
        );

        let _held_lock = atomic_name.lock_guard().await;
        assert!(
            atomic_name.try_lock_guard().is_err(),
            "Must fail when lock is held"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn lock_async() {
        struct Car {
            year: u16,
        }

        let atomic_car = AtomicMutex::from(Car { year: 2016 });

        // access data without returning anything from closure
        atomic_car
            .lock_async(|c| {
                async {
                    assert_eq!(c.year, 2016);
                }
                .boxed()
            })
            .await;

        // test return from closure.
        let year = atomic_car.lock_async(|c| async { c.year }.boxed()).await;
        assert_eq!(year, 2016);
    }
}
