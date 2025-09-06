// [track_caller] is used in this module to obtain source location of caller when
// a write-lock is acquired, and log it upon drop if the lock is held too long.
//
// [track_caller] is not (yet?) available for async fn in stable rust.
// it is available in nightly rust with the async_fn_track_caller
// feature flag.  To enable the feature in neptune build with
// cargo +nightly build --features track-lock-location

use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::sync::RwLock;
use tokio::sync::RwLockReadGuard;
use tokio::sync::RwLockWriteGuard;
use tokio::sync::TryLockError;

use super::now;
use super::LockAcquisition;
use super::LockCallbackFn;
use super::LockCallbackInfo;
use super::LockEvent;
use super::LockType;

/// An `Arc<RwLock<T>>` wrapper to make data thread-safe and easy to work with.
///
/// # Examples
/// ```
/// # use neptune_cash::application::locks::tokio::AtomicRw;
/// struct Car {
///     year: u16,
/// };
/// # tokio_test::block_on(async {
/// let mut atomic_car = AtomicRw::from(Car{year: 2016});
/// atomic_car.lock(|c| {println!("year: {}", c.year)}).await;
/// atomic_car.lock_mut(|mut c| {c.year = 2023}).await;
/// # })
/// ```
///
/// It is also possible to provide a name and callback fn/// during instantiation.  In this way, the application
/// can easily trace lock acquisitions.
///
/// # Examples
/// ```
/// # use neptune_cash::application::locks::tokio::{AtomicRw, LockEvent, LockCallbackFn};
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
/// let mut atomic_car = AtomicRw::<Car>::from((Car{year: 2016}, Some("car"), Some(LOG_TOKIO_LOCK_EVENT_CB)));
/// atomic_car.lock(|c| {println!("year: {}", c.year)}).await;
/// atomic_car.lock_mut(|mut c| {c.year = 2023}).await;
/// # })
/// ```
///
/// results in:
/// ```text
/// TryAcquire lock `car` of type `RwLock` for `Read` by
///     |-- thread main, `ThreadId(1)`
/// Acquire lock `car` of type `RwLock` for `Read` by
///     |-- thread main, `ThreadId(1)`
/// year: 2016
/// Release lock `car` of type `RwLock` for `Read` by
///     |-- thread main, `ThreadId(1)`
/// TryAcquire lock `car` of type `RwLock` for `Write` by
///     |-- thread main, `ThreadId(1)`
/// Acquire lock `car` of type `RwLock` for `Write` by
///     |-- thread main, `ThreadId(1)`
/// Release lock `car` of type `RwLock` for `Write` by
///     |-- thread main, `ThreadId(1)`
/// ```
#[derive(Debug)]
pub struct AtomicRw<T> {
    inner: Arc<RwLock<T>>,
    lock_callback_info: LockCallbackInfo,
}

impl<T: Default> Default for AtomicRw<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}

impl<T> From<T> for AtomicRw<T> {
    #[inline]
    fn from(t: T) -> Self {
        Self {
            inner: Arc::new(RwLock::new(t)),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}
impl<T> From<(T, Option<String>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from an optional name and an optional callback function, which
    /// is called when a lock event occurs.
    #[inline]
    fn from(v: (T, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(RwLock::new(v.0)),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, v.1, v.2),
        }
    }
}
impl<T> From<(T, Option<&str>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from a name ref and an optional callback function, which
    /// is called when a lock event occurs.
    #[inline]
    fn from(v: (T, Option<&str>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(RwLock::new(v.0)),
            lock_callback_info: LockCallbackInfo::new(
                LockType::RwLock,
                v.1.map(|s| s.to_owned()),
                v.2,
            ),
        }
    }
}

impl<T> Clone for AtomicRw<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            lock_callback_info: self.lock_callback_info.clone(),
        }
    }
}

impl<T> From<RwLock<T>> for AtomicRw<T> {
    #[inline]
    fn from(t: RwLock<T>) -> Self {
        Self {
            inner: Arc::new(t),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}
impl<T> From<(RwLock<T>, Option<String>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from a `RwLock<T>` plus an optional name
    /// and an optional callback function, which is called
    /// when a lock event occurs.
    #[inline]
    fn from(v: (RwLock<T>, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: Arc::new(v.0),
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, v.1, v.2),
        }
    }
}

impl<T> TryFrom<AtomicRw<T>> for RwLock<T> {
    type Error = Arc<RwLock<T>>;
    fn try_from(t: AtomicRw<T>) -> Result<RwLock<T>, Self::Error> {
        Arc::<RwLock<T>>::try_unwrap(t.inner)
    }
}

impl<T> From<Arc<RwLock<T>>> for AtomicRw<T> {
    #[inline]
    fn from(t: Arc<RwLock<T>>) -> Self {
        Self {
            inner: t,
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, None, None),
        }
    }
}
impl<T> From<(Arc<RwLock<T>>, Option<String>, Option<LockCallbackFn>)> for AtomicRw<T> {
    /// Create from an `Arc<RwLock<T>>` plus an optional name and
    /// an optional callback function, which is called when a lock
    /// event occurs.
    #[inline]
    fn from(v: (Arc<RwLock<T>>, Option<String>, Option<LockCallbackFn>)) -> Self {
        Self {
            inner: v.0,
            lock_callback_info: LockCallbackInfo::new(LockType::RwLock, v.1, v.2),
        }
    }
}

impl<T> From<AtomicRw<T>> for Arc<RwLock<T>> {
    #[inline]
    fn from(t: AtomicRw<T>) -> Self {
        t.inner
    }
}

// note: we impl the Atomic trait methods here also so they
// can be used without caller having to use the trait.
impl<T> AtomicRw<T> {
    /// Acquire read lock and return an `AtomicRwReadGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// let year = atomic_car.lock_guard().await.year;
    /// # })
    ///```
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_guard(&self) -> AtomicRwReadGuard<'_, T> {
        self.try_acquire_read_cb();

        let try_acquire_at = now();
        let guard = self.inner.read().await;
        AtomicRwReadGuard::new(guard, &self.lock_callback_info, try_acquire_at)
    }

    /// Acquire write lock and return an `AtomicRwWriteGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let mut atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock_guard_mut().await.year = 2022;
    /// # })
    /// ```
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_guard_mut(&mut self) -> AtomicRwWriteGuard<'_, T> {
        self.try_acquire_write_cb();

        let try_acquire_at = now();
        let guard = self.inner.write().await;
        AtomicRwWriteGuard::new(guard, &self.lock_callback_info, try_acquire_at)
    }

    /// Attempt to acquire write lock immediately.
    ///
    /// If the lock cannot be acquired without waiting, an error is returned.
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub fn try_lock_guard_mut(&mut self) -> Result<AtomicRwWriteGuard<'_, T>, TryLockError> {
        self.try_acquire_write_cb();

        let try_acquire_at = now();
        let guard = self.inner.try_write()?;
        Ok(AtomicRwWriteGuard::new(
            guard,
            &self.lock_callback_info,
            try_acquire_at,
        ))
    }

    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
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
        let inner_guard = self.inner.read().await;
        let guard = AtomicRwReadGuard::new(inner_guard, &self.lock_callback_info, try_acquire_at);
        f(&guard)
    }

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let mut atomic_car = AtomicRw::from(Car{year: 2016});
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
        let inner_guard = self.inner.write().await;
        let mut guard =
            AtomicRwWriteGuard::new(inner_guard, &self.lock_callback_info, try_acquire_at);
        f(&mut guard)
    }

    /// Immutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicRw;
    /// # use futures::future::FutureExt;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock_async(|c| async {println!("year: {}", c.year)}.boxed()).await;
    /// let year = atomic_car.lock_async(|c| async {c.year}.boxed()).await;
    /// })
    /// ```
    // design background: https://stackoverflow.com/a/77657788/10087197
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_async<R>(&self, f: impl FnOnce(&T) -> BoxFuture<'_, R>) -> R {
        self.try_acquire_read_cb();

        let try_acquire_at = now();
        let inner_guard = self.inner.read().await;
        let guard = AtomicRwReadGuard::new(inner_guard, &self.lock_callback_info, try_acquire_at);
        f(&guard).await
    }

    /// Mutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::tokio::AtomicRw;
    /// # use futures::future::FutureExt;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let mut atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock_mut_async(|mut c| async {c.year = 2022}.boxed()).await;
    /// let year = atomic_car.lock_mut_async(|mut c| async {c.year = 2023; c.year}.boxed()).await;
    /// })
    /// ```
    // design background: https://stackoverflow.com/a/77657788/10087197
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    pub async fn lock_mut_async<R>(&mut self, f: impl FnOnce(&mut T) -> BoxFuture<'_, R>) -> R {
        self.try_acquire_write_cb();

        let try_acquire_at = now();
        let inner_guard = self.inner.write().await;
        let mut guard =
            AtomicRwWriteGuard::new(inner_guard, &self.lock_callback_info, try_acquire_at);
        f(&mut guard).await
    }

    /// retrieve lock name if present, or None
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.lock_callback_info.lock_info_owned.name.as_deref()
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

    /// obtain inner Arc.
    pub fn inner(&self) -> &Arc<RwLock<T>> {
        &self.inner
    }
}

/// A wrapper for [RwLockReadGuard] that can optionally call a callback to
/// notify when the lock event occurs.
#[derive(Debug)]
pub struct AtomicRwReadGuard<'a, T> {
    guard: RwLockReadGuard<'a, T>,
    lock_callback_info: &'a LockCallbackInfo,
    try_acquire_at: Option<std::time::Instant>,
    acquire_at: Option<std::time::Instant>,
    location: Option<&'static core::panic::Location<'static>>,
}

impl<'a, T> AtomicRwReadGuard<'a, T> {
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    fn new(
        guard: RwLockReadGuard<'a, T>,
        lock_callback_info: &'a LockCallbackInfo,
        try_acquire_at: Option<std::time::Instant>,
    ) -> Self {
        let my_guard = Self {
            guard,
            lock_callback_info,
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
                acquisition: LockAcquisition::Read,
                try_acquire_at: my_guard.try_acquire_at,
                acquire_at: my_guard.acquire_at,
                location: my_guard.location,
            });
        }
        my_guard
    }
}

impl<T> Drop for AtomicRwReadGuard<'_, T> {
    fn drop(&mut self) {
        let lock_callback_info = self.lock_callback_info;
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Release {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Read,
                try_acquire_at: self.try_acquire_at,
                acquire_at: self.acquire_at,
                location: self.location,
            });
        }
    }
}

impl<T> Deref for AtomicRwReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

/// A wrapper for [RwLockWriteGuard] that can optionally call a callback to
/// notify when the lock event occurs.
#[derive(Debug)]
pub struct AtomicRwWriteGuard<'a, T> {
    guard: RwLockWriteGuard<'a, T>,
    lock_callback_info: &'a LockCallbackInfo,
    try_acquire_at: Option<std::time::Instant>,
    acquire_at: Option<std::time::Instant>,
    location: Option<&'static core::panic::Location<'static>>,
}

impl<'a, T> AtomicRwWriteGuard<'a, T> {
    #[cfg_attr(feature = "track-lock-location", track_caller)]
    fn new(
        guard: RwLockWriteGuard<'a, T>,
        lock_callback_info: &'a LockCallbackInfo,
        try_acquire_at: Option<std::time::Instant>,
    ) -> Self {
        let my_guard = Self {
            guard,
            lock_callback_info,
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
                acquisition: LockAcquisition::Write,
                try_acquire_at: my_guard.try_acquire_at,
                acquire_at: my_guard.acquire_at,
                location: my_guard.location,
            });
        }

        my_guard
    }
}

impl<T> Drop for AtomicRwWriteGuard<'_, T> {
    fn drop(&mut self) {
        let lock_callback_info = self.lock_callback_info;
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Release {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Write,
                try_acquire_at: self.try_acquire_at,
                acquire_at: self.acquire_at,
                location: self.location,
            });
        }
    }
}

impl<T> Deref for AtomicRwWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for AtomicRwWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use futures::future::FutureExt;
    use macro_rules_attr::apply;

    use super::*;
    use crate::tests::shared_tokio_runtime;

    /// Verify (compile-time) that AtomicRw::lock() and ::lock_mut() accept
    /// mutable values. (FnMut)
    #[apply(shared_tokio_runtime)]
    async fn mutable_assignment() {
        let name = "Jim".to_string();
        let mut atomic_name = AtomicRw::from(name);

        let mut new_name = String::new();
        atomic_name.lock_mut(|n| *n = "Sally".to_string()).await;
        atomic_name.lock_mut(|n| new_name = (*n).to_string()).await;
    }

    #[apply(shared_tokio_runtime)]
    async fn lock_async() {
        struct Car {
            year: u16,
        }

        let atomic_car = AtomicRw::from(Car { year: 2016 });

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
