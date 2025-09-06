use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use super::traits::Atomic;
use super::LockAcquisition;
use super::LockCallbackFn;
use super::LockCallbackInfo;
use super::LockEvent;
use super::LockType;

/// An `Arc<Mutex<T>>` wrapper to make data thread-safe and easy to work with.
///
/// # Example
/// ```
/// # use neptune_cash::application::locks::std::{AtomicMutex, traits::*};
/// struct Car {
///     year: u16,
/// }
/// let mut atomic_car = AtomicMutex::from(Car{year: 2016});
/// atomic_car.lock(|c| println!("year: {}", c.year));
/// atomic_car.lock_mut(|mut c| c.year = 2023);
/// ```
///
/// It is also possible to provide a name and callback fn
/// during instantiation.  In this way, the application
/// can easily trace lock acquisitions.
///
/// # Examples
/// ```
/// # use neptune_cash::application::locks::std::{AtomicMutex, LockEvent, LockCallbackFn};
/// struct Car {
///     year: u16,
/// }
///
/// pub fn log_lock_event(lock_event: LockEvent) {
///     let (event, info, acquisition) =
///     match lock_event {
///         LockEvent::TryAcquire{info, acquisition} => ("TryAcquire", info, acquisition),
///         LockEvent::Acquire{info, acquisition} => ("Acquire", info, acquisition),
///         LockEvent::Release{info, acquisition} => ("Release", info, acquisition),
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
/// const LOG_LOCK_EVENT_CB: LockCallbackFn = log_lock_event;
///
/// let mut atomic_car = AtomicMutex::<Car>::from((Car{year: 2016}, Some("car"), Some(LOG_LOCK_EVENT_CB)));
/// atomic_car.lock(|c| {println!("year: {}", c.year)});
/// atomic_car.lock_mut(|mut c| {c.year = 2023});
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
            lock_callback_info: self.lock_callback_info.clone(),
            inner: self.inner.clone(),
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
    /// Create from an `Mutex<T>` plus an optional name
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
    pub const fn const_new(
        t: Arc<Mutex<T>>,
        name: Option<String>,
        lock_callback_fn: Option<LockCallbackFn>,
    ) -> Self {
        Self {
            inner: t,
            lock_callback_info: LockCallbackInfo {
                lock_info_owned: super::shared::LockInfoOwned {
                    name,
                    lock_type: LockType::Mutex,
                },
                lock_callback_fn,
            },
        }
    }

    /// Acquire read lock and return an `AtomicMutexGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicMutex, traits::*};
    /// struct Car {
    ///     year: u16,
    /// }
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// let year = atomic_car.lock_guard().year;
    /// ```
    pub fn lock_guard(&self) -> AtomicMutexGuard<'_, T> {
        self.try_acquire_read_cb();
        let guard = self.inner.lock().expect("Read lock should succeed");
        AtomicMutexGuard::new(guard, &self.lock_callback_info, LockAcquisition::Read)
    }

    /// Acquire write lock and return an `AtomicMutexGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicMutex, traits::*};
    /// struct Car {
    ///     year: u16,
    /// }
    /// let mut atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_guard_mut().year = 2022;
    /// ```
    pub fn lock_guard_mut(&mut self) -> AtomicMutexGuard<'_, T> {
        self.try_acquire_write_cb();
        let guard = self.inner.lock().expect("Write lock should succeed");
        AtomicMutexGuard::new(guard, &self.lock_callback_info, LockAcquisition::Write)
    }

    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicMutex, traits::*};
    /// struct Car {
    ///     year: u16,
    /// }
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock(|c| println!("year: {}", c.year));
    /// let year = atomic_car.lock(|c| c.year);
    /// ```
    pub fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        self.try_acquire_read_cb();
        let guard = self.inner.lock().expect("Read lock should succeed");
        let my_guard =
            AtomicMutexGuard::new(guard, &self.lock_callback_info, LockAcquisition::Read);
        f(&my_guard)
    }

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicMutex, traits::*};
    /// struct Car {
    ///     year: u16,
    /// }
    /// let mut atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_mut(|mut c| {c.year = 2022});
    /// let year = atomic_car.lock_mut(|mut c| {c.year = 2023; c.year});
    /// ```
    pub fn lock_mut<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        self.try_acquire_write_cb();
        let guard = self.inner.lock().expect("Write lock should succeed");
        let mut my_guard =
            AtomicMutexGuard::new(guard, &self.lock_callback_info, LockAcquisition::Write);
        f(&mut my_guard)
    }

    /// get copy of the locked value T (if T implements Copy).
    ///
    /// # Example
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicMutex, traits::*};
    /// let atomic_u64 = AtomicMutex::from(25u64);
    /// let age = atomic_u64.get();
    /// ```
    #[inline]
    pub fn get(&self) -> T
    where
        T: Copy,
    {
        self.lock(|v| *v)
    }

    /// set the locked value T (if T implements Copy).
    ///
    /// # Example
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicMutex, traits::*};
    /// let mut atomic_bool = AtomicMutex::from(false);
    /// atomic_bool.set(true);
    /// ```
    #[inline]
    pub fn set(&mut self, value: T)
    where
        T: Copy,
    {
        self.lock_mut(|v| *v = value)
    }

    /// retrieve lock name if present, or None
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.lock_callback_info.lock_info_owned.name.as_deref()
    }

    fn try_acquire_read_cb(&self) {
        if let Some(cb) = self.lock_callback_info.lock_callback_fn {
            cb(LockEvent::TryAcquire {
                info: self.lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Read,
            });
        }
    }

    fn try_acquire_write_cb(&self) {
        if let Some(cb) = self.lock_callback_info.lock_callback_fn {
            cb(LockEvent::TryAcquire {
                info: self.lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: LockAcquisition::Write,
            });
        }
    }
}

impl<T> Atomic<T> for AtomicMutex<T> {
    #[inline]
    fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        AtomicMutex::<T>::lock(self, f)
    }

    #[inline]
    fn lock_mut<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        AtomicMutex::<T>::lock_mut(self, f)
    }
}

/// A wrapper for [MutexGuard] that can optionally call a callback to notify
/// when the lock event occurs
#[derive(Debug)]
pub struct AtomicMutexGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    lock_callback_info: &'a LockCallbackInfo,
    acquisition: LockAcquisition,
}

impl<'a, T> AtomicMutexGuard<'a, T> {
    fn new(
        guard: MutexGuard<'a, T>,
        lock_callback_info: &'a LockCallbackInfo,
        acquisition: LockAcquisition,
    ) -> Self {
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Acquire {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition,
            });
        }
        Self {
            guard,
            lock_callback_info,
            acquisition,
        }
    }
}

impl<T> Drop for AtomicMutexGuard<'_, T> {
    fn drop(&mut self) {
        let lock_callback_info = self.lock_callback_info;
        if let Some(cb) = lock_callback_info.lock_callback_fn {
            cb(LockEvent::Release {
                info: lock_callback_info.lock_info_owned.as_lock_info(),
                acquisition: self.acquisition,
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
    use super::*;

    /// Verify (compile-time) that AtomicMutex::lock() and ::lock_mut() accept
    /// mutable values. (FnMut)
    #[test]
    fn mutable_assignment() {
        let name = "Jim".to_string();
        let mut atomic_name = AtomicMutex::from(name);

        let mut new_name = String::new();
        atomic_name.lock(|n| new_name = n.to_string());
        atomic_name.lock_mut(|n| new_name = (*n).to_string());
    }
}
