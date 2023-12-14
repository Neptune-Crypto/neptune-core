use futures::future::BoxFuture;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

/// An `Arc<Mutex<T>>` wrapper to make data thread-safe and easy to work with.
///
/// # Example
/// ```
/// # use neptune_core::util_types::sync::tokio::AtomicMutex;
/// struct Car {
///     year: u16,
/// };
/// # tokio_test::block_on(async {
/// let atomic_car = AtomicMutex::from(Car{year: 2016});
/// atomic_car.lock(|c| println!("year: {}", c.year)).await;
/// atomic_car.lock_mut(|mut c| c.year = 2023).await;
/// # })
/// ```
#[derive(Debug, Default, Clone)]
pub struct AtomicMutex<T>(Arc<Mutex<T>>);
impl<T> From<T> for AtomicMutex<T> {
    #[inline]
    fn from(t: T) -> Self {
        Self(Arc::new(Mutex::new(t)))
    }
}

impl<T> From<Mutex<T>> for AtomicMutex<T> {
    #[inline]
    fn from(t: Mutex<T>) -> Self {
        Self(Arc::new(t))
    }
}

impl<T> TryFrom<AtomicMutex<T>> for Mutex<T> {
    type Error = Arc<Mutex<T>>;

    #[inline]
    fn try_from(t: AtomicMutex<T>) -> Result<Mutex<T>, Self::Error> {
        Arc::<Mutex<T>>::try_unwrap(t.0)
    }
}

impl<T> From<Arc<Mutex<T>>> for AtomicMutex<T> {
    #[inline]
    fn from(t: Arc<Mutex<T>>) -> Self {
        Self(t)
    }
}

impl<T> From<AtomicMutex<T>> for Arc<Mutex<T>> {
    #[inline]
    fn from(t: AtomicMutex<T>) -> Self {
        t.0
    }
}

// note: we impl the Atomic trait methods here also so they
// can be used without caller having to use the trait.
impl<T> AtomicMutex<T> {
    /// Acquire lock and return a `MutexGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicMutex;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    ///     let atomic_car = AtomicMutex::from(Car{year: 2016});
    ///     atomic_car.lock_guard_mut().await.year = 2022;
    /// # })
    /// ```
    pub async fn lock_guard_mut(&self) -> MutexGuard<T> {
        self.0.lock().await
    }

    /// Immutably access the data of type `T` in a closure and return a result
    ///
    /// # Example
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicMutex;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock(|c| println!("year: {}", c.year));
    /// let year = atomic_car.lock(|c| c.year).await;
    /// # })
    /// ```
    pub async fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let mut lock = self.0.lock().await;
        f(&mut lock)
    }

    /// Mutably access the data of type `T` in a closure and return a result
    ///
    /// # Example
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicMutex;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_mut(|mut c| c.year = 2022).await;
    /// let year = atomic_car.lock_mut(|mut c| {c.year = 2023; c.year}).await;
    /// # })
    /// ```
    pub async fn lock_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut lock = self.0.lock().await;
        f(&mut lock)
    }

    /// Immutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicMutex;
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
    pub async fn lock_async<R>(&self, f: impl FnOnce(&T) -> BoxFuture<'_, R>) -> R {
        let lock = self.0.lock().await;
        f(&lock).await
    }

    /// Mutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicMutex;
    /// # use futures::future::FutureExt;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicMutex::from(Car{year: 2016});
    /// atomic_car.lock_mut_async(|mut c| async {c.year = 2022}.boxed()).await;
    /// let year = atomic_car.lock_mut_async(|mut c| async {c.year = 2023; c.year}.boxed()).await;
    /// })
    /// ```
    // design background: https://stackoverflow.com/a/77657788/10087197
    pub async fn lock_mut_async<R>(&self, f: impl FnOnce(&mut T) -> BoxFuture<'_, R>) -> R {
        let mut lock = self.0.lock().await;
        f(&mut lock).await
    }
}

/*
    note: commenting until async-traits are supported in stable rust.
        It is supposed to be available in 1.75.0 on Dec 28, 2023.
        See: https://releases.rs/docs/1.75.0/
impl<T> Atomic<T> for AtomicMutex<T> {
    async fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        AtomicMutex::<T>:.lock(self, f).await
    }

    async fn lock_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        AtomicMutex::<T>:.lock_mut(self, f).await
    }
}
 */

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;

    #[tokio::test]
    // Verify (compile-time) that AtomicMutex:.lock() and :.lock_mut() accept mutable values.  (FnOnce)
    async fn mutable_assignment() {
        let name = "Jim".to_string();
        let atomic_name = AtomicMutex::from(name);

        let mut new_name: String = Default::default();
        atomic_name.lock(|n| new_name = n.to_string()).await;
        atomic_name.lock_mut(|n| new_name = n.to_string()).await;
    }

    #[tokio::test]
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
