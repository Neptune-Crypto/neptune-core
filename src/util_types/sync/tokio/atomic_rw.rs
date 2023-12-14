use futures::future::BoxFuture;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// An `Arc<RwLock<T>>` wrapper to make data thread-safe and easy to work with.
///
/// # Example
/// ```
/// # use neptune_core::util_types::sync::tokio::AtomicRw;
/// struct Car {
///     year: u16,
/// };
/// # tokio_test::block_on(async {
/// let atomic_car = AtomicRw::from(Car{year: 2016});
/// atomic_car.lock(|c| {println!("year: {}", c.year)}).await;
/// atomic_car.lock_mut(|mut c| {c.year = 2023}).await;
/// # })
/// ```
#[derive(Debug, Default)]
pub struct AtomicRw<T>(Arc<RwLock<T>>);
impl<T> From<T> for AtomicRw<T> {
    #[inline]
    fn from(t: T) -> Self {
        Self(Arc::new(RwLock::new(t)))
    }
}

impl<T> Clone for AtomicRw<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> From<RwLock<T>> for AtomicRw<T> {
    #[inline]
    fn from(t: RwLock<T>) -> Self {
        Self(Arc::new(t))
    }
}

impl<T> TryFrom<AtomicRw<T>> for RwLock<T> {
    type Error = Arc<RwLock<T>>;
    fn try_from(t: AtomicRw<T>) -> Result<RwLock<T>, Self::Error> {
        Arc::<RwLock<T>>::try_unwrap(t.0)
    }
}

impl<T> From<Arc<RwLock<T>>> for AtomicRw<T> {
    #[inline]
    fn from(t: Arc<RwLock<T>>) -> Self {
        Self(t)
    }
}

impl<T> From<AtomicRw<T>> for Arc<RwLock<T>> {
    #[inline]
    fn from(t: AtomicRw<T>) -> Self {
        t.0
    }
}

// note: we impl the Atomic trait methods here also so they
// can be used without caller having to use the trait.
impl<T> AtomicRw<T> {
    /// Acquire read lock and return an `RwLockReadGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// let year = atomic_car.lock_guard().await.year;
    /// # })
    /// ```
    pub async fn lock_guard(&self) -> RwLockReadGuard<T> {
        self.0.read().await
    }

    /// Acquire write lock and return an `RwLockWriteGuard`
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock_guard_mut().await.year = 2022;
    /// # })
    /// ```
    pub async fn lock_guard_mut(&self) -> RwLockWriteGuard<T> {
        self.0.write().await
    }

    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock(|c| println!("year: {}", c.year)).await;
    /// let year = atomic_car.lock(|c| c.year).await;
    /// })
    /// ```
    pub async fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let lock = self.0.read().await;
        f(&lock)
    }

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicRw;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock_mut(|mut c| c.year = 2022).await;
    /// let year = atomic_car.lock_mut(|mut c| {c.year = 2023; c.year}).await;
    /// })
    /// ```
    pub async fn lock_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut lock = self.0.write().await;
        f(&mut lock)
    }

    /// Immutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicRw;
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
    pub async fn lock_async<R>(&self, f: impl FnOnce(&T) -> BoxFuture<'_, R>) -> R {
        let lock = self.0.read().await;
        f(&lock).await
    }

    /// Mutably access the data of type `T` in an async closure and possibly return a result of type `R`
    ///
    /// The async callback uses dynamic dispatch and it is necessary to call
    /// `.boxed()` on the closure's async block and have [`FutureExt`](futures::future::FutureExt) in scope.
    ///
    /// # Examples
    /// ```
    /// # use neptune_core::util_types::sync::tokio::AtomicRw;
    /// # use futures::future::FutureExt;
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock_mut_async(|mut c| async {c.year = 2022}.boxed()).await;
    /// let year = atomic_car.lock_mut_async(|mut c| async {c.year = 2023; c.year}.boxed()).await;
    /// })
    /// ```
    // design background: https://stackoverflow.com/a/77657788/10087197
    pub async fn lock_mut_async<R>(&self, f: impl FnOnce(&mut T) -> BoxFuture<'_, R>) -> R {
        let mut lock = self.0.write().await;
        f(&mut lock).await
    }
}

/*
note: commenting until async-traits are supported in stable rust.
      It is supposed to be available in 1.75.0 on Dec 28, 2023.
      See: https://releases.rs/docs/1.75.0/
impl<T> Atomic<T> for AtomicRw<T> {
    #[inline]
    async fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        AtomicRw::<T>:.lock(self, f).await
    }

    #[inline]
    async fn lock_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        AtomicRw::<T>:.lock_mut(self, f).await
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::FutureExt;

    #[tokio::test]
    // Verify (compile-time) that AtomicRw:.lock() and :.lock_mut() accept mutable values.  (FnMut)
    async fn mutable_assignment() {
        let name = "Jim".to_string();
        let atomic_name = AtomicRw::from(name);

        let mut new_name: String = Default::default();
        atomic_name.lock_mut(|n| *n = "Sally".to_string()).await;
        atomic_name.lock_mut(|n| new_name = n.to_string()).await;
    }

    #[tokio::test]
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
