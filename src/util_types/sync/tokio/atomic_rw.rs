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
/// atomic_car.with(|c| {println!("year: {}", c.year)}).await;
/// atomic_car.with_mut(|mut c| {c.year = 2023}).await;
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
    /// let year = atomic_car.guard().await.year;
    /// # })
    /// ```
    pub async fn guard(&self) -> RwLockReadGuard<T> {
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
    /// atomic_car.guard_mut().await.year = 2022;
    /// # })
    /// ```
    pub async fn guard_mut(&self) -> RwLockWriteGuard<T> {
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
    /// atomic_car.with(|c| println!("year: {}", c.year)).await;
    /// let year = atomic_car.with(|c| c.year).await;
    /// })
    /// ```
    pub async fn with<R, F>(&self, f: F) -> R
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
    /// atomic_car.with_mut(|mut c| c.year = 2022).await;
    /// let year = atomic_car.with_mut(|mut c| {c.year = 2023; c.year}).await;
    /// })
    /// ```
    pub async fn with_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut lock = self.0.write().await;
        f(&mut lock)
    }
}

/*
note: commenting until async-traits are supported in stable rust.
      It is supposed to be available in 1.75.0 on Dec 28, 2023.
      See: https://releases.rs/docs/1.75.0/
impl<T> Atomic<T> for AtomicRw<T> {
    #[inline]
    async fn with<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        AtomicRw::<T>::with(self, f).await
    }

    #[inline]
    async fn with_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        AtomicRw::<T>::with_mut(self, f).await
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    // Verify (compile-time) that AtomicRw::with() and ::with_mut() accept mutable values.  (FnMut)
    async fn mutable_assignment() {
        let name = "Jim".to_string();
        let atomic_name = AtomicRw::from(name);

        let mut new_name: String = Default::default();
        atomic_name.with_mut(|n| *n = "Sally".to_string()).await;
        atomic_name.with_mut(|n| new_name = n.to_string()).await;
    }
}
