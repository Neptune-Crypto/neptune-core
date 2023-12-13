//! Traits that define the [`tokio_sync`](super) interface

/*
note: commenting until async-traits are supported in stable rust.
      It is supposed to be available in 1.75.0 on Dec 28, 2023.
      See: https://releases.rs/docs/1.75.0/

pub trait Atomic<T> {
    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Example
    /// ```
    /// # use neptune_core::util_types::sync::tokio::{AtomicRw, traits::*};
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.with(|c| {println!("year: {}", c.year); }).await;
    /// let year = atomic_car.with(|c| c.year).await;
    /// # })
    /// ```
    async fn with<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R;

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Example
    /// ```
    /// # use neptune_core::util_types::sync::tokio::{AtomicRw, traits::*};
    /// struct Car {
    ///     year: u16,
    /// };
    /// # tokio_test::block_on(async {
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.with_mut(|mut c| {c.year = 2022;}).await;
    /// let year = atomic_car.with_mut(|mut c| {c.year = 2023; c.year}).await;
    /// # })
    /// ```
    async fn with_mut<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R;
}
*/
