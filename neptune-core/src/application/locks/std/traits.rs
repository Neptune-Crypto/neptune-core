//! Traits that define the [`locks::std`](crate::application::locks::std)
//! interface

pub trait Atomic<T> {
    /// Immutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Example
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicRw, traits::*};
    /// struct Car {
    ///     year: u16,
    /// };
    /// let atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock(|c| {println!("year: {}", c.year); });
    /// let year = atomic_car.lock(|c| c.year);
    /// ```
    fn lock<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R;

    /// Mutably access the data of type `T` in a closure and possibly return a result of type `R`
    ///
    /// # Example
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicRw, traits::*};
    /// struct Car {
    ///     year: u16,
    /// };
    /// let mut atomic_car = AtomicRw::from(Car{year: 2016});
    /// atomic_car.lock_mut(|mut c| {c.year = 2022;});
    /// let year = atomic_car.lock_mut(|mut c| {c.year = 2023; c.year});
    /// ```
    fn lock_mut<R, F>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R;

    /// get copy of the locked value T (if T implements Copy).
    ///
    /// # Example
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicRw, traits::*};
    /// let atomic_u64 = AtomicRw::from(25u64);
    /// let age = atomic_u64.get();
    /// ```
    #[inline]
    fn get(&self) -> T
    where
        T: Copy,
    {
        self.lock(|v| *v)
    }

    /// set the locked value T (if T implements Copy).
    ///
    /// # Example
    /// ```
    /// # use neptune_cash::application::locks::std::{AtomicRw, traits::*};
    /// let mut atomic_bool = AtomicRw::from(false);
    /// atomic_bool.set(true);
    /// ```
    #[inline]
    fn set(&mut self, value: T)
    where
        T: Copy,
    {
        self.lock_mut(|v| *v = value)
    }
}
