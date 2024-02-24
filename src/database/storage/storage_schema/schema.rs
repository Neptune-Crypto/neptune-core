// use super::super::storage_vec::Index;
use super::{traits::*, DbtSingleton, DbtVec, PendingWrites, SimpleRustyReader};
use crate::locks::tokio::{AtomicMutex, AtomicRw, LockCallbackFn};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt::Display, sync::Arc};

/// Provides a virtual database schema.
///
/// `DbtSchema` can create any number of instances of types that
/// implement the trait [`DbTable`].  We refer to these instances as
/// `table`.  Examples are [`DbtVec`] and [`DbtSingleton`].
///
/// With proper usage (below), the application can perform writes
/// to any subset of the `table`s and then persist (write) the data
/// atomically to the database.
///
/// Thus we get something like relational NeptuneLevelDb transactions using
/// `LevelNeptuneLevelDb` key/val store.
///
/// ### Atomicity -- Single Table:
///
/// An individual `table` is atomic for all read and write
/// operations to itself.
///
/// ### Atomicity -- Multi Table:
///
/// Important!  Operations over multiple `table`s are NOT atomic
/// without additional locking by the application.
///
/// This can be achieved by placing the `table`s into a heterogenous
/// container such as a `struct` or `tuple`. Then place an
/// `Arc<Mutex<..>>` or `Arc<Mutex<RwLock<..>>` around the container.
///
/// # Example:
///
/// ```
/// # use crate::database::storage::{level_db, storage_vec::traits::*, storage_schema::{SimpleRustyStorage, traits::*}};
/// # let db = level_db::NeptuneLevelDb::open_new_test_database(true, None, None, None).await.unwrap();
/// use std::sync::{Arc, RwLock};
/// let mut storage = SimpleRustyStorage::new(db);
///
/// let tables = (
///     storage.schema.new_vec::<u16>("ages"),
///     storage.schema.new_vec::<String>("names"),
///     storage.schema.new_singleton::<bool>("proceed")
/// );
///
/// storage.restore_or_new();  // populate tables.
///
/// let mut atomic_tables = Arc::new(RwLock::new(tables));
/// let mut lock = atomic_tables.write().unwrap();
/// lock.0.push(5);
/// lock.1.push("Sally".into());
/// lock.2.set(true);
/// ```
///
/// In the example, the `table` were placed in a `tuple` container.
/// It works equally well to put them in a `struct`.  If the tables
/// are all of the same type (including generics), they could be
/// placed in a collection type such as `Vec`, or `HashMap`.
///
/// This crate provides [`AtomicRw`] and [`AtomicMutex`]
/// which are simple wrappers around `Arc<RwLock<T>>` and `Arc<Mutex<T>>`.
/// `DbtSchema` provides helper methods for wrapping your `table`s with
/// these.
///
/// This is the recommended usage.
///
/// # Example:
///
/// ```rust
/// # use crate::database::storage::{level_db, storage_vec::traits::*, storage_schema::{SimpleRustyStorage, traits::*}};
/// # let db = level_db::NeptuneLevelDb::open_new_test_database(true, None, None, None).await.unwrap();
/// let mut storage = SimpleRustyStorage::new(db);
///
/// let mut atomic_tables = storage.schema.create_tables_rw(|s| {
///     (
///         s.new_vec::<u16>("ages"),
///         s.new_vec::<String>("names"),
///         s.new_singleton::<bool>("proceed")
///     )
/// });
///
/// storage.restore_or_new();  // populate tables.
///
/// // these writes happen atomically.
/// atomic_tables.lock_mut(|tables| {
///     tables.0.push(5);
///     tables.1.push("Sally".into());
///     tables.2.set(true);
/// });
/// ```
pub struct DbtSchema {
    /// These are the tables known by this `DbtSchema` instance.
    ///
    /// Implementor(s) of [`StorageWriter`] will iterate over these
    /// tables, collect the pending operations, and write them
    /// atomically to the NeptuneLevelDb.
    pub pending_writes: AtomicRw<PendingWrites>,

    /// Database Reader
    pub reader: Arc<SimpleRustyReader>,

    /// If present, the provided callback function will be called
    /// whenever a lock is acquired by a `DbTable` instantiated
    /// by this `DbtSchema`.  See [AtomicRw](crate::sync::AtomicRw)
    pub lock_callback_fn: Option<LockCallbackFn>,

    /// indicates count of tables in this schema
    pub table_count: u8,
}

impl DbtSchema {
    /// Instantiate a `DbtSchema` from an `Arc<Reader` and
    /// optional `name` and lock acquisition callback.
    /// See See [AtomicRw](crate::sync::AtomicRw)
    pub fn new(
        reader: SimpleRustyReader,
        name: Option<&str>,
        lock_callback_fn: Option<LockCallbackFn>,
    ) -> Self {
        Self {
            pending_writes: AtomicRw::from((PendingWrites::default(), name, lock_callback_fn)),
            reader: Arc::new(reader),
            lock_callback_fn,
            table_count: 0,
        }
    }
}

impl DbtSchema {
    /// Create a new DbtVec
    ///
    /// The `DbtSchema` will keep a reference to the `DbtVec`. In this way,
    /// the Schema becomes aware of any write operations and later
    /// a [`StorageWriter`] impl can write them all out.
    ///
    /// Atomicity: see [`DbtSchema`]
    #[inline]
    pub async fn new_vec<V>(&mut self, name: &str) -> DbtVec<V>
    where
        V: Clone + 'static,
        V: Serialize + DeserializeOwned + Send + Sync,
    {
        let pending_writes = self.pending_writes.clone();
        let reader = self.reader.clone();
        let key_prefix = self.table_count;
        self.table_count += 1;

        let mut vector = DbtVec::<V>::new(pending_writes, reader, key_prefix, name).await;
        vector.restore_or_new().await;

        vector
    }

    // possible future extension
    // fn new_hashmap<K, V>(&self) -> Arc<RefCell<DbtHashMap<K, V>>> { }

    /// Create a new DbtSingleton
    ///
    /// The `DbtSchema` will keep a reference to the `DbtSingleton`.
    /// In this way, the Schema becomes aware of any write operations
    /// and later a [`StorageWriter`] impl can write them all out.
    ///
    /// Atomicity: see [`DbtSchema`]
    #[inline]
    pub async fn new_singleton<V>(&mut self, name: impl Into<String> + Display) -> DbtSingleton<V>
    where
        V: Default + Clone + 'static,
        V: Serialize + DeserializeOwned + Send + Sync,
        // DbtSingleton<V>: DbTable + Send + Sync,
    {
        let key = self.table_count;
        self.table_count += 1;

        let mut singleton = DbtSingleton::<V>::new(
            key,
            self.pending_writes.clone(),
            self.reader.clone(),
            name.into(),
        );
        singleton.restore_or_new().await;
        singleton
    }

    /// create tables and wrap in an [`AtomicRw<T>`]
    ///
    /// This is the recommended way to create a group of tables
    /// that are atomic for reads and writes across tables.
    ///
    /// Atomicity is guaranteed by an [`RwLock`](std::sync::RwLock).
    ///
    /// # Example:
    ///
    /// ```rust
    /// # use crate::database::storage::{level_db, storage_vec::traits::*, storage_schema::{SimpleRustyStorage, traits::*}};
    /// # let db = level_db::NeptuneLevelDb::open_new_test_database(true, None, None, None).await.unwrap();
    /// let mut storage = SimpleRustyStorage::new(db);
    ///
    /// let mut atomic_tables = storage.schema.create_tables_rw(|s| {
    ///     (
    ///         s.new_vec::<u16>("ages"),
    ///         s.new_vec::<String>("names"),
    ///         s.new_singleton::<bool>("proceed")
    ///     )
    /// });
    ///
    /// storage.restore_or_new();  // populate tables.
    ///
    /// // these writes happen atomically.
    /// atomic_tables.lock_mut(|tables| {
    ///     tables.0.push(5);
    ///     tables.1.push("Sally".into());
    ///     tables.2.set(true);
    /// });
    /// ```
    pub fn create_tables_rw<D, F>(&mut self, f: F) -> AtomicRw<D>
    where
        F: Fn(&mut Self) -> D,
    {
        let data = f(self);
        AtomicRw::<D>::from(data)
    }

    /// create tables and wrap in an [`AtomicMutex<T>`]
    ///
    /// This is a simple way to create a group of tables
    /// that are atomic for reads and writes across tables.
    ///
    /// Atomicity is guaranteed by a [`Mutex`](std::sync::Mutex).
    ///
    /// # Example:
    ///
    /// ```rust
    /// # use crate::database::storage::{level_db, storage_vec::traits::*, storage_schema::{SimpleRustyStorage, traits::*}};
    /// # let db = level_db::NeptuneLevelDb::open_new_test_database(true, None, None, None).await.unwrap();
    /// let mut storage = SimpleRustyStorage::new(db);
    ///
    /// let mut atomic_tables = storage.schema.create_tables_mutex(|s| {
    ///     (
    ///         s.new_vec::<u16>("ages"),
    ///         s.new_vec::<String>("names"),
    ///         s.new_singleton::<bool>("proceed")
    ///     )
    /// });
    ///
    /// storage.restore_or_new();  // populate tables.
    ///
    /// // these writes happen atomically.
    /// atomic_tables.lock_mut(|tables| {
    ///     tables.0.push(5);
    ///     tables.1.push("Sally".into());
    ///     tables.2.set(true);
    /// });
    /// ```
    pub fn create_tables_mutex<D, F>(&mut self, f: F) -> AtomicMutex<D>
    where
        F: Fn(&mut Self) -> D,
    {
        let data = f(self);
        AtomicMutex::<D>::from(data)
    }

    /// Wraps input of type `T` with a [`AtomicRw`]
    ///
    /// note: method [`create_tables_rw()`](Self::create_tables_rw()) is a simpler alternative.
    ///
    /// # Example:
    ///
    /// ```
    /// # use crate::database::storage::{level_db, storage_vec::traits::*, storage_schema::{DbtSchema, SimpleRustyStorage, traits::*}};
    /// # let db = level_db::NeptuneLevelDb::open_new_test_database(true, None, None, None).await.unwrap();
    /// let mut storage = SimpleRustyStorage::new(db);
    ///
    /// let ages = storage.schema.new_vec::<u16>("ages");
    /// let names = storage.schema.new_vec::<String>("names");
    /// let proceed = storage.schema.new_singleton::<bool>("proceed");
    ///
    /// storage.restore_or_new();  // populate tables.
    ///
    /// let tables = (ages, names, proceed);
    /// let mut atomic_tables = storage.schema.atomic_rw(tables);
    ///
    /// // these writes happen atomically.
    /// atomic_tables.lock_mut(|tables| {
    ///     tables.0.push(5);
    ///     tables.1.push("Sally".into());
    ///     tables.2.set(true);
    /// });
    /// ```
    pub fn atomic_rw<T>(&self, data: T) -> AtomicRw<T> {
        AtomicRw::from(data)
    }

    /// Wraps input of type `T` with a [`AtomicMutex`]
    ///
    /// note: method [`create_tables_mutex()`](Self::create_tables_mutex()) is a simpler alternative.
    ///
    /// # Example:
    ///
    /// ```
    /// # use crate::database::storage::{level_db, storage_vec::traits::*, storage_schema::{DbtSchema, SimpleRustyStorage, traits::*}};
    /// # let db = level_db::NeptuneLevelDb::open_new_test_database(true, None, None, None).await.unwrap();
    /// let mut storage = SimpleRustyStorage::new(db);
    ///
    /// let ages = storage.schema.new_vec::<u16>("ages");
    /// let names = storage.schema.new_vec::<String>("names");
    /// let proceed = storage.schema.new_singleton::<bool>("proceed");
    ///
    /// storage.restore_or_new();  // populate tables.
    ///
    /// let tables = (ages, names, proceed);
    /// let mut atomic_tables = storage.schema.atomic_mutex(tables);
    ///
    /// // these writes happen atomically.
    /// atomic_tables.lock_mut(|tables| {
    ///     tables.0.push(5);
    ///     tables.1.push("Sally".into());
    ///     tables.2.set(true);
    /// });
    /// ```
    pub fn atomic_mutex<T>(&self, data: T) -> AtomicMutex<T> {
        AtomicMutex::from(data)
    }
}
