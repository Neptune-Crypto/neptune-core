use super::{traits::*, DbtSingleton, DbtVec, PendingWrites, SimpleRustyReader};
use crate::locks::tokio::{AtomicRw, LockCallbackFn};
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
/// Thus we get something like relational database transactions using `LevelDB`
/// key/val store.
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
/// // these writes happen atomically.
/// atomic_tables.lock_mut(|tables| {
///     tables.0.push(5);
///     tables.1.push("Sally".into());
///     tables.2.set(true);
/// });
/// ```
pub struct DbtSchema {
    /// Pending writes for all tables in this Schema.
    /// These get written/cleared by StorageWriter::persist()
    ///
    /// todo: Can we get rid of this lock?
    pub(super) pending_writes: AtomicRw<PendingWrites>,

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
    /// Instantiate a `DbtSchema` from a `SimpleRustyReader` and
    /// optional `name` and lock acquisition callback.
    /// See [AtomicRw](crate::sync::AtomicRw)
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

    /// Create a new DbtVec
    ///
    /// All pending write operations of the DbtVec are stored
    /// in the schema
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
    /// All pending write operations of the DbtSingleton are stored
    /// in the schema
    #[inline]
    pub async fn new_singleton<V>(&mut self, name: impl Into<String> + Display) -> DbtSingleton<V>
    where
        V: Default + Clone + 'static,
        V: Serialize + DeserializeOwned + Send + Sync,
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
}