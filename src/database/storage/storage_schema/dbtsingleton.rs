use std::{fmt::Debug, sync::Arc};

use super::{
    dbtsingleton_private::DbtSingletonPrivate, traits::*, PendingWrites, SimpleRustyReader,
};
use crate::locks::tokio::AtomicRw;
use serde::{de::DeserializeOwned, Serialize};

/// Singleton type created by [`super::DbtSchema`]
///
/// This type is concurrency-safe.  A single RwLock is employed
/// for all read and write ops.  Callers do not need to perform
/// any additional locking.
///
/// Also because the locking is fully encapsulated within DbtSingleton
/// there is no possibility of a caller holding a lock too long
/// by accident or encountering ordering deadlock issues.
///
/// `DbtSingleton` is a NewType around Arc<RwLock<..>>.  Thus it
/// can be cheaply cloned to create a reference as if it were an
/// Arc.
#[derive(Debug)]
pub struct DbtSingleton<V> {
    // note: Arc is not needed, because we never hand out inner to anyone.
    inner: DbtSingletonPrivate<V>,
}

// We manually impl Clone so that callers can make reference clones.
// impl<V> Clone for DbtSingleton<V> {
//     fn clone(&self) -> Self {
//         Self {
//             inner: self.inner.clone(),
//         }
//     }
// }

impl<V> DbtSingleton<V>
where
    V: Default + Clone + Serialize,
{
    // DbtSingleton can not be instantiated directly outside of storage_schema module
    // use [Schema::new_singleton()]
    #[inline]
    pub(super) fn new(
        key: u8,
        write_ops: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        name: String,
    ) -> Self {
        let singleton = DbtSingletonPrivate::<V>::new(key, write_ops, reader, name);
        Self { inner: singleton }
    }

    /// returns singleton value
    #[inline]
    pub async fn get(&self) -> V {
        self.inner.get()
    }

    /// set singleton value
    #[inline]
    pub async fn set(&mut self, t: V) {
        self.inner.set(t).await;
    }
}

#[async_trait::async_trait]
impl<V> DbTable for DbtSingleton<V>
where
    V: Clone + Default,
    V: Serialize + DeserializeOwned + Send + Sync,
{
    #[inline]
    async fn restore_or_new(&mut self) {
        // let mut inner = self.inner.lock_guard_mut().await;

        self.inner.current_value = match self.inner.reader.get(self.inner.key.into()).await {
            Some(value) => value.into_any(),
            None => V::default(),
        };
    }
}
