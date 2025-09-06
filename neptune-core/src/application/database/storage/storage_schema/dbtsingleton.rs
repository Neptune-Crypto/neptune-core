use std::fmt::Debug;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::dbtsingleton_private::DbtSingletonPrivate;
use super::traits::*;
use super::PendingWrites;
use super::SimpleRustyReader;
use crate::application::locks::tokio::AtomicRw;

/// Singleton type created by [`super::DbtSchema`]
///
/// Data stored in a Singleton gets persisted to a
/// levelDb database.
#[derive(Debug)]
pub struct DbtSingleton<V> {
    // todo: unify inner.  no longer necessary.
    inner: DbtSingletonPrivate<V>,
}

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
    pub fn get(&self) -> V {
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
        self.inner.current_value = match self.inner.reader.get(self.inner.key.into()).await {
            Some(value) => value.into_any(),
            None => V::default(),
        };
    }
}
