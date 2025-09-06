use std::fmt::Debug;
use std::fmt::Formatter;
use std::sync::Arc;

use serde::Serialize;

use super::PendingWrites;
use super::RustyValue;
use super::SimpleRustyReader;
use super::WriteOperation;
use crate::application::locks::tokio::AtomicRw;

// note: no locking is required in `DbtSingletonPrivate` because locking
// is performed in the `DbtSingleton` public wrapper.
pub(super) struct DbtSingletonPrivate<V> {
    pub(super) pending_writes: AtomicRw<PendingWrites>,
    pub(super) key: u8,
    pub(super) current_value: V,
    pub(super) old_value: V,
    pub(super) reader: Arc<SimpleRustyReader>,
    pub(super) name: String,
}

impl<V> Debug for DbtSingletonPrivate<V>
where
    V: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("DbtSingletonPrivate")
            .field("key", &self.key)
            .field("current_value", &self.current_value)
            .field("old_value", &self.old_value)
            .field("reader", &"Arc<dyn StorageReader + Send + Sync>")
            .field("name", &self.name)
            .finish()
    }
}

impl<V: Clone + Default + Serialize> DbtSingletonPrivate<V> {
    pub(super) fn new(
        key: u8,
        pending_writes: AtomicRw<PendingWrites>,
        reader: Arc<SimpleRustyReader>,
        name: String,
    ) -> Self {
        Self {
            key,
            current_value: Default::default(),
            old_value: Default::default(),
            pending_writes,
            reader,
            name: name.to_owned(),
        }
    }
    pub(super) fn get(&self) -> V {
        self.current_value.clone()
    }

    pub(super) async fn set(&mut self, v: V) {
        self.pending_writes
            .lock_guard_mut()
            .await
            .write_ops
            .push(WriteOperation::Write(
                self.key.into(),
                RustyValue::from_any(&v),
            ));

        self.current_value = v;
    }
}
