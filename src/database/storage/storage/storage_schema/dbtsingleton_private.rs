use super::traits::*;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

// note: no locking is required in `DbtSingletonPrivate` because locking
// is performed in the `DbtSingleton` public wrapper.
pub(crate) struct DbtSingletonPrivate<V> {
    pub(super) key: u8,
    pub(super) current_value: V,
    pub(super) old_value: V,
    pub(super) reader: Arc<dyn StorageReader + Sync + Send>,
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

impl<V: Clone + Default> DbtSingletonPrivate<V> {
    pub(super) fn new(key: u8, reader: Arc<dyn StorageReader + Sync + Send>, name: String) -> Self {
        Self {
            key,
            current_value: Default::default(),
            old_value: Default::default(),
            reader,
            name: name.to_owned(),
        }
    }
    pub(super) fn get(&self) -> V {
        self.current_value.clone()
    }

    pub(super) fn set(&mut self, v: V) {
        self.current_value = v;
    }
}
