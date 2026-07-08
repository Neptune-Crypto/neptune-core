use super::super::super::neptune_leveldb::NeptuneLevelDb;
use super::traits::StorageReader;
use super::RustyKey;
use super::RustyValue;

// Note: RustyReader and SimpleRustyReader appear to be exactly
// the same.  Can we remove one of them?

/// A read-only database interface
#[derive(Debug, Clone)]
pub struct SimpleRustyReader {
    pub(super) db: NeptuneLevelDb<RustyKey, RustyValue>,
}

impl StorageReader for SimpleRustyReader {
    #[inline]
    async fn get(&self, key: RustyKey) -> Option<RustyValue> {
        self.db.get(key).await
    }

    #[inline]
    async fn get_many(&self, keys: impl IntoIterator<Item = RustyKey>) -> Vec<Option<RustyValue>> {
        futures::future::join_all(keys.into_iter().map(|key| self.db.get(key))).await
    }
}
