use super::super::level_db::DB;
use super::{traits::StorageReader, RustyKey, RustyValue};

// Note: RustyReader and SimpleRustyReader appear to be exactly
// the same.  Can we remove one of them?

/// A read-only database interface
#[derive(Debug, Clone)]
pub struct SimpleRustyReader {
    pub(super) db: DB,
}

impl StorageReader for SimpleRustyReader {
    #[inline]
    fn get(&self, key: RustyKey) -> Option<RustyValue> {
        self.db
            .get(&key.0)
            .expect("there should be some value")
            .map(RustyValue)
    }

    #[inline]
    fn get_many(&self, keys: &[RustyKey]) -> Vec<Option<RustyValue>> {
        keys.iter()
            .map(|key| {
                self.db
                    .get(&key.0)
                    .expect("there should be some value")
                    .map(RustyValue)
            })
            .collect()
    }
}
