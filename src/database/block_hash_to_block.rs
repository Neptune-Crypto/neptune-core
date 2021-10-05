use db_key::Key;
use std::convert::{From, TryInto};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHash([u8; 32]);

pub const HASH_LENGTH: usize = 32;

impl From<[u8; HASH_LENGTH]> for BlockHash {
    fn from(item: [u8; HASH_LENGTH]) -> Self {
        BlockHash(item)
    }
}

impl Key for BlockHash {
    fn from_u8(key: &[u8]) -> Self {
        BlockHash(
            key.try_into()
                .expect("slice with incorrect length used as block hash"),
        )
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(&self.0)
    }
}
