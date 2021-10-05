use db_key::Key;
use std::convert::{From, TryInto};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeight(u64);

impl From<u64> for BlockHeight {
    fn from(item: u64) -> Self {
        BlockHeight(item)
    }
}

impl Key for BlockHeight {
    fn from_u8(key: &[u8]) -> Self {
        let val = u64::from_be_bytes(
            key.to_owned()
                .try_into()
                .expect("slice with incorrect length used as block height"),
        );
        BlockHeight(val)
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        let val = u64::to_be_bytes(self.0);
        f(&val)
    }
}
