use super::level_db::DB;
use super::storage_vec::Index;
use serde::de::DeserializeOwned;

#[inline]
pub(super) fn serialize<B>(b: &B) -> Vec<u8>
where
    B: ?Sized + serde::Serialize,
{
    bincode::serialize(b).expect("should have serialized value")
}

#[inline]
pub(super) fn deserialize<'b, B>(bytes: &'b [u8]) -> B
where
    B: serde::de::Deserialize<'b>,
{
    bincode::deserialize(bytes).expect("should have deserialized value")
}

#[inline]
pub(super) fn get_u8_option(db: &DB, index: &[u8], name: &str) -> Option<Vec<u8>> {
    db.get_u8(index).unwrap_or_else(|e| {
        panic!(
            "DB Error retrieving index {} of {}. error: {}",
            deserialize::<Index>(index),
            name,
            e
        )
    })
}

#[inline]
pub(super) fn get_u8<T: DeserializeOwned>(db: &DB, index: &[u8], name: &str) -> T {
    let db_val = get_u8_option(db, index, name).unwrap_or_else(|| {
        panic!(
            "Element with index {} does not exist in {}. This should not happen",
            deserialize::<Index>(index),
            name
        )
    });
    deserialize(&db_val)
}
