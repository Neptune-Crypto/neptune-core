//! Provides a DB backed Array API that is thread-safe, uncached, and
//! non-atomic

use super::level_db::DB;
use super::utils;
use leveldb::batch::WriteBatch;
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;

type IndexType = u128;

/// Permanent storage of a fixed-length array with elements of type `T`.
#[derive(Debug, Clone)]
pub struct DatabaseArray<const N: IndexType, T: Serialize + DeserializeOwned + Default> {
    db: DB,
    _type: PhantomData<T>,
}

impl<const N: IndexType, T: Serialize + DeserializeOwned + Default> DatabaseArray<N, T> {
    /// Return the element at position index. Returns `T::defeault()` if value is unset
    #[inline]
    pub fn get(&self, index: IndexType) -> T {
        assert!(
            N > index,
            "Cannot get outside of length. Length: {N}, index: {index}"
        );
        let elem_as_bytes_res = self.db.get(&index).unwrap();
        match elem_as_bytes_res {
            Some(bytes) => utils::deserialize(&bytes),
            None => T::default(),
        }
    }

    /// set all key/val pairs in `indices_and_vals`
    pub fn batch_set(&mut self, indices_and_vals: &[(IndexType, T)]) {
        let indices: Vec<IndexType> = indices_and_vals.iter().map(|(index, _)| *index).collect();
        assert!(
            indices.iter().all(|index| *index < N),
            "All indices must be lower than length of array. Got: {indices:?}"
        );
        let batch_write = WriteBatch::new();
        for (index, val) in indices_and_vals.iter() {
            let value_bytes: Vec<u8> = utils::serialize(val);
            batch_write.put(index, &value_bytes);
        }

        self.db
            .write(&batch_write, true)
            .expect("Failed to batch-write to database");
    }

    /// Set the value at index
    #[inline]
    pub fn set(&mut self, index: IndexType, value: T) {
        assert!(
            N > index,
            "Cannot set outside of length. Length: {N}, index: {index}"
        );
        let value_bytes: Vec<u8> = utils::serialize(&value);
        self.db.put(&index, &value_bytes).unwrap();
    }

    /// Create a new, default-initialized database array. Input database must be empty.
    #[inline]
    pub fn new(db: DB) -> Self {
        Self {
            db,
            _type: PhantomData,
        }
    }

    /// Restore a database array object from a database.
    #[inline]
    pub fn restore(db: DB) -> Self {
        Self::new(db)
    }

    /// Drop the database array and return the database in which its values are stored
    #[inline]
    pub fn extract_db(self) -> DB {
        self.db
    }
}

#[cfg(test)]
mod database_array_tests {
    use super::*;

    #[test]
    fn init_and_default_values_test() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();
        assert_eq!(0u64, u64::default());
        let mut db_array: DatabaseArray<101, u64> = DatabaseArray::new(db);
        assert_eq!(0u64, db_array.get(0));
        assert_eq!(0u64, db_array.get(100));
        assert_eq!(0u64, db_array.get(42));
        db_array.set(0, 17);
        db_array.set(59, 16);
        db_array.set(80, 0);
        assert_eq!(17u64, db_array.get(0));
        assert_eq!(16u64, db_array.get(59));
        assert_eq!(0u64, db_array.get(80));
        assert_eq!(0u64, db_array.get(81));
        assert_eq!(0u64, db_array.get(79));

        // Test batch-set, verify that writes worked and that other values were unchanged
        db_array.batch_set(&[(100, 10000), (11, 1100), (12, 1200)]);
        assert_eq!(10000u64, db_array.get(100));
        assert_eq!(1100u64, db_array.get(11));
        assert_eq!(1200u64, db_array.get(12));
        assert_eq!(0u64, db_array.get(80));
        assert_eq!(0u64, db_array.get(81));
        assert_eq!(0u64, db_array.get(79));
    }

    #[should_panic = "Cannot get outside of length. Length: 101, index: 101"]
    #[test]
    fn panic_on_index_out_of_range_empty_test() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();
        let db_array: DatabaseArray<101, u64> = DatabaseArray::new(db);
        db_array.get(101);
    }

    #[should_panic = "Cannot set outside of length. Length: 50, index: 90"]
    #[test]
    fn panic_on_index_out_of_range_length_one_set_test() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut db_array: DatabaseArray<50, u64> = DatabaseArray::new(db);
        db_array.set(90, 17);
    }
}
