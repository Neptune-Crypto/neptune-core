//! LevelDB provides atomic writes to a database.  However each database is a
//! simple key/value store.  There is no logical sub-unit of a database that we
//! might call a "Table" or `struct`.
//!
//! This makes it difficult for rust code to have multiple `struct` stored in a
//! single DB with atomic updates.
//!
//! This module provides a virtual DB Schema with logical "tables" that are
//! backed by key/val pairs in a single LevelDB database.
//!
//! Atomic writes are supported across multiple "tables".
//!
//! [`DbtSchema`] that can generate any number of [`DbtVec`] and
//! [`DbtSingleton`] collection types.
//!
//! Mutating operations to these "tables" are cached and written to the database
//! in a single atomic batch operation.
//!
//! Important: write operations are not written until
//! SimpleRustyStorage::persist() is called.

mod dbtsingleton;
mod dbtsingleton_private;
mod dbtvec;
mod dbtvec_private;
mod enums;
mod pending_writes;
mod rusty_key;
mod rusty_reader;
mod rusty_value;
mod schema;
mod simple_rusty_reader;
mod simple_rusty_storage;
pub mod traits;

pub use dbtsingleton::*;
pub use dbtvec::*;
pub use enums::*;
use pending_writes::*;
pub use rusty_key::*;
pub use rusty_reader::*;
pub use rusty_value::*;
pub use schema::*;
pub use simple_rusty_reader::*;
pub use simple_rusty_storage::*;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::random;
    use rand::Rng;
    use rand::RngCore;
    use serde::Deserialize;
    use serde::Serialize;

    use super::super::storage_vec::traits::*;
    use super::super::storage_vec::Index;
    use super::traits::*;
    use super::*;
    use crate::application::database::NeptuneLevelDb;
    use crate::tests::shared_tokio_runtime;
    use crate::twenty_first::math::other::random_elements;

    #[derive(Default, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
    struct S(Vec<u8>);
    impl From<Vec<u8>> for S {
        fn from(value: Vec<u8>) -> Self {
            S(value)
        }
    }
    impl From<S> for Vec<u8> {
        fn from(value: S) -> Self {
            value.0
        }
    }
    impl From<(S, S)> for S {
        fn from(value: (S, S)) -> Self {
            let vector0: Vec<u8> = value.0.into();
            let vector1: Vec<u8> = value.1.into();
            S([vector0, vector1].concat())
        }
    }
    impl From<S> for u64 {
        fn from(value: S) -> Self {
            u64::from_be_bytes(value.0.try_into().unwrap())
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn test_simple_singleton() {
        let singleton_value = S([1u8, 3u8, 3u8, 7u8].to_vec());

        // open new NeptuneLevelDb that will not be dropped on close.
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let db_path = db.path().clone();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        assert_eq!(1, Arc::strong_count(&rusty_storage.schema.reader));
        let mut singleton = rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned())
            .await;
        assert_eq!(2, Arc::strong_count(&rusty_storage.schema.reader));

        // test
        assert_eq!(singleton.get(), S([].to_vec()));

        // set
        singleton.set(singleton_value.clone()).await;

        // test
        assert_eq!(singleton.get(), singleton_value);

        // persist
        rusty_storage.persist().await;

        // test
        assert_eq!(singleton.get(), singleton_value);

        assert_eq!(2, Arc::strong_count(&rusty_storage.schema.reader));

        // This is just so we can count reader references
        // after rusty_storage is dropped.
        let reader_ref = rusty_storage.schema.reader.clone();
        assert_eq!(3, Arc::strong_count(&reader_ref));

        // drop
        drop(rusty_storage); // <--- 1 reader ref dropped.
        assert_eq!(2, Arc::strong_count(&reader_ref));

        drop(singleton); //     <--- 1 reader ref dropped
        assert_eq!(1, Arc::strong_count(&reader_ref));

        drop(reader_ref); // <--- Final reader ref dropped. Db closes.

        // restore.  re-open existing NeptuneLevelDb.
        let new_db = NeptuneLevelDb::open_test_database(&db_path, true, None, None, None)
            .await
            .unwrap();
        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let new_singleton = new_rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned())
            .await;

        // test
        assert_eq!(new_singleton.get(), singleton_value);
    }

    #[apply(shared_tokio_runtime)]
    async fn test_simple_vector() {
        // open new NeptuneLevelDb that will not be dropped on close.
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let db_path = db.path().clone();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector").await;

        // should work to pass empty array, when vector.is_empty() == true
        vector.set_all([]).await;

        // test `get_all`
        assert!(
            vector.get_all().await.is_empty(),
            "`get_all` on unpopulated vector must return empty vector"
        );

        // populate
        vector.push(S([1u8].to_vec())).await;
        vector.push(S([3u8].to_vec())).await;
        vector.push(S([4u8].to_vec())).await;
        vector.push(S([7u8].to_vec())).await;
        vector.push(S([8u8].to_vec())).await;

        // test `get`
        assert_eq!(vector.get(0).await, S([1u8].to_vec()));
        assert_eq!(vector.get(1).await, S([3u8].to_vec()));
        assert_eq!(vector.get(2).await, S([4u8].to_vec()));
        assert_eq!(vector.get(3).await, S([7u8].to_vec()));
        assert_eq!(vector.get(4).await, S([8u8].to_vec()));
        assert_eq!(vector.len().await, 5);

        // test `get_many`
        assert_eq!(
            vector.get_many(&[0, 2, 3]).await,
            vec![
                vector.get(0).await,
                vector.get(2).await,
                vector.get(3).await
            ]
        );
        assert_eq!(
            vector.get_many(&[2, 3, 0]).await,
            vec![
                vector.get(2).await,
                vector.get(3).await,
                vector.get(0).await
            ]
        );
        assert_eq!(
            vector.get_many(&[3, 0, 2]).await,
            vec![
                vector.get(3).await,
                vector.get(0).await,
                vector.get(2).await
            ]
        );
        assert_eq!(
            vector.get_many(&[0, 1, 2, 3, 4]).await,
            vec![
                vector.get(0).await,
                vector.get(1).await,
                vector.get(2).await,
                vector.get(3).await,
                vector.get(4).await,
            ]
        );
        assert_eq!(vector.get_many(&[]).await, vec![]);
        assert_eq!(vector.get_many(&[3]).await, vec![vector.get(3).await]);

        // We allow `get_many` to take repeated indices.
        assert_eq!(vector.get_many(&[3; 0]).await, vec![]);
        assert_eq!(vector.get_many(&[3; 1]).await, vec![vector.get(3).await; 1]);
        assert_eq!(vector.get_many(&[3; 2]).await, vec![vector.get(3).await; 2]);
        assert_eq!(vector.get_many(&[3; 3]).await, vec![vector.get(3).await; 3]);
        assert_eq!(vector.get_many(&[3; 4]).await, vec![vector.get(3).await; 4]);
        assert_eq!(vector.get_many(&[3; 5]).await, vec![vector.get(3).await; 5]);
        assert_eq!(
            vector.get_many(&[3, 3, 2, 3]).await,
            vec![
                vector.get(3).await,
                vector.get(3).await,
                vector.get(2).await,
                vector.get(3).await
            ]
        );

        // at this point, `vector` should contain:
        let expect_values = vec![
            S([1u8].to_vec()),
            S([3u8].to_vec()),
            S([4u8].to_vec()),
            S([7u8].to_vec()),
            S([8u8].to_vec()),
        ];

        // test `get_all`
        assert_eq!(
            expect_values,
            vector.get_all().await,
            "`get_all` must return expected values"
        );

        // test roundtrip through `set_all`, `get_all`
        let values_tmp = vec![
            S([2u8].to_vec()),
            S([4u8].to_vec()),
            S([6u8].to_vec()),
            S([8u8].to_vec()),
            S([9u8].to_vec()),
        ];
        vector.set_all(values_tmp.clone()).await;

        assert_eq!(
            values_tmp,
            vector.get_all().await,
            "`get_all` must return values passed to `set_all`",
        );

        vector.set_all(expect_values.clone()).await;

        // persist
        rusty_storage.persist().await;

        // test `get_all` after persist
        assert_eq!(
            expect_values,
            vector.get_all().await,
            "`get_all` must return expected values after persist"
        );

        // modify
        let last = vector.pop().await.unwrap();

        // test
        assert_eq!(last, S([8u8].to_vec()));

        // drop without persisting
        drop(rusty_storage); // <--- DB ref dropped.
        drop(vector); //        <--- Final DB ref dropped. NeptuneLevelDb closes

        // Open existing database.
        let new_db = NeptuneLevelDb::open_test_database(&db_path, true, None, None, None)
            .await
            .unwrap();

        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let mut new_vector = new_rusty_storage.schema.new_vec::<S>("test-vector").await;

        // modify
        new_vector.set(2, S([3u8].to_vec())).await;

        let last_again = new_vector.pop().await.unwrap();
        assert_eq!(last_again, S([8u8].to_vec()));

        // test
        assert_eq!(new_vector.get(0).await, S([1u8].to_vec()));
        assert_eq!(new_vector.get(1).await, S([3u8].to_vec()));
        assert_eq!(new_vector.get(2).await, S([3u8].to_vec()));
        assert_eq!(new_vector.get(3).await, S([7u8].to_vec()));
        assert_eq!(new_vector.len().await, 4);

        // test `get_many`, ensure that output matches input ordering
        assert_eq!(
            new_vector.get_many(&[2]).await,
            vec![new_vector.get(2).await]
        );
        assert_eq!(
            new_vector.get_many(&[3, 1, 0]).await,
            vec![
                new_vector.get(3).await,
                new_vector.get(1).await,
                new_vector.get(0).await
            ]
        );
        assert_eq!(
            new_vector.get_many(&[0, 2, 3]).await,
            vec![
                new_vector.get(0).await,
                new_vector.get(2).await,
                new_vector.get(3).await
            ]
        );
        assert_eq!(
            new_vector.get_many(&[0, 1, 2, 3]).await,
            vec![
                new_vector.get(0).await,
                new_vector.get(1).await,
                new_vector.get(2).await,
                new_vector.get(3).await,
            ]
        );
        assert_eq!(new_vector.get_many(&[]).await, vec![]);
        assert_eq!(
            new_vector.get_many(&[3]).await,
            vec![new_vector.get(3).await]
        );

        // We allow `get_many` to take repeated indices.
        assert_eq!(new_vector.get_many(&[3; 0]).await, vec![]);
        assert_eq!(
            new_vector.get_many(&[3; 1]).await,
            vec![new_vector.get(3).await; 1]
        );
        assert_eq!(
            new_vector.get_many(&[3; 2]).await,
            vec![new_vector.get(3).await; 2]
        );
        assert_eq!(
            new_vector.get_many(&[3; 3]).await,
            vec![new_vector.get(3).await; 3]
        );
        assert_eq!(
            new_vector.get_many(&[3; 4]).await,
            vec![new_vector.get(3).await; 4]
        );
        assert_eq!(
            new_vector.get_many(&[3; 5]).await,
            vec![new_vector.get(3).await; 5]
        );

        // test `get_all`
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([3u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector.get_all().await,
            "`get_all` must return expected values"
        );

        new_vector.set(1, S([130u8].to_vec())).await;
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([130u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector.get_all().await,
            "`get_all` must return expected values, after mutation"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn test_dbtcvecs_get_many() {
        const TEST_LIST_LENGTH: u8 = 105;

        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector").await;

        // populate
        for i in 0u8..TEST_LIST_LENGTH {
            vector.push(S(vec![i, i, i])).await;
        }

        let read_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % u64::from(TEST_LIST_LENGTH))
            .collect();
        let values = vector.get_many(&read_indices).await;
        assert!(read_indices
            .iter()
            .zip(values)
            .all(|(index, value)| value == S(vec![*index as u8, *index as u8, *index as u8])));

        // Mutate some indices
        let mutate_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % u64::from(TEST_LIST_LENGTH))
            .collect();
        for index in &mutate_indices {
            vector
                .set(
                    *index,
                    S(vec![*index as u8 + 1, *index as u8 + 1, *index as u8 + 1]),
                )
                .await
        }

        let new_values = vector.get_many(&read_indices).await;
        for (value, index) in new_values.into_iter().zip(read_indices) {
            if mutate_indices.contains(&index) {
                assert_eq!(
                    S(vec![index as u8 + 1, index as u8 + 1, index as u8 + 1]),
                    value
                )
            } else {
                assert_eq!(S(vec![index as u8, index as u8, index as u8]), value)
            }
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn test_dbtcvecs_set_many_get_many() {
        const TEST_LIST_LENGTH: u8 = 105;

        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        // initialize storage
        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector").await;

        // Generate initial index/value pairs.
        let init_keyvals: Vec<(Index, S)> = (0u8..TEST_LIST_LENGTH)
            .map(|i| (Index::from(i), S(vec![i, i, i])))
            .collect();

        // set_many() does not grow the list, so we must first push
        // some empty elems, to desired length.
        for _ in 0u8..TEST_LIST_LENGTH {
            vector.push(S(vec![])).await;
        }

        // set the initial values
        vector.set_many(init_keyvals).await;

        // generate some random indices to read
        let read_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % u64::from(TEST_LIST_LENGTH))
            .collect();

        // perform read, and validate as expected
        let values = vector.get_many(&read_indices).await;
        assert!(read_indices
            .iter()
            .zip(values)
            .all(|(index, value)| value == S(vec![*index as u8, *index as u8, *index as u8])));

        // Generate some random indices for mutation
        let mutate_indices: Vec<u64> = random_elements::<u64>(30)
            .iter()
            .map(|x| x % u64::from(TEST_LIST_LENGTH))
            .collect();

        // Generate keyvals for mutation
        let mutate_keyvals: Vec<(Index, S)> = mutate_indices
            .iter()
            .map(|index| {
                let val = (index % u64::from(TEST_LIST_LENGTH) + 1) as u8;
                (*index, S(vec![val, val, val]))
            })
            .collect();

        // Mutate values at randomly generated indices
        vector.set_many(mutate_keyvals).await;

        // Verify mutated values, and non-mutated also.
        let new_values = vector.get_many(&read_indices).await;
        for (value, index) in new_values.into_iter().zip(read_indices.clone()) {
            if mutate_indices.contains(&index) {
                assert_eq!(
                    S(vec![index as u8 + 1, index as u8 + 1, index as u8 + 1]),
                    value
                )
            } else {
                assert_eq!(S(vec![index as u8, index as u8, index as u8]), value)
            }
        }

        // Persist and verify that result is unchanged
        rusty_storage.persist().await;
        let new_values_after_persist = vector.get_many(&read_indices).await;
        for (value, index) in new_values_after_persist.into_iter().zip(read_indices) {
            if mutate_indices.contains(&index) {
                assert_eq!(
                    S(vec![index as u8 + 1, index as u8 + 1, index as u8 + 1]),
                    value
                )
            } else {
                assert_eq!(S(vec![index as u8, index as u8, index as u8]), value)
            }
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn test_dbtcvecs_set_all_get_many() {
        const TEST_LIST_LENGTH: u8 = 105;

        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        // initialize storage
        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector").await;

        // Generate initial index/value pairs.
        let init_vals: Vec<S> = (0u8..TEST_LIST_LENGTH).map(|i| S(vec![i, i, i])).collect();

        let mut mutate_vals = init_vals.clone(); // for later

        // set_all() does not grow the list, so we must first push
        // some empty elems, to desired length.
        for _ in 0u8..TEST_LIST_LENGTH {
            vector.push(S(vec![])).await;
        }

        // set the initial values
        vector.set_all(init_vals).await;

        // generate some random indices to read
        let read_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % u64::from(TEST_LIST_LENGTH))
            .collect();

        // perform read, and validate as expected
        let values = vector.get_many(&read_indices).await;
        assert!(read_indices
            .iter()
            .zip(values)
            .all(|(index, value)| value == S(vec![*index as u8, *index as u8, *index as u8])));

        // Generate some random indices for mutation
        let mutate_indices: Vec<u64> = random_elements::<u64>(30)
            .iter()
            .map(|x| x % u64::from(TEST_LIST_LENGTH))
            .collect();

        // Generate vals for mutation
        for index in &mutate_indices {
            let val = (index % u64::from(TEST_LIST_LENGTH) + 1) as u8;
            mutate_vals[*index as usize] = S(vec![val, val, val]);
        }

        // Mutate values at randomly generated indices
        vector.set_all(mutate_vals).await;

        // Verify mutated values, and non-mutated also.
        let new_values = vector.get_many(&read_indices).await;
        for (value, index) in new_values.into_iter().zip(read_indices) {
            if mutate_indices.contains(&index) {
                assert_eq!(
                    S(vec![index as u8 + 1, index as u8 + 1, index as u8 + 1]),
                    value
                )
            } else {
                assert_eq!(S(vec![index as u8, index as u8, index as u8]), value)
            }
        }
    }

    #[apply(shared_tokio_runtime)]
    async fn storage_schema_vector_pbt() {
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut persisted_vector = rusty_storage.schema.new_vec::<u64>("test-vector").await;

        // Insert 1000 elements
        let mut rng = rand::rng();
        let mut normal_vector = vec![];
        for _ in 0..1000 {
            let value = random();
            normal_vector.push(value);
            persisted_vector.push(value).await;
        }
        rusty_storage.persist().await;

        for _i in 0..1000 {
            assert_eq!(normal_vector.len() as u64, persisted_vector.len().await);

            match rng.random_range(0..=5) {
                0 => {
                    // `push`
                    let push_val = rng.next_u64();
                    persisted_vector.push(push_val).await;
                    normal_vector.push(push_val);
                }
                1 => {
                    // `pop`
                    let normal_pop_val = normal_vector.pop().unwrap();
                    let persisted_pop_val = persisted_vector.pop().await.unwrap();
                    assert_eq!(persisted_pop_val, normal_pop_val);
                }
                2 => {
                    // `get_many`
                    assert_eq!(normal_vector.len(), persisted_vector.len().await as usize);

                    let index = rng.random_range(0..normal_vector.len());
                    assert_eq!(Vec::<u64>::default(), persisted_vector.get_many(&[]).await);
                    assert_eq!(
                        normal_vector[index],
                        persisted_vector.get(index as u64).await
                    );
                    assert_eq!(
                        vec![normal_vector[index]],
                        persisted_vector.get_many(&[index as u64]).await
                    );
                    assert_eq!(
                        vec![normal_vector[index], normal_vector[index]],
                        persisted_vector
                            .get_many(&[index as u64, index as u64])
                            .await
                    );
                }
                3 => {
                    // `set`
                    let value = rng.next_u64();
                    let index = rng.random_range(0..normal_vector.len());
                    normal_vector[index] = value;
                    persisted_vector.set(index as u64, value).await;
                }
                4 => {
                    // `set_many`
                    let indices: Vec<u64> = (0..rng.random_range(0..10))
                        .map(|_| rng.random_range(0..normal_vector.len() as u64))
                        .unique()
                        .collect();
                    let values: Vec<u64> = (0..indices.len()).map(|_| rng.next_u64()).collect_vec();
                    let update: Vec<(u64, u64)> =
                        indices.into_iter().zip_eq(values.into_iter()).collect();
                    for (key, val) in &update {
                        normal_vector[*key as usize] = *val;
                    }
                    persisted_vector.set_many(update).await;
                }
                5 => {
                    // persist
                    rusty_storage.persist().await;
                }
                _ => unreachable!(),
            }
        }

        // Check equality after above loop
        assert_eq!(normal_vector.len(), persisted_vector.len().await as usize);
        for (i, nvi) in normal_vector.iter().enumerate() {
            assert_eq!(*nvi, persisted_vector.get(i as u64).await);
        }

        // Check equality using `get_many`
        assert_eq!(
            normal_vector,
            persisted_vector
                .get_many(&(0..normal_vector.len() as u64).collect_vec())
                .await
        );

        // Check equality after persisting updates
        rusty_storage.persist().await;
        assert_eq!(normal_vector.len(), persisted_vector.len().await as usize);
        for (i, nvi) in normal_vector.iter().enumerate() {
            assert_eq!(*nvi, persisted_vector.get(i as u64).await);
        }

        // Check equality using `get_many`
        assert_eq!(
            normal_vector,
            persisted_vector
                .get_many(&(0..normal_vector.len() as u64).collect_vec())
                .await
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn singleton_vector_key_collision() {
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let db_path = db.path().clone();
        let mut rusty_storage = SimpleRustyStorage::new(db);
        let vector1 = rusty_storage.schema.new_vec::<u64>("test-vector1").await;
        let mut singleton = rusty_storage
            .schema
            .new_singleton::<u64>("singleton-1".to_owned())
            .await;

        // initialize
        assert!(vector1.is_empty().await);
        singleton.set(1776u64).await;
        assert!(vector1.is_empty().await);
        rusty_storage.persist().await;
        assert!(vector1.is_empty().await);

        drop(rusty_storage); // <-- DB ref dropped
        drop(vector1); //       <-- DB ref dropped
        drop(singleton); //     <-- final DB ref dropped (NeptuneLevelDb closes)

        // re-open NeptuneLevelDb / restore from disk
        let new_db = NeptuneLevelDb::open_test_database(&db_path, true, None, None, None)
            .await
            .unwrap();
        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let new_vector1 = new_rusty_storage.schema.new_vec::<S>("test-vector1").await;
        assert!(new_vector1.is_empty().await);
    }

    #[apply(shared_tokio_runtime)]
    async fn test_two_vectors_and_singleton() {
        let singleton_value = S([3u8, 3u8, 3u8, 1u8].to_vec());

        // Open new database that will not be destroyed on close.
        let db = NeptuneLevelDb::open_new_test_database(false, None, None, None)
            .await
            .unwrap();
        let db_path = db.path().clone();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector1 = rusty_storage.schema.new_vec::<S>("test-vector1").await;
        let mut vector2 = rusty_storage.schema.new_vec::<S>("test-vector2").await;
        let mut singleton = rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned())
            .await;

        assert!(
            vector1.get_all().await.is_empty(),
            "`get_all` call to unpopulated persistent vector must return empty vector"
        );
        assert!(
            vector2.get_all().await.is_empty(),
            "`get_all` call to unpopulated persistent vector must return empty vector"
        );

        // populate 1
        vector1.push(S([1u8].to_vec())).await;
        vector1.push(S([30u8].to_vec())).await;
        vector1.push(S([4u8].to_vec())).await;
        vector1.push(S([7u8].to_vec())).await;
        vector1.push(S([8u8].to_vec())).await;

        // populate 2
        vector2.push(S([1u8].to_vec())).await;
        vector2.push(S([3u8].to_vec())).await;
        vector2.push(S([3u8].to_vec())).await;
        vector2.push(S([7u8].to_vec())).await;

        // set singleton
        singleton.set(singleton_value.clone()).await;

        // modify 1
        vector1.set(0, S([8u8].to_vec())).await;

        // test
        assert_eq!(vector1.get(0).await, S([8u8].to_vec()));
        assert_eq!(vector1.get(1).await, S([30u8].to_vec()));
        assert_eq!(vector1.get(2).await, S([4u8].to_vec()));
        assert_eq!(vector1.get(3).await, S([7u8].to_vec()));
        assert_eq!(vector1.get(4).await, S([8u8].to_vec()));
        assert_eq!(
            vector1.get_many(&[2, 0, 3]).await,
            vec![
                vector1.get(2).await,
                vector1.get(0).await,
                vector1.get(3).await
            ]
        );
        assert_eq!(
            vector1.get_many(&[2, 3, 1]).await,
            vec![
                vector1.get(2).await,
                vector1.get(3).await,
                vector1.get(1).await
            ]
        );
        assert_eq!(vector1.len().await, 5);
        assert_eq!(vector2.get(0).await, S([1u8].to_vec()));
        assert_eq!(vector2.get(1).await, S([3u8].to_vec()));
        assert_eq!(vector2.get(2).await, S([3u8].to_vec()));
        assert_eq!(vector2.get(3).await, S([7u8].to_vec()));
        assert_eq!(
            vector2.get_many(&[0, 1, 2]).await,
            vec![
                vector2.get(0).await,
                vector2.get(1).await,
                vector2.get(2).await
            ]
        );
        assert_eq!(vector2.get_many(&[]).await, vec![]);
        assert_eq!(
            vector2.get_many(&[1, 2]).await,
            vec![vector2.get(1).await, vector2.get(2).await]
        );
        assert_eq!(
            vector2.get_many(&[2, 1]).await,
            vec![vector2.get(2).await, vector2.get(1).await]
        );
        assert_eq!(vector2.len().await, 4);
        assert_eq!(singleton.get(), singleton_value);
        assert_eq!(
            vec![
                S([8u8].to_vec()),
                S([30u8].to_vec()),
                S([4u8].to_vec()),
                S([7u8].to_vec()),
                S([8u8].to_vec())
            ],
            vector1.get_all().await
        );
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([3u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            vector2.get_all().await
        );

        // persist and drop
        rusty_storage.persist().await;
        assert_eq!(
            vector2.get_many(&[2, 1]).await,
            vec![vector2.get(2).await, vector2.get(1).await]
        );
        drop(rusty_storage); // <-- DB ref dropped
        drop(vector1); //       <-- DB ref dropped
        drop(vector2); //       <-- DB ref dropped
        drop(singleton); //     <-- final DB ref dropped (NeptuneLevelDb closes)

        // re-open NeptuneLevelDb / restore from disk
        let new_db = NeptuneLevelDb::open_test_database(&db_path, true, None, None, None)
            .await
            .unwrap();
        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let new_vector1 = new_rusty_storage.schema.new_vec::<S>("test-vector1").await;
        let mut new_vector2 = new_rusty_storage.schema.new_vec::<S>("test-vector2").await;

        let new_singleton = new_rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned())
            .await;

        // test again
        assert_eq!(new_vector1.get(0).await, S([8u8].to_vec()));
        assert_eq!(new_vector1.get(1).await, S([30u8].to_vec()));
        assert_eq!(new_vector1.get(2).await, S([4u8].to_vec()));
        assert_eq!(new_vector1.get(3).await, S([7u8].to_vec()));
        assert_eq!(new_vector1.get(4).await, S([8u8].to_vec()));
        assert_eq!(new_vector1.len().await, 5);
        assert_eq!(new_vector2.get(0).await, S([1u8].to_vec()));
        assert_eq!(new_vector2.get(1).await, S([3u8].to_vec()));
        assert_eq!(new_vector2.get(2).await, S([3u8].to_vec()));
        assert_eq!(new_vector2.get(3).await, S([7u8].to_vec()));
        assert_eq!(new_vector2.len().await, 4);
        assert_eq!(new_singleton.get(), singleton_value);

        // Test `get_many` for a restored NeptuneLevelDb
        assert_eq!(
            new_vector2.get_many(&[2, 1]).await,
            vec![new_vector2.get(2).await, new_vector2.get(1).await]
        );
        assert_eq!(
            new_vector2.get_many(&[0, 1]).await,
            vec![new_vector2.get(0).await, new_vector2.get(1).await]
        );
        assert_eq!(
            new_vector2.get_many(&[1, 0]).await,
            vec![new_vector2.get(1).await, new_vector2.get(0).await]
        );
        assert_eq!(
            new_vector2.get_many(&[0, 1, 2, 3]).await,
            vec![
                new_vector2.get(0).await,
                new_vector2.get(1).await,
                new_vector2.get(2).await,
                new_vector2.get(3).await,
            ]
        );
        assert_eq!(
            new_vector2.get_many(&[2]).await,
            vec![new_vector2.get(2).await,]
        );
        assert_eq!(new_vector2.get_many(&[]).await, vec![]);

        // Test `get_all` for a restored NeptuneLevelDb
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([3u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector2.get_all().await,
            "`get_all` must return expected values, before mutation"
        );
        new_vector2.set(1, S([130u8].to_vec())).await;
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([130u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector2.get_all().await,
            "`get_all` must return expected values, after mutation"
        );
    }

    #[should_panic(
        expected = "Out-of-bounds. Got 2 but length was 2. persisted vector name: test-vector"
    )]
    #[apply(shared_tokio_runtime)]
    async fn out_of_bounds_using_get() {
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector").await;

        vector.push(1).await;
        vector.push(1).await;
        vector.get(2).await;
    }

    #[should_panic(
        expected = "Out-of-bounds. Got index 2 but length was 2. persisted vector name: test-vector"
    )]
    #[apply(shared_tokio_runtime)]
    async fn out_of_bounds_using_get_many() {
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector").await;

        vector.push(1).await;
        vector.push(1).await;
        vector.get_many(&[0, 0, 0, 1, 1, 2]).await;
    }

    #[should_panic(
        expected = "Out-of-bounds. Got 1 but length was 1. persisted vector name: test-vector"
    )]
    #[apply(shared_tokio_runtime)]
    async fn out_of_bounds_using_set_many() {
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector").await;

        vector.push(1).await;

        // attempt to set 2 values, when only one is in vector.
        vector.set_many([(0, 0), (1, 1)]).await;
    }

    #[should_panic(expected = "size-mismatch.  input has 2 elements and target has 1 elements")]
    #[apply(shared_tokio_runtime)]
    async fn size_mismatch_too_many_using_set_all() {
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector").await;

        vector.push(1).await;

        // attempt to set 2 values, when only one is in vector.
        vector.set_all([0, 1]).await;
    }

    #[should_panic(expected = "size-mismatch.  input has 1 elements and target has 2 elements")]
    #[apply(shared_tokio_runtime)]
    async fn size_mismatch_too_few_using_set_all() {
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector").await;

        vector.push(0).await;
        vector.push(1).await;

        // attempt to set 1 values, when two are in vector.
        vector.set_all([5]).await;
    }

    #[apply(shared_tokio_runtime)]
    async fn test_db_sync_and_send() {
        fn sync_and_send<T: Sync + Send>(_t: T) {}

        // open new NeptuneLevelDb that will not be dropped on close.
        let db: NeptuneLevelDb<usize, usize> =
            NeptuneLevelDb::open_new_test_database(false, None, None, None)
                .await
                .unwrap();
        sync_and_send(db);
    }
}
