//! Provides a virtual DB Schema with atomic writes across "tables".
//!
//! This module provides [`DbtSchema`] that can generate any number of
//! [`DbtVec`] and [`DbtSingleton`] collection types.
//!
//! Mutating operations to these "tables" are cached and written to the
//! database in a single atomic batch operation.

mod dbtsingleton;
mod dbtsingleton_private;
mod dbtvec;
mod dbtvec_private;
mod enums;
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
pub use rusty_key::*;
pub use rusty_reader::*;
pub use rusty_value::*;
pub use schema::*;
pub use simple_rusty_reader::*;
pub use simple_rusty_storage::*;

#[cfg(test)]
mod tests {

    use super::traits::*;
    use super::*;

    use std::{collections::BTreeSet, sync::Arc};

    use rand::{random, Rng, RngCore};
    use serde::{Deserialize, Serialize};

    use crate::{
        shared_math::other::random_elements,
        storage::{
            level_db::DB,
            storage_vec::{traits::*, Index},
        },
    };
    use itertools::Itertools;

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

    #[test]
    fn test_simple_singleton() {
        let singleton_value = S([1u8, 3u8, 3u8, 7u8].to_vec());

        // open new DB that will not be dropped on close.
        let db = DB::open_new_test_database(false, None, None, None).unwrap();
        let db_path = db.path().clone();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        assert_eq!(1, Arc::strong_count(&rusty_storage.schema.reader));
        let mut singleton = rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned());
        assert_eq!(2, Arc::strong_count(&rusty_storage.schema.reader));

        // initialize
        rusty_storage.restore_or_new();

        // test
        assert_eq!(singleton.get(), S([].to_vec()));

        // set
        singleton.set(singleton_value.clone());

        // test
        assert_eq!(singleton.get(), singleton_value);

        // persist
        rusty_storage.persist();

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

        // restore.  re-open existing DB.
        let new_db = DB::open_test_database(&db_path, true, None, None, None).unwrap();
        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let new_singleton = new_rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned());
        new_rusty_storage.restore_or_new();

        // test
        assert_eq!(new_singleton.get(), singleton_value);
    }

    #[test]
    fn test_simple_vector() {
        // open new DB that will not be dropped on close.
        let db = DB::open_new_test_database(false, None, None, None).unwrap();
        let db_path = db.path().clone();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector");

        // initialize
        rusty_storage.restore_or_new();

        // should work to pass empty array, when vector.is_empty() == true
        vector.set_all([]);

        // test `get_all`
        assert!(
            vector.get_all().is_empty(),
            "`get_all` on unpopulated vector must return empty vector"
        );

        // populate
        vector.push(S([1u8].to_vec()));
        vector.push(S([3u8].to_vec()));
        vector.push(S([4u8].to_vec()));
        vector.push(S([7u8].to_vec()));
        vector.push(S([8u8].to_vec()));

        // test `get`
        assert_eq!(vector.get(0), S([1u8].to_vec()));
        assert_eq!(vector.get(1), S([3u8].to_vec()));
        assert_eq!(vector.get(2), S([4u8].to_vec()));
        assert_eq!(vector.get(3), S([7u8].to_vec()));
        assert_eq!(vector.get(4), S([8u8].to_vec()));
        assert_eq!(vector.len(), 5);

        // test `get_many`
        assert_eq!(
            vector.get_many(&[0, 2, 3]),
            vec![vector.get(0), vector.get(2), vector.get(3)]
        );
        assert_eq!(
            vector.get_many(&[2, 3, 0]),
            vec![vector.get(2), vector.get(3), vector.get(0)]
        );
        assert_eq!(
            vector.get_many(&[3, 0, 2]),
            vec![vector.get(3), vector.get(0), vector.get(2)]
        );
        assert_eq!(
            vector.get_many(&[0, 1, 2, 3, 4]),
            vec![
                vector.get(0),
                vector.get(1),
                vector.get(2),
                vector.get(3),
                vector.get(4),
            ]
        );
        assert_eq!(vector.get_many(&[]), vec![]);
        assert_eq!(vector.get_many(&[3]), vec![vector.get(3)]);

        // We allow `get_many` to take repeated indices.
        assert_eq!(vector.get_many(&[3; 0]), vec![vector.get(3); 0]);
        assert_eq!(vector.get_many(&[3; 1]), vec![vector.get(3); 1]);
        assert_eq!(vector.get_many(&[3; 2]), vec![vector.get(3); 2]);
        assert_eq!(vector.get_many(&[3; 3]), vec![vector.get(3); 3]);
        assert_eq!(vector.get_many(&[3; 4]), vec![vector.get(3); 4]);
        assert_eq!(vector.get_many(&[3; 5]), vec![vector.get(3); 5]);
        assert_eq!(
            vector.get_many(&[3, 3, 2, 3]),
            vec![vector.get(3), vector.get(3), vector.get(2), vector.get(3)]
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
            vector.get_all(),
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
        vector.set_all(values_tmp.clone());

        assert_eq!(
            values_tmp,
            vector.get_all(),
            "`get_all` must return values passed to `set_all`",
        );

        vector.set_all(expect_values.clone());

        // persist
        rusty_storage.persist();

        // test `get_all` after persist
        assert_eq!(
            expect_values,
            vector.get_all(),
            "`get_all` must return expected values after persist"
        );

        // modify
        let last = vector.pop().unwrap();

        // test
        assert_eq!(last, S([8u8].to_vec()));

        // drop without persisting
        drop(rusty_storage); // <--- DB ref dropped.
        drop(vector); //        <--- Final DB ref dropped. DB closes

        // Open existing database.
        let new_db = DB::open_test_database(&db_path, true, None, None, None).unwrap();

        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let mut new_vector = new_rusty_storage.schema.new_vec::<S>("test-vector");

        // initialize
        new_rusty_storage.restore_or_new();

        // modify
        new_vector.set(2, S([3u8].to_vec()));
        println!("vec: {:?}", new_vector);
        let last_again = new_vector.pop().unwrap();
        assert_eq!(last_again, S([8u8].to_vec()));

        // test
        assert_eq!(new_vector.get(0), S([1u8].to_vec()));
        assert_eq!(new_vector.get(1), S([3u8].to_vec()));
        assert_eq!(new_vector.get(2), S([3u8].to_vec()));
        assert_eq!(new_vector.get(3), S([7u8].to_vec()));
        assert_eq!(new_vector.len(), 4);

        // test `get_many`, ensure that output matches input ordering
        assert_eq!(new_vector.get_many(&[2]), vec![new_vector.get(2)]);
        assert_eq!(
            new_vector.get_many(&[3, 1, 0]),
            vec![new_vector.get(3), new_vector.get(1), new_vector.get(0)]
        );
        assert_eq!(
            new_vector.get_many(&[0, 2, 3]),
            vec![new_vector.get(0), new_vector.get(2), new_vector.get(3)]
        );
        assert_eq!(
            new_vector.get_many(&[0, 1, 2, 3]),
            vec![
                new_vector.get(0),
                new_vector.get(1),
                new_vector.get(2),
                new_vector.get(3),
            ]
        );
        assert_eq!(new_vector.get_many(&[]), vec![]);
        assert_eq!(new_vector.get_many(&[3]), vec![new_vector.get(3)]);

        // We allow `get_many` to take repeated indices.
        assert_eq!(new_vector.get_many(&[3; 0]), vec![new_vector.get(3); 0]);
        assert_eq!(new_vector.get_many(&[3; 1]), vec![new_vector.get(3); 1]);
        assert_eq!(new_vector.get_many(&[3; 2]), vec![new_vector.get(3); 2]);
        assert_eq!(new_vector.get_many(&[3; 3]), vec![new_vector.get(3); 3]);
        assert_eq!(new_vector.get_many(&[3; 4]), vec![new_vector.get(3); 4]);
        assert_eq!(new_vector.get_many(&[3; 5]), vec![new_vector.get(3); 5]);

        // test `get_all`
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([3u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector.get_all(),
            "`get_all` must return expected values"
        );

        new_vector.set(1, S([130u8].to_vec()));
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([130u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector.get_all(),
            "`get_all` must return expected values, after mutation"
        );
    }

    #[test]
    fn test_dbtcvecs_get_many() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector");

        // initialize
        rusty_storage.restore_or_new();

        // populate
        const TEST_LIST_LENGTH: u8 = 105;
        for i in 0u8..TEST_LIST_LENGTH {
            vector.push(S(vec![i, i, i]));
        }

        let read_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % TEST_LIST_LENGTH as u64)
            .collect();
        let values = vector.get_many(&read_indices);
        assert!(read_indices
            .iter()
            .zip(values)
            .all(|(index, value)| value == S(vec![*index as u8, *index as u8, *index as u8])));

        // Mutate some indices
        let mutate_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % TEST_LIST_LENGTH as u64)
            .collect();
        for index in mutate_indices.iter() {
            vector.set(
                *index,
                S(vec![*index as u8 + 1, *index as u8 + 1, *index as u8 + 1]),
            )
        }

        let new_values = vector.get_many(&read_indices);
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

    #[test]
    fn test_dbtcvecs_set_many_get_many() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        // initialize storage
        let mut rusty_storage = SimpleRustyStorage::new(db);
        rusty_storage.restore_or_new();
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector");

        // Generate initial index/value pairs.
        const TEST_LIST_LENGTH: u8 = 105;
        let init_keyvals: Vec<(Index, S)> = (0u8..TEST_LIST_LENGTH)
            .map(|i| (i as Index, S(vec![i, i, i])))
            .collect();

        // set_many() does not grow the list, so we must first push
        // some empty elems, to desired length.
        for _ in 0u8..TEST_LIST_LENGTH {
            vector.push(S(vec![]));
        }

        // set the initial values
        vector.set_many(init_keyvals);

        // generate some random indices to read
        let read_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % TEST_LIST_LENGTH as u64)
            .collect();

        // perform read, and validate as expected
        let values = vector.get_many(&read_indices);
        assert!(read_indices
            .iter()
            .zip(values)
            .all(|(index, value)| value == S(vec![*index as u8, *index as u8, *index as u8])));

        // Generate some random indices for mutation
        let mutate_indices: Vec<u64> = random_elements::<u64>(30)
            .iter()
            .map(|x| x % TEST_LIST_LENGTH as u64)
            .collect();

        // Generate keyvals for mutation
        let mutate_keyvals: Vec<(Index, S)> = mutate_indices
            .iter()
            .map(|index| {
                let val = (index % TEST_LIST_LENGTH as u64 + 1) as u8;
                (*index, S(vec![val, val, val]))
            })
            .collect();

        // Mutate values at randomly generated indices
        vector.set_many(mutate_keyvals);

        // Verify mutated values, and non-mutated also.
        let new_values = vector.get_many(&read_indices);
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
        rusty_storage.persist();
        let new_values_after_persist = vector.get_many(&read_indices);
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

    #[test]
    fn test_dbtcvecs_set_all_get_many() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        // initialize storage
        let mut rusty_storage = SimpleRustyStorage::new(db);
        rusty_storage.restore_or_new();
        let mut vector = rusty_storage.schema.new_vec::<S>("test-vector");

        // Generate initial index/value pairs.
        const TEST_LIST_LENGTH: u8 = 105;
        let init_vals: Vec<S> = (0u8..TEST_LIST_LENGTH)
            .map(|i| (S(vec![i, i, i])))
            .collect();

        let mut mutate_vals = init_vals.clone(); // for later

        // set_all() does not grow the list, so we must first push
        // some empty elems, to desired length.
        for _ in 0u8..TEST_LIST_LENGTH {
            vector.push(S(vec![]));
        }

        // set the initial values
        vector.set_all(init_vals);

        // generate some random indices to read
        let read_indices: Vec<u64> = random_elements::<u64>(30)
            .into_iter()
            .map(|x| x % TEST_LIST_LENGTH as u64)
            .collect();

        // perform read, and validate as expected
        let values = vector.get_many(&read_indices);
        assert!(read_indices
            .iter()
            .zip(values)
            .all(|(index, value)| value == S(vec![*index as u8, *index as u8, *index as u8])));

        // Generate some random indices for mutation
        let mutate_indices: Vec<u64> = random_elements::<u64>(30)
            .iter()
            .map(|x| x % TEST_LIST_LENGTH as u64)
            .collect();

        // Generate vals for mutation
        for index in mutate_indices.iter() {
            let val = (index % TEST_LIST_LENGTH as u64 + 1) as u8;
            mutate_vals[*index as usize] = S(vec![val, val, val]);
        }

        // Mutate values at randomly generated indices
        vector.set_all(mutate_vals);

        // Verify mutated values, and non-mutated also.
        let new_values = vector.get_many(&read_indices);
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

    #[test]
    fn storage_schema_vector_pbt() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut persisted_vector = rusty_storage.schema.new_vec::<u64>("test-vector");

        // Insert 1000 elements
        let mut rng = rand::thread_rng();
        let mut normal_vector = vec![];
        for _ in 0..1000 {
            let value = random();
            normal_vector.push(value);
            persisted_vector.push(value);
        }
        rusty_storage.persist();

        for _ in 0..1000 {
            match rng.gen_range(0..=5) {
                0 => {
                    // `push`
                    let push_val = rng.next_u64();
                    persisted_vector.push(push_val);
                    normal_vector.push(push_val);
                }
                1 => {
                    // `pop`
                    let persisted_pop_val = persisted_vector.pop().unwrap();
                    let normal_pop_val = normal_vector.pop().unwrap();
                    assert_eq!(persisted_pop_val, normal_pop_val);
                }
                2 => {
                    // `get_many`
                    assert_eq!(normal_vector.len(), persisted_vector.len() as usize);

                    let index = rng.gen_range(0..normal_vector.len());
                    assert_eq!(Vec::<u64>::default(), persisted_vector.get_many(&[]));
                    assert_eq!(normal_vector[index], persisted_vector.get(index as u64));
                    assert_eq!(
                        vec![normal_vector[index]],
                        persisted_vector.get_many(&[index as u64])
                    );
                    assert_eq!(
                        vec![normal_vector[index], normal_vector[index]],
                        persisted_vector.get_many(&[index as u64, index as u64])
                    );
                }
                3 => {
                    // `set`
                    let value = rng.next_u64();
                    let index = rng.gen_range(0..normal_vector.len());
                    normal_vector[index] = value;
                    persisted_vector.set(index as u64, value);
                }
                4 => {
                    // `set_many`
                    let indices: Vec<u64> = (0..rng.gen_range(0..10))
                        .map(|_| rng.gen_range(0..normal_vector.len() as u64))
                        .unique()
                        .collect();
                    let values: Vec<u64> = (0..indices.len()).map(|_| rng.next_u64()).collect_vec();
                    let update: Vec<(u64, u64)> =
                        indices.into_iter().zip_eq(values.into_iter()).collect();
                    for (key, val) in update.iter() {
                        normal_vector[*key as usize] = *val;
                    }
                    persisted_vector.set_many(update);
                }
                5 => {
                    // persist
                    rusty_storage.persist();
                }
                _ => unreachable!(),
            }
        }

        // Check equality after above loop
        assert_eq!(normal_vector.len(), persisted_vector.len() as usize);
        for (i, nvi) in normal_vector.iter().enumerate() {
            assert_eq!(*nvi, persisted_vector.get(i as u64));
        }

        // Check equality using `get_many`
        assert_eq!(
            normal_vector,
            persisted_vector.get_many(&(0..normal_vector.len() as u64).collect_vec())
        );

        // Check equality after persisting updates
        rusty_storage.persist();
        assert_eq!(normal_vector.len(), persisted_vector.len() as usize);
        for (i, nvi) in normal_vector.iter().enumerate() {
            assert_eq!(*nvi, persisted_vector.get(i as u64));
        }

        // Check equality using `get_many`
        assert_eq!(
            normal_vector,
            persisted_vector.get_many(&(0..normal_vector.len() as u64).collect_vec())
        );
    }

    #[test]
    fn singleton_vector_key_collission() {
        let db = DB::open_new_test_database(false, None, None, None).unwrap();
        let db_path = db.path().clone();
        let mut rusty_storage = SimpleRustyStorage::new(db);
        let vector1 = rusty_storage.schema.new_vec::<u64>("test-vector1");
        let mut singleton = rusty_storage
            .schema
            .new_singleton::<u64>("singleton-1".to_owned());

        // initialize
        rusty_storage.restore_or_new();
        assert!(vector1.is_empty());
        singleton.set(1776u64);
        assert!(vector1.is_empty());
        rusty_storage.persist();
        assert!(vector1.is_empty());

        drop(rusty_storage); // <-- DB ref dropped
        drop(vector1); //       <-- DB ref dropped
        drop(singleton); //     <-- final DB ref dropped (DB closes)

        // re-open DB / restore from disk
        let new_db = DB::open_test_database(&db_path, true, None, None, None).unwrap();
        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let new_vector1 = new_rusty_storage.schema.new_vec::<S>("test-vector1");
        new_rusty_storage.restore_or_new();
        assert!(new_vector1.is_empty());
    }

    #[test]
    fn test_two_vectors_and_singleton() {
        let singleton_value = S([3u8, 3u8, 3u8, 1u8].to_vec());

        // Open new database that will not be destroyed on close.
        let db = DB::open_new_test_database(false, None, None, None).unwrap();
        let db_path = db.path().clone();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector1 = rusty_storage.schema.new_vec::<S>("test-vector1");
        let mut vector2 = rusty_storage.schema.new_vec::<S>("test-vector2");
        let mut singleton = rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned());

        // initialize
        rusty_storage.restore_or_new();

        assert!(
            vector1.get_all().is_empty(),
            "`get_all` call to unpopulated persistent vector must return empty vector"
        );
        assert!(
            vector2.get_all().is_empty(),
            "`get_all` call to unpopulated persistent vector must return empty vector"
        );

        // populate 1
        vector1.push(S([1u8].to_vec()));
        vector1.push(S([30u8].to_vec()));
        vector1.push(S([4u8].to_vec()));
        vector1.push(S([7u8].to_vec()));
        vector1.push(S([8u8].to_vec()));

        // populate 2
        vector2.push(S([1u8].to_vec()));
        vector2.push(S([3u8].to_vec()));
        vector2.push(S([3u8].to_vec()));
        vector2.push(S([7u8].to_vec()));

        // set singleton
        singleton.set(singleton_value.clone());

        // modify 1
        vector1.set(0, S([8u8].to_vec()));

        // test
        assert_eq!(vector1.get(0), S([8u8].to_vec()));
        assert_eq!(vector1.get(1), S([30u8].to_vec()));
        assert_eq!(vector1.get(2), S([4u8].to_vec()));
        assert_eq!(vector1.get(3), S([7u8].to_vec()));
        assert_eq!(vector1.get(4), S([8u8].to_vec()));
        assert_eq!(
            vector1.get_many(&[2, 0, 3]),
            vec![vector1.get(2), vector1.get(0), vector1.get(3)]
        );
        assert_eq!(
            vector1.get_many(&[2, 3, 1]),
            vec![vector1.get(2), vector1.get(3), vector1.get(1)]
        );
        assert_eq!(vector1.len(), 5);
        assert_eq!(vector2.get(0), S([1u8].to_vec()));
        assert_eq!(vector2.get(1), S([3u8].to_vec()));
        assert_eq!(vector2.get(2), S([3u8].to_vec()));
        assert_eq!(vector2.get(3), S([7u8].to_vec()));
        assert_eq!(
            vector2.get_many(&[0, 1, 2]),
            vec![vector2.get(0), vector2.get(1), vector2.get(2)]
        );
        assert_eq!(vector2.get_many(&[]), vec![]);
        assert_eq!(
            vector2.get_many(&[1, 2]),
            vec![vector2.get(1), vector2.get(2)]
        );
        assert_eq!(
            vector2.get_many(&[2, 1]),
            vec![vector2.get(2), vector2.get(1)]
        );
        assert_eq!(vector2.len(), 4);
        assert_eq!(singleton.get(), singleton_value);
        assert_eq!(
            vec![
                S([8u8].to_vec()),
                S([30u8].to_vec()),
                S([4u8].to_vec()),
                S([7u8].to_vec()),
                S([8u8].to_vec())
            ],
            vector1.get_all()
        );
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([3u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            vector2.get_all()
        );

        // persist and drop
        rusty_storage.persist();
        assert_eq!(
            vector2.get_many(&[2, 1]),
            vec![vector2.get(2), vector2.get(1)]
        );
        drop(rusty_storage); // <-- DB ref dropped
        drop(vector1); //       <-- DB ref dropped
        drop(vector2); //       <-- DB ref dropped
        drop(singleton); //     <-- final DB ref dropped (DB closes)

        // re-open DB / restore from disk
        let new_db = DB::open_test_database(&db_path, true, None, None, None).unwrap();
        let mut new_rusty_storage = SimpleRustyStorage::new(new_db);
        let new_vector1 = new_rusty_storage.schema.new_vec::<S>("test-vector1");
        let mut new_vector2 = new_rusty_storage.schema.new_vec::<S>("test-vector2");
        new_rusty_storage.restore_or_new();
        let new_singleton = new_rusty_storage
            .schema
            .new_singleton::<S>("singleton".to_owned());
        new_rusty_storage.restore_or_new();

        // test again
        assert_eq!(new_vector1.get(0), S([8u8].to_vec()));
        assert_eq!(new_vector1.get(1), S([30u8].to_vec()));
        assert_eq!(new_vector1.get(2), S([4u8].to_vec()));
        assert_eq!(new_vector1.get(3), S([7u8].to_vec()));
        assert_eq!(new_vector1.get(4), S([8u8].to_vec()));
        assert_eq!(new_vector1.len(), 5);
        assert_eq!(new_vector2.get(0), S([1u8].to_vec()));
        assert_eq!(new_vector2.get(1), S([3u8].to_vec()));
        assert_eq!(new_vector2.get(2), S([3u8].to_vec()));
        assert_eq!(new_vector2.get(3), S([7u8].to_vec()));
        assert_eq!(new_vector2.len(), 4);
        assert_eq!(new_singleton.get(), singleton_value);

        // Test `get_many` for a restored DB
        assert_eq!(
            new_vector2.get_many(&[2, 1]),
            vec![new_vector2.get(2), new_vector2.get(1)]
        );
        assert_eq!(
            new_vector2.get_many(&[0, 1]),
            vec![new_vector2.get(0), new_vector2.get(1)]
        );
        assert_eq!(
            new_vector2.get_many(&[1, 0]),
            vec![new_vector2.get(1), new_vector2.get(0)]
        );
        assert_eq!(
            new_vector2.get_many(&[0, 1, 2, 3]),
            vec![
                new_vector2.get(0),
                new_vector2.get(1),
                new_vector2.get(2),
                new_vector2.get(3),
            ]
        );
        assert_eq!(new_vector2.get_many(&[2]), vec![new_vector2.get(2),]);
        assert_eq!(new_vector2.get_many(&[]), vec![]);

        // Test `get_all` for a restored DB
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([3u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector2.get_all(),
            "`get_all` must return expected values, before mutation"
        );
        new_vector2.set(1, S([130u8].to_vec()));
        assert_eq!(
            vec![
                S([1u8].to_vec()),
                S([130u8].to_vec()),
                S([3u8].to_vec()),
                S([7u8].to_vec()),
            ],
            new_vector2.get_all(),
            "`get_all` must return expected values, after mutation"
        );
    }

    #[should_panic(
        expected = "Out-of-bounds. Got 2 but length was 2. persisted vector name: test-vector"
    )]
    #[test]
    fn out_of_bounds_using_get() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector");

        // initialize
        rusty_storage.restore_or_new();

        vector.push(1);
        vector.push(1);
        vector.get(2);
    }

    #[should_panic(
        expected = "Out-of-bounds. Got index 2 but length was 2. persisted vector name: test-vector"
    )]
    #[test]
    fn out_of_bounds_using_get_many() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector");

        // initialize
        rusty_storage.restore_or_new();

        vector.push(1);
        vector.push(1);
        vector.get_many(&[0, 0, 0, 1, 1, 2]);
    }

    #[should_panic(
        expected = "Out-of-bounds. Got 1 but length was 1. persisted vector name: test-vector"
    )]
    #[test]
    fn out_of_bounds_using_set_many() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector");

        // initialize
        rusty_storage.restore_or_new();

        vector.push(1);

        // attempt to set 2 values, when only one is in vector.
        vector.set_many([(0, 0), (1, 1)]);
    }

    #[should_panic(expected = "size-mismatch.  input has 2 elements and target has 1 elements")]
    #[test]
    fn size_mismatch_too_many_using_set_all() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector");

        // initialize
        rusty_storage.restore_or_new();

        vector.push(1);

        // attempt to set 2 values, when only one is in vector.
        vector.set_all([0, 1]);
    }

    #[should_panic(expected = "size-mismatch.  input has 1 elements and target has 2 elements")]
    #[test]
    fn size_mismatch_too_few_using_set_all() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        let mut rusty_storage = SimpleRustyStorage::new(db);
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector");

        // initialize
        rusty_storage.restore_or_new();

        vector.push(0);
        vector.push(1);

        // attempt to set 1 values, when two are in vector.
        vector.set_all([5]);
    }

    #[test]
    fn test_dbtcvecs_iter_mut() {
        let db = DB::open_new_test_database(true, None, None, None).unwrap();

        // initialize storage
        let mut rusty_storage = SimpleRustyStorage::new(db);
        rusty_storage.restore_or_new();
        let mut vector = rusty_storage.schema.new_vec::<u64>("test-vector");

        // Generate initial index/value pairs.
        const TEST_LIST_LENGTH: u64 = 105;
        let init_vals: Vec<u64> = (0..TEST_LIST_LENGTH).map(|i| i * 2).collect();

        // let mut mutate_vals = init_vals.clone(); // for later

        // set_all() does not grow the list, so we must first push
        // some empty elems, to desired length.
        for _ in 0..TEST_LIST_LENGTH {
            vector.push(0);
        }

        // set the initial values
        vector.set_all(init_vals);

        // Generate some random indices for mutation
        let mutate_indices: BTreeSet<u64> = random_elements::<u64>(30)
            .iter()
            .map(|x| x % TEST_LIST_LENGTH)
            .collect();

        // note: with LendingIterator for loop is not available.
        let mut iter = vector.many_iter_mut(mutate_indices.clone());
        while let Some(mut setter) = iter.next() {
            let val = setter.value();
            setter.set(*val / 2);
        }
        drop(iter); // <--- without this, code will deadlock at next read.

        // Verify mutated values, and non-mutated also.
        for (index, value) in vector.iter() {
            if mutate_indices.contains(&index) {
                assert_eq!(index, value)
            } else {
                assert_eq!(index * 2, value)
            }
        }
    }

    #[test]
    fn test_db_sync_and_send() {
        fn sync_and_send<T: Sync + Send>(_t: T) {}

        // open new DB that will not be dropped on close.
        let db = DB::open_new_test_database(false, None, None, None).unwrap();
        sync_and_send(db);
    }

    pub mod concurrency {
        use super::*;
        use crate::sync::AtomicRw;
        use std::thread;

        type TestVec = DbtVec<u64>;
        type TestSingleton = DbtSingleton<u64>;

        pub fn iter_all_eq<T: PartialEq>(iter: impl IntoIterator<Item = T>) -> bool {
            let mut iter = iter.into_iter();
            let first = match iter.next() {
                Some(f) => f,
                None => return true,
            };
            iter.all(|elem| elem == first)
        }

        mod storage_vec {
            use super::*;
            use crate::storage::storage_vec::traits::tests as traits_tests;

            fn gen_concurrency_test_vec() -> TestVec {
                // open new DB that will be removed on close.
                let db = DB::open_new_test_database(true, None, None, None).unwrap();
                let mut rusty_storage = SimpleRustyStorage::new(db);
                rusty_storage.schema.new_vec::<u64>("atomicity-test-vector")
            }

            #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
            #[test]
            fn non_atomic_set_and_get() {
                traits_tests::concurrency::non_atomic_set_and_get(&mut gen_concurrency_test_vec());
            }

            #[test]
            #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
            fn non_atomic_set_and_get_wrapped_atomic_rw() {
                traits_tests::concurrency::non_atomic_set_and_get_wrapped_atomic_rw(
                    &mut gen_concurrency_test_vec(),
                );
            }

            #[test]
            fn atomic_set_and_get_wrapped_atomic_rw() {
                traits_tests::concurrency::atomic_set_and_get_wrapped_atomic_rw(
                    &mut gen_concurrency_test_vec(),
                );
            }

            #[test]
            fn atomic_setmany_and_getmany() {
                traits_tests::concurrency::atomic_setmany_and_getmany(
                    &mut gen_concurrency_test_vec(),
                );
            }

            #[test]
            fn atomic_setall_and_getall() {
                traits_tests::concurrency::atomic_setall_and_getall(&mut gen_concurrency_test_vec());
            }

            #[test]
            fn atomic_iter_mut_and_iter() {
                traits_tests::concurrency::atomic_iter_mut_and_iter(&mut gen_concurrency_test_vec());
            }
        }

        mod storage_singleton {
            use super::*;

            fn gen_atomic_rw_test_singleton(num: u8) -> AtomicRw<Vec<TestSingleton>> {
                // open new DB that will be removed on close.
                let db = DB::open_new_test_database(true, None, None, None).unwrap();
                let mut storage = SimpleRustyStorage::new(db);

                storage.schema.create_tables_rw(|schema| {
                    (0..num)
                        .map(|_i| {
                            let mut singleton = schema.new_singleton::<u64>("singleton".to_owned());
                            singleton.set(25);
                            singleton
                        })
                        .collect()
                })
            }

            fn gen_non_atomic_test_singleton(num: u8) -> Vec<TestSingleton> {
                // open new DB that will be removed on close.
                let db = DB::open_new_test_database(true, None, None, None).unwrap();
                let mut storage = SimpleRustyStorage::new(db);

                (0..num)
                    .map(|_i| {
                        let mut singleton =
                            storage.schema.new_singleton::<u64>("singleton".to_owned());
                        singleton.set(25);
                        singleton
                    })
                    .collect()
            }

            // This test verifies that concurrent reads and writes
            // to multiple DbtSingleton in a `DbtSchema` are atomic when
            // using a correct construction with an RwLock placed around a
            // collection holding all the `DbtSingleton`.
            //
            // It tests two things:
            //  1. That individual tables are atomic within themselves.
            //  2. That the entire set of tables is atomic.
            //
            // The construction shared between threads is:
            //    AtomicRw< Arc<RwLock< Vec< DbtSingleton<Arc<RwLock<DbtSingletonPrivate<u64>>>> > >> >
            //    --------------------- ++++ ********************************************+++**** + ----
            //
            // * = provided by DbtSingleton
            // * = provided by AtomicRw
            // + = supplied by application
            //
            // The test passes and demonstrates it is important to always use a
            // correct atomic construction, such as provided by
            // `DbtSchema::create_tables_rw()`
            //
            // note: similar tests exist for pre refactored code at:
            // https://github.com/dan-da/twenty-first/blob/088f12d6c46c3a15c8d826f8e20839ad7131f915/twenty-first/src/util_types/storage_schema.rs#L1671
            #[test]
            pub fn multi_table_atomic_rw_setmany_and_getmany() {
                let table_singletons = gen_atomic_rw_test_singleton(2);

                // performs single-line read lock on table_singletons to copy original state.
                let orig = table_singletons.lock(|ts| ts[0].get());

                // make a modified state template equal to twice original value.
                let modified = orig * 2;

                // this test should never fail.  we only loop 100 times to keep
                // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
                for i in 0..100 {
                    thread::scope(|s| {
                        // This is our reader thread
                        let gets = s.spawn(|| {
                            let mut copies = vec![];

                            // start locked read operations
                            table_singletons.lock(|tables| {
                                for singleton in tables.iter() {
                                    let copy = singleton.get();

                                    // Verify that the table is self-consistent.
                                    // It must match either the orig template or the modified template.
                                    assert!(
                                        copy == orig || copy == modified,
                                        "in test iteration #{}: encountered inconsistent table read. data: {:?}",
                                        i,
                                        copy
                                    );

                                    copies.push(copy);
                                }
                            }); // <--- end locked read operations

                            // Verify that copies are equal. If not, the tables are different from eachother.
                            assert!(
                                iter_all_eq(copies.clone()),
                                "in test iteration #{}: encountered inconsistent read across tables:\n  data: {:?}",
                                i,
                                copies
                            );
                        });

                        // This is our writer thread
                        let sets = s.spawn(|| {
                            // start locked write ops
                            table_singletons.clone().lock_mut(|tables| {
                                // iterate tables backwards from reader to find inconsistencies faster.
                                for singleton in tables.iter_mut().rev() {
                                    singleton.set(modified);
                                }
                            }); // <--- end locked write ops
                        });
                        gets.join().unwrap();
                        sets.join().unwrap();

                        println!("--- Both threads (reader, writer) finished. restart. ---");

                        // start locked write ops
                        table_singletons.clone().lock_mut(|tables| {
                            for singleton in tables.iter_mut() {
                                singleton.set(orig);
                            }
                        }) // <--- end locked write ops
                    });
                }
            }

            // This test panics thus proving that concurrent reads and writes
            // to multiple DbtSingleton in a `DbtSchema` are not atomic when the
            // DbtSingleton are individually shared between threads.
            //
            // This failure is expected (correct), but somewhat subtle and not
            // immediately obvious if one is expecting atomic read/write guarantee
            // across all `Tables` created by a single `DbtSchema` instance in all cases.
            //
            // This test fails a consistency assertion that all tables should hold the
            // same values. The failure is caused by a non-atomic construction
            // for sharing multiple tables between threads.
            //
            // The construction shared between threads is:
            //   Vec< DbtSingleton<Arc<RwLock<u64>>> >
            //
            // The failing test demonstrates that:
            //   a) a collection of "naked" `DbtSingleton` "tables" is not atomic.
            //   b) `DbtSchema` does not prevent creation of non-atomic multi-table construction
            //   c) It is important to always use a correct atomic construction, such as provided
            //      by `DbtSchema::create_tables_rw()`
            //
            // note: similar tests exist for pre refactored code at:
            // https://github.com/dan-da/twenty-first/blob/088f12d6c46c3a15c8d826f8e20839ad7131f915/twenty-first/src/util_types/storage_schema.rs#L1671
            #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
            #[test]
            pub fn non_atomic_multi_table_set_and_get() {
                let singletons = gen_non_atomic_test_singleton(2);

                let orig = singletons[0].get();
                let modified = orig * 2;

                for i in 0..10000 {
                    thread::scope(|s| {
                        let gets = s.spawn(|| {
                            let mut copies = vec![];
                            for singleton in singletons.iter() {
                                let copy = singleton.get();

                                // Verify that the table is self-consistent.
                                // It must match either the orig template or the modified template.
                                assert!(
                                    copy == orig || copy == modified,
                                    "in test iteration #{}: encountered inconsistent table read. data: {:?}",
                                    i,
                                    copy
                                );

                                copies.push(copy);

                                // this sleep helps find an inconsistency in fewer iterations.
                                std::thread::sleep(std::time::Duration::from_nanos(50));
                            }

                            // Verify that copies are equal. If not, the tables are different from eachother.
                            assert!(
                                iter_all_eq(copies.clone()),
                                "in test iteration #{}: encountered inconsistent read across tables:\n  data: {:?}",
                                i,
                                copies
                            );
                        });

                        let sets = s.spawn(|| {
                            // iterate tables backwards from reader to find inconsistencies faster.
                            for singleton in singletons.clone().iter_mut().rev() {
                                singleton.set(modified);
                            }
                        });
                        gets.join().unwrap();
                        sets.join().unwrap();

                        println!("--- threads finished. restart. ---");

                        for singleton in singletons.clone().iter_mut() {
                            singleton.set(orig);
                        }
                    });
                }
            }
        }

        mod multi_table_storage_vec {
            use super::*;

            fn gen_atomic_rw_test_vecs(num: u8) -> AtomicRw<Vec<TestVec>> {
                // open new DB that will be removed on close.
                let db = DB::open_new_test_database(true, None, None, None).unwrap();
                let mut storage = SimpleRustyStorage::new(db);

                storage.schema.create_tables_rw(|schema| {
                    (0..num)
                        .map(|i| {
                            let mut vec =
                                schema.new_vec::<u64>(&format!("atomicity-test-vector #{}", i));
                            for j in 0u64..300 {
                                vec.push(j);
                            }
                            vec
                        })
                        .collect()
                })
            }

            fn gen_non_atomic_test_vecs(num: u8) -> Vec<TestVec> {
                // open new DB that will be removed on close.
                let db = DB::open_new_test_database(true, None, None, None).unwrap();
                let mut rusty_storage = SimpleRustyStorage::new(db);

                (0..num)
                    .map(|i| {
                        let mut vec = rusty_storage
                            .schema
                            .new_vec::<u64>(&format!("atomicity-test-vector #{}", i));
                        for j in 0u64..300 {
                            vec.push(j);
                        }
                        vec
                    })
                    .collect()
            }

            // This test verifies that concurrent reads and writes
            // to multiple DbtVec in a `DbtSchema` are atomic when
            // using a correct construction with an RwLock placed around a
            // collection holding all the `DbtVec`.
            //
            // It tests two things:
            //  1. That individual tables are atomic within themselves.
            //  2. That the entire set of tables is atomic.
            //
            // The construction shared between threads is:
            //    AtomicRw< Arc<RwLock< Vec< DbtVec<Arc<RwLock<DbtVecPrivate<u64>>>> > >> >
            //    --------------------- ++++ ********************************+++**** + ----
            //
            // * = provided by DbtVec
            // * = provided by AtomicRw
            // + = supplied by application
            //
            // The test passes and demonstrates it is important to always use a
            // correct atomic construction, such as provided by
            // `DbtSchema::create_tables_rw()`
            //
            // note: similar tests exist for pre refactored code at:
            // https://github.com/dan-da/twenty-first/blob/088f12d6c46c3a15c8d826f8e20839ad7131f915/twenty-first/src/util_types/storage_schema.rs#L1671
            #[test]
            pub fn multi_table_atomic_rw_setmany_and_getmany() {
                let table_vecs = gen_atomic_rw_test_vecs(2);

                // performs single-line read lock on table_vecs to copy original state.
                let orig = table_vecs.lock(|tv| tv[0].get_all());

                // make a modified state template setting all values to 50 in all tables.
                let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

                // note: all table vecs have the same length and same values.
                let indices: Vec<_> = (0..orig.len() as u64).collect();

                // this test should never fail.  we only loop 100 times to keep
                // the test fast.  Bump it up to 10000+ temporarily to be extra certain.
                for i in 0..100 {
                    thread::scope(|s| {
                        // This is our reader thread
                        let gets = s.spawn(|| {
                            let mut copies = vec![];

                            // start locked read operations
                            table_vecs.lock(|tables| {
                                for vec in tables.iter() {
                                    let copy = vec.get_many(&indices);

                                    // Verify that the table is self-consistent.
                                    // It must match either the orig template or the modified template.
                                    assert!(
                                        copy == orig || copy == modified,
                                        "in test iteration #{}: encountered inconsistent table read. data: {:?}",
                                        i,
                                        copy
                                    );

                                    copies.push(copy);
                                }
                            }); // <--- end locked read operations

                            let sums: Vec<u64> = copies.iter().map(|f| f.iter().sum()).collect();

                            // Verify that sums are equal. If not, the tables are different from eachother.
                            assert!(
                                iter_all_eq(sums.clone()),
                                "in test iteration #{}: encountered inconsistent read across tables:\n  sums: {:?}\n  data: {:?}",
                                i,
                                sums,
                                copies
                            );
                            println!("sums: {:?}", sums);
                        });

                        // This is our writer thread
                        let sets = s.spawn(|| {
                            // start locked write ops
                            table_vecs.clone().lock_mut(|tables| {
                                // iterate tables backwards from reader to find inconsistencies faster.
                                for vec in tables.iter_mut().rev() {
                                    vec.set_many(
                                        orig.iter().enumerate().map(|(k, _v)| (k as u64, 50u64)),
                                    );
                                }
                            }); // <--- end locked write ops
                        });
                        gets.join().unwrap();
                        sets.join().unwrap();

                        println!("--- Both threads (reader, writer) finished. restart. ---");

                        // start locked write ops
                        table_vecs.clone().lock_mut(|tables| {
                            for vec in tables.iter_mut() {
                                vec.set_all(orig.clone());
                            }
                        }) // <--- end locked write ops
                    });
                }
            }

            // This test panics thus proving that concurrent reads and writes
            // to multiple DbtVec in a `DbtSchema` are not atomic when the DbtVec are
            // individually shared between threads.
            //
            // This failure is expected (correct), but somewhat subtle and not
            // immediately obvious if one is expecting atomic read/write guarantee
            // across all `Tables` created by a single `DbtSchema` instance in all cases.
            //
            // This test fails a consistency assertion that all tables should hold the
            // same values. The failure is caused by a non-atomic construction
            // for sharing multiple tables between threads.
            //
            // The construction shared between threads is:
            //   Vec< DbtVec<Arc<RwLock<u64>>> >
            //
            // The failing test demonstrates that:
            //   a) a collection of "naked" `DbtVec` "tables" is not atomic.
            //   b) `DbtSchema` does not prevent creation of non-atomic multi-table construction
            //   c) It is important to always use a correct atomic construction, such as provided
            //      by `DbtSchema::create_tables_rw()`
            //
            // note: similar tests exist for pre refactored code at:
            // https://github.com/dan-da/twenty-first/blob/088f12d6c46c3a15c8d826f8e20839ad7131f915/twenty-first/src/util_types/storage_schema.rs#L1671
            #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Any { .. }")]
            #[test]
            pub fn non_atomic_multi_table_setmany_and_getmany() {
                let vecs = gen_non_atomic_test_vecs(2);
                let orig = vecs[0].get_all();
                let modified: Vec<u64> = orig.iter().map(|_| 50).collect();

                // note: all vecs have the same length and same values.
                let indices: Vec<_> = (0..orig.len() as u64).collect();

                for i in 0..10000 {
                    thread::scope(|s| {
                        let gets = s.spawn(|| {
                            let mut copies = vec![];
                            for vec in vecs.iter() {
                                let copy = vec.get_many(&indices);

                                // Verify that the table is self-consistent.
                                // It must match either the orig template or the modified template.
                                assert!(
                                    copy == orig || copy == modified,
                                    "in test iteration #{}: encountered inconsistent table read. data: {:?}",
                                    i,
                                    copy
                                );

                                copies.push(copy);

                                // this sleep helps find an inconsistency in fewer iterations.
                                std::thread::sleep(std::time::Duration::from_nanos(50));
                            }

                            let sums: Vec<u64> = copies.iter().map(|f| f.iter().sum()).collect();

                            // Verify that sums are equal. If not, the tables are different from eachother.
                            assert!(
                                iter_all_eq(sums.clone()),
                                "in test iteration #{}: encountered inconsistent read across tables:\n  sums: {:?}\n  data: {:?}",
                                i,
                                sums,
                                copies
                            );
                            println!("sums: {:?}", sums);
                        });

                        let sets = s.spawn(|| {
                            // iterate tables backwards from reader to find inconsistencies faster.
                            for vec in vecs.clone().iter_mut().rev() {
                                vec.set_many(
                                    orig.iter().enumerate().map(|(k, _v)| (k as u64, 50u64)),
                                );
                            }
                        });
                        gets.join().unwrap();
                        sets.join().unwrap();

                        println!("--- threads finished. restart. ---");

                        for vec in vecs.clone().iter_mut() {
                            vec.set_all(orig.clone());
                        }
                    });
                }
            }
        }
    }
}
