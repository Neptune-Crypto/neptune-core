use divan::Bencher;
use leveldb::options::Options;
use leveldb::options::ReadOptions;
use leveldb::options::WriteOptions;
use leveldb_sys::Compression;
use neptune_cash::application::database::storage::storage_schema::traits::*;
use neptune_cash::application::database::storage::storage_schema::DbtVec;
use neptune_cash::application::database::storage::storage_schema::SimpleRustyStorage;
use neptune_cash::application::database::storage::storage_vec::traits::*;
use neptune_cash::application::database::NeptuneLevelDb;

// These database bench tests are made with divan.
//
// See:
//  https://nikolaivazquez.com/blog/divan/
//  https://docs.rs/divan/0.1.0/divan/attr.bench.html
//  https://github.com/nvzqz/divan
//
//  Options for #[bench] attr:
//   https://docs.rs/divan/0.1.0/divan/attr.bench.html#options
//
//   name, crate, consts, types, sample_count, sample_size, threads
//   counters, min_time, max_time, skip_ext_time, ignore

fn main() {
    divan::main();
}

/// These settings affect DB performance and correctness.
///
/// Adjust and re-run the benchmarks to see effects.
///
/// Rust docs:  (basic)
///   https://docs.rs/rs-leveldb/0.1.5/leveldb/database/options/struct.Options.html
///
/// C++ docs:  (complete)
///   https://github.com/google/leveldb/blob/068d5ee1a3ac40dabd00d211d5013af44be55bea/include/leveldb/options.h
fn db_options() -> Options {
    Options {
        // default: false
        create_if_missing: true,

        // default: false
        error_if_exists: true,

        // default: false
        paranoid_checks: false,

        // default: None  --> (4 * 1024 * 1024)
        write_buffer_size: None,

        // default: None   --> 1000
        max_open_files: None,

        // default: None   -->  4 * 1024
        block_size: None,

        // default: None   -->  16
        block_restart_interval: None,

        // default: Compression::No
        //      or: Compression::Snappy
        compression: Compression::No,

        // default: None   --> 8MB
        cache: None,
        // cache: Some(Cache::new(1024)),
        // note: tests put 128 bytes in each entry.
        // 100 entries = 12,800 bytes.
        // So Cache of 1024 bytes is 8% of total data set.
        // that seems reasonably realistic to get some
        // hits/misses.
    }
}

fn value() -> Vec<u8> {
    (0..127).collect()
}

async fn create_test_dbtvec() -> (SimpleRustyStorage, DbtVec<Vec<u8>>) {
    let db = NeptuneLevelDb::open_new_test_database(
        true,
        Some(db_options()),
        Some(ReadOptions {
            verify_checksums: false,
            fill_cache: false,
        }),
        Some(WriteOptions { sync: true }),
    )
    .await
    .unwrap();
    let mut storage = SimpleRustyStorage::new(db);
    let vec = storage.schema.new_vec::<Vec<u8>>("test-vector").await;
    (storage, vec)
}

mod write_100_entries {
    use super::*;

    // note: numbers > 100 make the sync_on_write::put() test really slow.
    const NUM_WRITE_ITEMS: u64 = 100;

    mod push {
        use super::*;

        fn push_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut vector) = rt.block_on(create_test_dbtvec());

            bencher.bench_local(|| {
                rt.block_on(async {
                    for _i in 0..NUM_WRITE_ITEMS {
                        vector.push(value()).await;
                    }
                    if persist {
                        storage.persist().await;
                    }
                });
            });
        }

        #[divan::bench]
        fn push(bencher: Bencher) {
            push_impl(bencher, false);
        }

        #[divan::bench]
        fn push_and_persist(bencher: Bencher) {
            push_impl(bencher, true);
        }
    }

    mod set {
        use super::*;

        fn set_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut vector) = rt.block_on(create_test_dbtvec());

            for _i in 0..NUM_WRITE_ITEMS {
                rt.block_on(vector.push(value()));
            }

            bencher.bench_local(|| {
                rt.block_on(async {
                    for i in 0..NUM_WRITE_ITEMS {
                        vector.set(i, value()).await;
                    }

                    if persist {
                        storage.persist().await;
                    }
                });
            });
        }

        #[divan::bench]
        fn set(bencher: Bencher) {
            set_impl(bencher, false);
        }

        #[divan::bench]
        fn set_and_persist(bencher: Bencher) {
            set_impl(bencher, true);
        }
    }

    mod set_many {
        use super::*;

        fn set_many_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut vector) = rt.block_on(create_test_dbtvec());

            for _ in 0..NUM_WRITE_ITEMS {
                rt.block_on(vector.push(vec![42]));
            }

            bencher.bench_local(|| {
                rt.block_on(async {
                    let values: Vec<_> = (0..NUM_WRITE_ITEMS).map(|i| (i, value())).collect();
                    vector.set_many(values).await;
                    if persist {
                        storage.persist().await
                    }
                });
            });
        }

        #[divan::bench]
        fn set_many(bencher: Bencher) {
            set_many_impl(bencher, false);
        }

        #[divan::bench]
        fn set_many_and_persist(bencher: Bencher) {
            set_many_impl(bencher, true);
        }
    }

    mod pop {
        use super::*;

        fn pop_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut vector) = rt.block_on(create_test_dbtvec());

            for _i in 0..NUM_WRITE_ITEMS {
                rt.block_on(vector.push(value()));
            }

            bencher.bench_local(|| {
                rt.block_on(async {
                    for _i in 0..NUM_WRITE_ITEMS {
                        vector.pop().await;
                    }

                    if persist {
                        storage.persist().await;
                    }
                });
            });
        }

        #[divan::bench]
        fn pop(bencher: Bencher) {
            pop_impl(bencher, false);
        }

        #[divan::bench]
        fn pop_and_persist(bencher: Bencher) {
            pop_impl(bencher, true);
        }
    }
}

mod read_100_entries {
    use super::*;

    const NUM_READ_ITEMS: u64 = 100;

    fn get_impl(bencher: Bencher, num_each: usize, persisted: bool) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let vector = rt.block_on(async {
            let (mut storage, mut vector) = create_test_dbtvec().await;

            for _i in 0..NUM_READ_ITEMS {
                vector.push(value()).await;
            }
            if persisted {
                storage.persist().await;
            }
            vector
        });

        bencher.bench_local(|| {
            rt.block_on(async {
                for i in 0..NUM_READ_ITEMS {
                    for _j in 0..num_each {
                        let _ = vector.get(i).await;
                    }
                }
            });
        });
    }

    fn get_many_impl(bencher: Bencher, num_each: usize, persisted: bool) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let vector = rt.block_on(async {
            let (mut storage, mut vector) = create_test_dbtvec().await;

            for _i in 0..NUM_READ_ITEMS {
                vector.push(value()).await;
            }
            if persisted {
                storage.persist().await;
            }
            vector
        });

        let indices: Vec<u64> = (0..NUM_READ_ITEMS).collect();
        bencher.bench_local(|| {
            rt.block_on(async {
                for _j in 0..num_each {
                    let _ = vector.get_many(&indices).await;
                }
            });
        });
    }

    mod get_each_entry_1_time {
        use super::*;

        mod persisted {
            use super::*;

            #[divan::bench]
            fn get(bencher: Bencher) {
                get_impl(bencher, 1, true);
            }

            #[divan::bench]
            fn get_many(bencher: Bencher) {
                get_many_impl(bencher, 1, true);
            }
        }

        mod unpersisted {
            use super::*;

            #[divan::bench]
            fn get(bencher: Bencher) {
                get_impl(bencher, 1, false);
            }

            #[divan::bench]
            fn get_many(bencher: Bencher) {
                get_many_impl(bencher, 1, false);
            }
        }
    }

    mod get_each_entry_20_times {
        use super::*;

        mod persisted {
            use super::*;

            #[divan::bench]
            fn get(bencher: Bencher) {
                get_impl(bencher, 20, true);
            }

            #[divan::bench]
            fn get_many(bencher: Bencher) {
                get_many_impl(bencher, 20, true);
            }
        }

        mod unpersisted {
            use super::*;

            #[divan::bench]
            fn get(bencher: Bencher) {
                get_impl(bencher, 20, false);
            }

            #[divan::bench]
            fn get_many(bencher: Bencher) {
                get_many_impl(bencher, 20, false);
            }
        }
    }
}
