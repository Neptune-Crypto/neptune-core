use divan::Bencher;
use leveldb::batch::WriteBatch;
use leveldb::options::Options;
use leveldb::options::ReadOptions;
use leveldb::options::WriteOptions;
use leveldb_sys::Compression;
use neptune_cash::application::database::leveldb::DB;

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
/// Important: the default settings are not optimal,
///  eg: no read cache.
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
        // cache: None,
        cache: None,
        // note: tests put 128 bytes in each entry.
        // 100 entries = 12,800 bytes.
        //
        // Warning: WriteBatch.put() tends to crash
        // when this value is Some(Cache::new(..))
        // instead of None.
    }
}

fn read_options(verify_checksums: bool, fill_cache: bool) -> ReadOptions {
    ReadOptions {
        verify_checksums,
        fill_cache,
    }
}
fn read_options_default() -> ReadOptions {
    ReadOptions::new()
}

fn write_options(sync: bool) -> WriteOptions {
    WriteOptions { sync }
}

fn value() -> Vec<u8> {
    (0..127).collect()
}

mod write_100_entries {
    use super::*;

    // note: numbers > 100 make the sync_on_write::put() test really slow.
    const NUM_WRITE_ITEMS: u32 = 100;

    mod puts {
        use super::*;

        fn put(bencher: Bencher, sync: bool) {
            let mut db = DB::open_new_test_database(
                true,
                Some(db_options()),
                Some(read_options_default()),
                Some(write_options(sync)),
            )
            .unwrap();

            bencher.bench_local(|| {
                for i in 0..NUM_WRITE_ITEMS {
                    let _ = db.put(&i, &value());
                }
            });
        }

        fn batch_put(bencher: Bencher, sync: bool) {
            let mut db = DB::open_new_test_database(
                true,
                Some(db_options()),
                Some(read_options_default()),
                Some(write_options(sync)),
            )
            .unwrap();

            bencher.bench_local(|| {
                let wb = WriteBatch::new();
                for i in 0..NUM_WRITE_ITEMS {
                    wb.put(&i, &value());
                }
                let _ = db.write(&wb, sync);
            });
        }

        fn batch_put_write(bencher: Bencher, sync: bool) {
            let mut db = DB::open_new_test_database(
                true,
                Some(db_options()),
                Some(read_options_default()),
                Some(write_options(sync)),
            )
            .unwrap();

            let wb = WriteBatch::new();
            for i in 0..NUM_WRITE_ITEMS {
                wb.put(&i, &value());
            }

            bencher.bench_local(|| {
                let _ = db.write(&wb, sync);
            });
        }

        mod sync_on_write {
            use super::*;

            #[divan::bench]
            fn put(bencher: Bencher) {
                super::put(bencher, true);
            }

            #[divan::bench]
            fn batch_put(bencher: Bencher) {
                super::batch_put(bencher, true);
            }

            #[divan::bench]
            fn batch_put_write(bencher: Bencher) {
                super::batch_put_write(bencher, true);
            }
        }

        mod no_sync_on_write {
            use super::*;

            #[divan::bench]
            fn put(bencher: Bencher) {
                super::put(bencher, false);
            }

            #[divan::bench]
            fn batch_put(bencher: Bencher) {
                super::batch_put(bencher, false);
            }

            #[divan::bench]
            fn batch_put_write(bencher: Bencher) {
                super::batch_put_write(bencher, false);
            }
        }
    }

    mod deletes {
        use super::*;

        fn delete(bencher: Bencher, sync: bool) {
            let mut db = DB::open_new_test_database(
                true,
                Some(db_options()),
                Some(read_options_default()),
                Some(write_options(sync)),
            )
            .unwrap();

            for i in 0..NUM_WRITE_ITEMS {
                let _ = db.put(&i, &value());
            }

            bencher.bench_local(|| {
                for i in 0..NUM_WRITE_ITEMS {
                    let _ = db.delete(&i);
                }
            });
        }

        fn batch_delete(bencher: Bencher, sync: bool) {
            let mut db = DB::open_new_test_database(
                true,
                Some(db_options()),
                Some(read_options_default()),
                Some(write_options(sync)),
            )
            .unwrap();

            // batch write items, unsync
            let wb = WriteBatch::new();
            for i in 0..NUM_WRITE_ITEMS {
                wb.put(&i, &value());
            }
            let _ = db.write(&wb, false);

            // batch delete items, sync
            let wb_del = WriteBatch::new();

            bencher.bench_local(|| {
                for i in 0..NUM_WRITE_ITEMS {
                    wb.delete(&i);
                }
                let _ = db.write(&wb_del, sync);
            });
        }

        fn batch_delete_write(bencher: Bencher, sync: bool) {
            let mut db = DB::open_new_test_database(
                true,
                Some(db_options()),
                Some(read_options_default()),
                Some(write_options(sync)),
            )
            .unwrap();

            // batch write items, unsync
            let wb = WriteBatch::new();
            for i in 0..NUM_WRITE_ITEMS {
                wb.put(&i, &value());
            }
            let _ = db.write(&wb, false);

            // batch delete items, sync
            let wb_del = WriteBatch::new();
            for i in 0..NUM_WRITE_ITEMS {
                wb.delete(&i);
            }

            bencher.bench_local(|| {
                let _ = db.write(&wb_del, sync);
            });
        }

        mod sync_on_write {
            use super::*;

            #[divan::bench]
            fn delete(bencher: Bencher) {
                super::delete(bencher, true);
            }

            #[divan::bench]
            fn batch_delete(bencher: Bencher) {
                super::batch_delete(bencher, true);
            }

            #[divan::bench]
            fn batch_delete_write(bencher: Bencher) {
                super::batch_delete_write(bencher, true);
            }
        }

        mod no_sync_on_write {
            use super::*;

            #[divan::bench]
            fn delete(bencher: Bencher) {
                super::delete(bencher, false);
            }

            #[divan::bench]
            fn batch_delete(bencher: Bencher) {
                super::batch_delete(bencher, false);
            }

            #[divan::bench]
            fn batch_delete_write(bencher: Bencher) {
                super::batch_delete_write(bencher, false);
            }
        }
    }
}

mod read_100_entries {
    use super::*;

    const NUM_READ_ITEMS: u32 = 100;

    mod gets {
        use super::*;

        fn get(bencher: Bencher, num_reads: usize, cache: bool, verify_checksum: bool) {
            let mut db = DB::open_new_test_database(
                true,
                Some(db_options()),
                Some(read_options(verify_checksum, cache)),
                Some(write_options(false)),
            )
            .unwrap();

            for i in 0..NUM_READ_ITEMS {
                let _ = db.put(&i, &value());
            }

            bencher.bench_local(|| {
                for i in 0..NUM_READ_ITEMS {
                    for _j in 0..num_reads {
                        let _ = db.get(&i);
                    }
                }
            });
        }

        mod get_each_entry_1_time {
            use super::*;

            mod fill_cache {
                use super::*;

                mod verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 1, true, true);
                    }
                }

                mod no_verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 1, true, false);
                    }
                }
            }
            mod no_fill_cache {
                use super::*;

                mod verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 1, false, true);
                    }
                }

                mod no_verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 1, false, false);
                    }
                }
            }
        }

        mod get_each_entry_20_times {
            use super::*;

            mod fill_cache {
                use super::*;

                mod verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 20, true, true);
                    }
                }

                mod no_verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 20, true, false);
                    }
                }
            }
            mod no_fill_cache {
                use super::*;

                mod verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 20, false, true);
                    }
                }

                mod no_verify_checksums {
                    use super::*;

                    #[divan::bench]
                    fn get(bencher: Bencher) {
                        super::get(bencher, 20, false, false);
                    }
                }
            }
        }
    }
}

mod storage_schema {
    mod dbtvec {}
}

mod storage_vec {}
