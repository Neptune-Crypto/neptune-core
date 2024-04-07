use divan::Bencher;
use leveldb::options::Options;
use leveldb::options::ReadOptions;
use leveldb::options::WriteOptions;
use leveldb_sys::Compression;
use neptune_core::database::storage::storage_schema::traits::*;
use neptune_core::database::storage::storage_schema::DbtVec;
use neptune_core::database::storage::storage_schema::SimpleRustyStorage;
use neptune_core::database::NeptuneLevelDb;
use neptune_core::util_types::mutator_set::archival_mmr::ArchivalMmr;
use tasm_lib::twenty_first::shared_math::tip5::Tip5;
use tasm_lib::Digest;

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
fn db_options() -> Option<Options> {
    Some(Options {
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
    })
}

async fn empty_ammr() -> (SimpleRustyStorage, ArchivalMmr<Tip5, DbtVec<Digest>>) {
    let db = NeptuneLevelDb::open_new_test_database(
        false,
        db_options(),
        Some(ReadOptions {
            verify_checksums: false,
            fill_cache: false,
        }),
        Some(WriteOptions { sync: true }),
    )
    .await
    .unwrap();
    let mut rusty_storage = SimpleRustyStorage::new(db);
    let nv = rusty_storage
        .schema
        .new_vec::<Digest>("test-archival-mmr")
        .await;

    (rusty_storage, ArchivalMmr::new(nv).await)
}

mod append {
    use super::*;

    mod append_5000 {
        const NUM_WRITE_ITEMS: usize = 5000;
        use tasm_lib::twenty_first::shared_math::other::random_elements;

        use super::*;

        fn append_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut ammr) = rt.block_on(empty_ammr());
            let digests = random_elements(NUM_WRITE_ITEMS);

            bencher.bench_local(|| {
                rt.block_on(async {
                    for new_leaf in digests.iter() {
                        ammr.append(*new_leaf).await;
                    }
                    if persist {
                        storage.persist().await;
                    }
                });
            });
        }

        #[divan::bench]
        fn append(bencher: Bencher) {
            append_impl(bencher, false);
        }

        #[divan::bench]
        fn append_and_persist(bencher: Bencher) {
            append_impl(bencher, true);
        }
    }
}
