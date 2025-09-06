use divan::Bencher;
use leveldb::options::Options;
use leveldb::options::ReadOptions;
use leveldb::options::WriteOptions;
use leveldb_sys::Compression;
use neptune_cash::application::database::storage::storage_schema::traits::*;
use neptune_cash::application::database::storage::storage_schema::DbtVec;
use neptune_cash::application::database::storage::storage_schema::SimpleRustyStorage;
use neptune_cash::application::database::storage::storage_vec::traits::StorageVecBase;
use neptune_cash::application::database::NeptuneLevelDb;
use neptune_cash::util_types::archival_mmr::ArchivalMmr;
use rand::random;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::num_leafs_to_num_nodes;

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

async fn new_ammr(leaf_count: u64) -> (SimpleRustyStorage, ArchivalMmr<DbtVec<Digest>>) {
    let db = NeptuneLevelDb::open_new_test_database(
        false,
        Some(db_options()),
        Some(ReadOptions {
            verify_checksums: false,
            fill_cache: false,
        }),
        Some(WriteOptions { sync: true }),
    )
    .await
    .unwrap();
    let mut rusty_storage = SimpleRustyStorage::new(db);
    let mut nv = rusty_storage
        .schema
        .new_vec::<Digest>("test-archival-mmr")
        .await;

    // Add the dummy node since nodes are 1-indexed in AMMRs.
    nv.push(Digest::default()).await;

    let num_nodes = num_leafs_to_num_nodes(leaf_count);
    for _ in 0..num_nodes {
        nv.push(random()).await;
    }

    (rusty_storage, ArchivalMmr::new(nv).await)
}

mod append {
    use super::*;

    mod append_5000 {
        const NUM_WRITE_ITEMS: usize = 5000;
        const INIT_AMMR_LEAF_COUNT: u64 = 0;
        use tasm_lib::twenty_first::math::other::random_elements;

        use super::*;

        fn append_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut ammr) = rt.block_on(new_ammr(INIT_AMMR_LEAF_COUNT));
            let digests = random_elements(NUM_WRITE_ITEMS);

            bencher.bench_local(|| {
                rt.block_on(async {
                    for new_leaf in &digests {
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

mod mutate {
    use super::*;

    mod mutate_100_of_10000 {
        use itertools::Itertools;
        use rand::Rng;
        use tasm_lib::twenty_first::math::other::random_elements;

        use super::*;

        const NUM_MUTATIONS: usize = 100;
        const AMMR_LEAF_COUNT: u64 = 10000;

        fn leaf_mutation_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut ammr) = rt.block_on(new_ammr(AMMR_LEAF_COUNT));
            let mut rng = rand::rng();
            let digests = random_elements(NUM_MUTATIONS);
            let leaf_index_of_mutated_leafs = (0..NUM_MUTATIONS as u64)
                .map(|_| rng.random_range(0..AMMR_LEAF_COUNT))
                .collect_vec();

            bencher.bench_local(|| {
                rt.block_on(async {
                    for (new_leaf, leaf_index) in
                        digests.iter().zip(leaf_index_of_mutated_leafs.iter())
                    {
                        ammr.mutate_leaf(*leaf_index, *new_leaf).await;
                    }
                    if persist {
                        storage.persist().await;
                    }
                });
            });
        }

        #[divan::bench]
        fn leaf_mutation(bencher: Bencher) {
            leaf_mutation_impl(bencher, false);
        }

        #[divan::bench]
        fn leaf_mutation_and_persist(bencher: Bencher) {
            leaf_mutation_impl(bencher, true);
        }
    }
}

mod batch_mutate_leaf_and_update_mps {
    use super::*;

    mod mutate_100_of_10000 {
        use itertools::Itertools;
        use rand::Rng;
        use tasm_lib::twenty_first::math::other::random_elements;

        use super::*;

        const NUM_MUTATIONS_IN_BATCH: usize = 100;
        const AMMR_LEAF_COUNT: u64 = 10000;

        fn batch_leaf_mutation_impl(bencher: Bencher, persist: bool) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (mut storage, mut ammr) = rt.block_on(new_ammr(AMMR_LEAF_COUNT));
            let mut rng = rand::rng();
            let new_digests = random_elements(NUM_MUTATIONS_IN_BATCH);
            let mut leaf_index_of_mutated_leafs = (0..NUM_MUTATIONS_IN_BATCH as u64)
                .map(|_| rng.random_range(0..AMMR_LEAF_COUNT))
                .collect_vec();
            leaf_index_of_mutated_leafs.sort();
            leaf_index_of_mutated_leafs.dedup();

            let mutation_data = leaf_index_of_mutated_leafs
                .into_iter()
                .zip(new_digests)
                .collect_vec();

            let mut leaf_indices_for_mps_to_preserve = (0..NUM_MUTATIONS_IN_BATCH as u64)
                .map(|_| rng.random_range(0..AMMR_LEAF_COUNT))
                .collect_vec();
            leaf_indices_for_mps_to_preserve.sort();
            leaf_indices_for_mps_to_preserve.dedup();

            let mut mps = leaf_indices_for_mps_to_preserve
                .iter()
                .map(|i| rt.block_on(async { ammr.prove_membership_async(*i).await }))
                .collect_vec();

            bencher.bench_local(|| {
                rt.block_on(async {
                    ammr.batch_mutate_leaf_and_update_mps(
                        &mut mps.iter_mut().collect_vec(),
                        mutation_data.clone(),
                    )
                    .await;
                    if persist {
                        storage.persist().await;
                    }
                });
            });
        }

        #[divan::bench]
        fn leaf_mutation(bencher: Bencher) {
            batch_leaf_mutation_impl(bencher, false);
        }

        #[divan::bench]
        fn leaf_mutation_and_persist(bencher: Bencher) {
            batch_leaf_mutation_impl(bencher, true);
        }
    }
}

mod get_peaks {
    use super::*;

    mod get_peaks_of_about_1m {
        use super::*;

        const AMMR_LEAF_COUNT: u64 = 1_001_003;

        fn get_peaks_impl(bencher: Bencher) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let (_, ammr) = rt.block_on(new_ammr(AMMR_LEAF_COUNT));

            bencher.bench_local(|| {
                rt.block_on(async {
                    ammr.peaks().await;
                });
            });
        }

        #[divan::bench]
        fn get_peaks(bencher: Bencher) {
            get_peaks_impl(bencher);
        }
    }
}
