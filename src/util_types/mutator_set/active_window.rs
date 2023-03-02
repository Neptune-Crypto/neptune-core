use itertools::Itertools;
use rusty_leveldb::{LdbIterator, DB};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::Range;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};
use twenty_first::util_types::database_vector::DatabaseVector;

use super::chunk::Chunk;
use super::shared::{CHUNK_SIZE, WINDOW_SIZE};

#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct ActiveWindow<H: AlgebraicHasher> {
    // It's OK to store this in memory, since it's on the size of kilobytes, not gigabytes.
    pub sbf: Vec<u32>,
    _hasher: PhantomData<H>,
}

impl<H: AlgebraicHasher> PartialEq for ActiveWindow<H> {
    fn eq(&self, other: &Self) -> bool {
        self.sbf == other.sbf
    }
}

impl<H: AlgebraicHasher> Default for ActiveWindow<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: AlgebraicHasher> ActiveWindow<H> {
    pub fn new() -> Self {
        Self {
            sbf: Vec::new(),
            _hasher: PhantomData,
        }
    }
    /// Populate an database with the values in this active window.
    /// This is used to persist the state of an archival mutator set.
    pub fn store_to_database(&self, mut db: DB) -> DB {
        let db_is_empty = db
            .new_iter()
            .expect("Must be able to create DB iterator")
            .next()
            .is_none();
        let mut database_vector = if db_is_empty {
            DatabaseVector::new(db)
        } else {
            DatabaseVector::restore(db)
        };
        database_vector.overwrite_with_vec(self.sbf.clone());
        database_vector.extract_db()
    }

    /// Given a database object that has been stored on disk, return an ActiveWindow object
    pub fn restore_from_database(db: DB) -> Self {
        let mut database_vector: DatabaseVector<u32> = DatabaseVector::restore(db);
        let db_entry_count: u128 = database_vector.len();
        let mut active_window = ActiveWindow::default();

        for i in 0..db_entry_count {
            let index = database_vector.get(i);
            active_window.insert(index)
        }

        active_window
    }

    /// Grab a slice from the sparse Bloom filter by supplying an
    /// interval. Given how the
    /// sparse Bloom filter is represented (i.e., as a list of
    /// indices), this operation boils down to copying all indices
    /// that live in the range and subtracting the lower bound from
    /// them.
    /// The word "slice" is used in the denotation of submatrices not
    /// rust's contiguous memory structures.
    fn slice(&self, interval: Range<u32>) -> Vec<u32> {
        let indices = self
            .sbf
            .iter()
            .filter(|l| interval.contains(*l))
            .map(|l| *l - interval.start)
            .collect_vec();
        indices
    }

    /// Get the chunk of the active window that, upon sliding, becomes
    /// inactive.
    pub fn slid_chunk(&self) -> Chunk {
        Chunk::from_indices(&self.slice(0..CHUNK_SIZE))
    }

    /// Set range to zero.
    fn zerofy(&mut self, lower: u32, upper: u32) {
        // locate
        let mut drops = Vec::new();
        for (location_index, location) in self.sbf.iter().enumerate() {
            if lower <= *location && *location < upper {
                drops.push(location_index);
            }
        }

        // drop
        for d in drops.iter().rev() {
            self.sbf.remove(*d);
        }
    }

    /// Slide the window: drop all integers indexing into the first
    /// chunk, and subtract CHUNK_SIZE from all others.
    pub fn slide_window(&mut self) {
        self.zerofy(0, CHUNK_SIZE);
        for location in self.sbf.iter_mut() {
            *location -= CHUNK_SIZE;
        }
    }

    /// Return true iff there is a set integer in the given range.
    fn hasset(&self, lower: u32, upper: u32) -> bool {
        for location in self.sbf.iter() {
            if lower <= *location && *location < upper {
                return true;
            }
        }
        false
    }

    /// Undo a window slide.
    pub fn slide_window_back(&mut self, chunk: &Chunk) {
        assert!(!self.hasset(WINDOW_SIZE - CHUNK_SIZE, WINDOW_SIZE));
        for location in self.sbf.iter_mut() {
            *location += CHUNK_SIZE;
        }
        let indices = chunk.to_indices();
        for index in indices {
            self.sbf.push(index);
        }
        self.sbf.sort();
    }

    pub fn insert(&mut self, index: u32) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `insert`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );
        self.sbf.push(index);
        self.sbf.sort();
    }

    pub fn remove(&mut self, index: u32) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `remove`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );

        // locate
        let mut found = false;
        let mut drop_index_index = 0;
        for (index_index, index_value) in self.sbf.iter().enumerate() {
            if *index_value == index {
                found = true;
                drop_index_index = index_index;
            }
        }

        // if found, drop
        if found {
            self.sbf.remove(drop_index_index);
        }

        // if not found, the indicated integer is zero
        if !found {
            panic!("Decremented integer is already zero.");
        }
    }

    pub fn contains(&self, index: u32) -> bool {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `contains`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );

        for loc in self.sbf.iter() {
            if *loc == index {
                return true;
            }
        }
        false
    }

    pub fn to_vec_u32(&self) -> Vec<u32> {
        self.sbf.clone()
    }

    pub fn from_vec_u32(vector: &[u32]) -> Self {
        Self {
            sbf: vector.to_vec(),
            _hasher: PhantomData,
        }
    }
}

impl<H: AlgebraicHasher> Hashable for ActiveWindow<H> {
    fn to_sequence(&self) -> Vec<twenty_first::shared_math::b_field_element::BFieldElement> {
        self.sbf
            .iter()
            .flat_map(|u128| u128.to_sequence())
            .collect()
    }
}

#[cfg(test)]
mod active_window_tests {

    use super::*;
    use rand::{thread_rng, RngCore};
    use twenty_first::shared_math::rescue_prime_regular::RescuePrimeRegular;

    impl<H: AlgebraicHasher> ActiveWindow<H> {
        fn new_from(sbf: Vec<u32>) -> Self {
            Self {
                sbf,
                _hasher: PhantomData,
            }
        }
    }

    #[test]
    fn insert_remove_probe_indices_pbt() {
        let sbf = Vec::<u32>::new();
        let mut aw = ActiveWindow::<blake3::Hasher>::new_from(sbf);
        for i in 0..100 {
            assert!(!aw.contains(i as u32));
        }

        let mut prng = thread_rng();
        for _ in 0..100 {
            let index = prng.next_u32() % WINDOW_SIZE;
            aw.insert(index);

            assert!(aw.contains(index));
        }

        // Set all indices, then check that they are set
        for i in 0..100 {
            aw.insert(i);
        }

        for i in 0..100 {
            assert!(aw.contains(i as u32));
        }
    }

    #[test]
    fn test_slide_window() {
        let mut aw = ActiveWindow::<blake3::Hasher>::new();

        let num_insertions = 100;
        let mut rng = thread_rng();
        for _ in 0..num_insertions {
            aw.insert(rng.next_u32() % WINDOW_SIZE);
        }

        aw.slide_window();

        // Verify that last N elements are zero after window slide
        assert!(!aw.hasset(WINDOW_SIZE - CHUNK_SIZE, CHUNK_SIZE));
    }

    #[test]
    fn test_slide_window_back() {
        type Hasher = blake3::Hasher;

        let mut active_window = ActiveWindow::<Hasher>::new();
        let num_insertions = 1000;
        let mut rng = thread_rng();
        for _ in 0..num_insertions {
            active_window.insert((rng.next_u32()) % WINDOW_SIZE);
        }
        let dummy_chunk = active_window.slid_chunk();
        active_window.slide_window();
        assert!(!active_window.hasset(WINDOW_SIZE - CHUNK_SIZE, WINDOW_SIZE));

        active_window.slide_window_back(&dummy_chunk);
        for index in dummy_chunk.relative_indices {
            assert!(active_window.contains(index));
        }
    }

    #[test]
    fn test_slide_window_and_back() {
        type Hasher = blake3::Hasher;

        let mut active_window = ActiveWindow::<Hasher>::new();
        let num_insertions = 1000;
        let mut rng = thread_rng();
        for _ in 0..num_insertions {
            active_window.insert((rng.next_u32()) % WINDOW_SIZE);
        }
        let aw_before = active_window.clone();

        let chunk = active_window.slid_chunk();

        active_window.slide_window();

        active_window.slide_window_back(&chunk);
        let aw_after = active_window.clone();

        assert_eq!(
            aw_before, aw_after,
            "Sliding forward and then back must be the identity operation."
        );
    }

    fn hash_unequal<H: AlgebraicHasher>() {
        H::hash(&ActiveWindow::<H>::new());

        let mut aw_1 = ActiveWindow::<H>::new();
        aw_1.insert(1u32);
        let aw_2 = ActiveWindow::<H>::new();

        assert_ne!(H::hash(&aw_1), H::hash(&aw_2));
    }

    #[test]
    fn test_hash_unequal_nocrash() {
        // This is just a test to ensure that the hashing of the active part of the SWBF
        // works in the runtime, for relevant hash functions. It also tests that different
        // indices being inserted results in different digests.
        hash_unequal::<blake3::Hasher>();
        hash_unequal::<RescuePrimeRegular>();
    }

    #[test]
    fn test_active_window_serialization() {
        type H = RescuePrimeRegular;

        let aw0 = ActiveWindow::<H>::new();
        let json_aw0 = serde_json::to_string(&aw0).unwrap();
        let aw0_back = serde_json::from_str::<ActiveWindow<H>>(&json_aw0).unwrap();
        assert_eq!(aw0.sbf, aw0_back.sbf);
    }

    #[test]
    fn test_store_load_database() {
        // populate active window
        type Hasher = blake3::Hasher;

        let mut active_window = ActiveWindow::<Hasher>::new();
        let num_insertions = 1000;
        let mut rng = thread_rng();
        for _ in 0..num_insertions {
            active_window.insert(rng.next_u32() % WINDOW_SIZE);
        }

        // prepare database for storing / loading
        let opt = rusty_leveldb::in_memory();
        let mut active_window_db = DB::open("active_window", opt.clone()).unwrap();

        // store active window to database
        active_window_db = active_window.store_to_database(active_window_db);
        active_window_db.flush().expect("Flush failure");

        // load active window from database
        let restored_active_window = ActiveWindow::restore_from_database(active_window_db);

        // assert equality
        assert_eq!(active_window, restored_active_window);

        // populate with more indices
        for _ in 0..num_insertions {
            active_window.insert(rng.next_u32() % WINDOW_SIZE);
        }

        // store active window to database
        active_window_db = DB::open("active_window", opt.clone()).unwrap();
        active_window_db = active_window.store_to_database(active_window_db);
        active_window_db.flush().expect("Flush failure");

        // load active window from database
        let restored_active_window = ActiveWindow::restore_from_database(active_window_db);

        // assert equality
        assert_eq!(active_window, restored_active_window);

        // remove items
        for _ in 0..num_insertions {
            active_window
                .sbf
                .remove(rng.next_u32() as usize % active_window.sbf.len());
        }

        // store active window to database
        active_window_db = DB::open("active_window", opt).unwrap();
        active_window_db = active_window.store_to_database(active_window_db);
        active_window_db.flush().expect("Flush failure");

        // load active window from database
        let restored_active_window = ActiveWindow::restore_from_database(active_window_db);

        // assert equality
        assert_eq!(active_window, restored_active_window);
    }
}
