use std::ops::Range;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::removal_record::chunk::Chunk;
use super::shared::CHUNK_SIZE;
use super::shared::WINDOW_SIZE;

#[derive(Clone, Debug, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct ActiveWindow {
    // It's OK to store this in memory, since it's on the size of kilobytes, not gigabytes.
    pub sbf: Vec<u32>,
}

impl PartialEq for ActiveWindow {
    fn eq(&self, other: &Self) -> bool {
        self.sbf == other.sbf
    }
}

impl Default for ActiveWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveWindow {
    pub fn new() -> Self {
        Self { sbf: Vec::new() }
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
        for location in &mut self.sbf {
            *location -= CHUNK_SIZE;
        }
    }

    /// Return true iff there is a set integer in the given range.
    fn hasset(&self, lower: u32, upper: u32) -> bool {
        for location in &self.sbf {
            if lower <= *location && *location < upper {
                return true;
            }
        }
        false
    }

    /// Undo a window slide.
    pub fn slide_window_back(&mut self, chunk: &Chunk) {
        assert!(!self.hasset(WINDOW_SIZE - CHUNK_SIZE, WINDOW_SIZE));
        for location in &mut self.sbf {
            *location += CHUNK_SIZE;
        }
        let indices = chunk.to_indices();
        for index in indices {
            self.sbf.push(index);
        }
        self.sbf.sort();
    }

    /// # Panics
    ///
    /// - if the index is not less than window size
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

        // locate last match
        let mut found = false;
        let mut drop_index_index = 0;
        for (index_index, index_value) in self.sbf.iter().enumerate() {
            if *index_value == index {
                found = true;
                drop_index_index = index_index;
            }
        }

        // if found, drop last match
        if found {
            self.sbf.remove(drop_index_index);
        }

        // if not found, the indicated integer is zero
        assert!(found, "Decremented integer is already zero.");
    }

    pub fn contains(&self, index: u32) -> bool {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `contains`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );

        for loc in &self.sbf {
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
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rand::RngCore;
    use tasm_lib::prelude::Tip5;

    use super::*;

    impl ActiveWindow {
        fn new_from(sbf: Vec<u32>) -> Self {
            Self { sbf }
        }
    }

    #[test]
    fn aw_is_reversible_bloom_filter() {
        let sbf = Vec::<u32>::new();
        let mut aw = ActiveWindow::new_from(sbf);

        // Insert an index twice, remove it once and the verify that
        // it is still there
        let index = 7;
        assert!(!aw.contains(index));
        aw.insert(index);
        assert!(aw.contains(index));
        aw.insert(index);
        assert!(aw.contains(index));
        aw.remove(index);
        assert!(aw.contains(index));
        aw.remove(index);
        assert!(!aw.contains(index));
    }

    #[test]
    fn insert_remove_probe_indices_pbt() {
        let sbf = Vec::<u32>::new();
        let mut aw = ActiveWindow::new_from(sbf);
        for i in 0..100 {
            assert!(!aw.contains(i as u32));
        }

        let mut prng = rand::rng();
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
        let mut aw = ActiveWindow::new();

        let num_insertions = 100;
        let mut rng = rand::rng();
        for _ in 0..num_insertions {
            aw.insert(rng.next_u32() % WINDOW_SIZE);
        }

        aw.slide_window();

        // Verify that last N elements are zero after window slide
        assert!(!aw.hasset(WINDOW_SIZE - CHUNK_SIZE, CHUNK_SIZE));
    }

    #[test]
    fn test_slide_window_back() {
        let mut active_window = ActiveWindow::new();
        let num_insertions = 1000;
        let mut rng = rand::rng();
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
        let mut active_window = ActiveWindow::new();
        let num_insertions = 1000;
        let mut rng = rand::rng();
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

    fn hash_unequal_prop() {
        Tip5::hash(&ActiveWindow::new());

        let mut aw_1 = ActiveWindow::new();
        aw_1.insert(1u32);
        let aw_2 = ActiveWindow::new();

        assert_ne!(Tip5::hash(&aw_1), Tip5::hash(&aw_2));
    }

    #[test]
    fn test_hash_unequal_nocrash() {
        // This is just a test to ensure that the hashing of the active part of the SWBF
        // works in the runtime, for relevant hash functions. It also tests that different
        // indices being inserted results in different digests.
        hash_unequal_prop();
    }

    #[test]
    fn test_active_window_serialization() {
        let aw0 = ActiveWindow::new();
        let json_aw0 = serde_json::to_string(&aw0).unwrap();
        let aw0_back = serde_json::from_str::<ActiveWindow>(&json_aw0).unwrap();
        assert_eq!(aw0.sbf, aw0_back.sbf);
    }

    #[test]
    fn test_active_window_decode() {
        let mut rng = rand::rng();

        let mut aw0 = ActiveWindow::new();
        for _ in 0..37 {
            aw0.insert(rng.next_u32() % WINDOW_SIZE);
        }
        let encoded = aw0.encode();
        let decoded = *ActiveWindow::decode(&encoded).unwrap();

        assert_eq!(aw0, decoded);
    }
}
