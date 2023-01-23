use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};

use super::chunk::Chunk;
use super::ibf::{InvertibleBloomFilter, SparseBloomFilter};
use super::shared::{CHUNK_SIZE, WINDOW_SIZE};

#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct ActiveWindow<H: AlgebraicHasher> {
    // It's OK to store this in memory, since it's on the size of kilobytes, not gigabytes.
    // The byte array is boxed to prevent stack-overflows when deserializing this data
    // structure. Cf. https://neptune.builders/core-team/neptune-core/issues/32
    pub sbf: SparseBloomFilter<{ WINDOW_SIZE as u128 }>,
    _hasher: PhantomData<H>,
}

impl<H: AlgebraicHasher> PartialEq for ActiveWindow<H> {
    fn eq(&self, other: &Self) -> bool {
        self.sbf == other.sbf
    }
}

#[allow(clippy::new_without_default)]
impl<H: AlgebraicHasher> ActiveWindow<H> {
    pub fn new() -> Self {
        Self {
            sbf: SparseBloomFilter::<{ WINDOW_SIZE as u128 }>::new(),
            _hasher: PhantomData,
        }
    }

    /// Get the chunk of the active window that, upon sliding, becomes
    /// inactive.
    pub fn slid_chunk(&self) -> Chunk {
        Chunk::from_indices(
            &self
                .sbf
                .slice::<{ CHUNK_SIZE as u128 }>(0..CHUNK_SIZE as u128)
                .indices,
        )
    }

    /// Slide the window: drop all integers indexing into the first
    /// chunk, and subtract CHUNK_SIZE from all others.
    pub fn slide_window(&mut self) {
        self.sbf.zerofy(0, CHUNK_SIZE as u128);
        for location in self.sbf.indices.iter_mut() {
            *location -= CHUNK_SIZE as u128;
        }
    }

    /// Undo a window slide.
    pub fn slide_window_back(&mut self, chunk: &Chunk) {
        assert!(!self
            .sbf
            .hasset((WINDOW_SIZE - CHUNK_SIZE) as u128, WINDOW_SIZE as u128));
        for location in self.sbf.indices.iter_mut() {
            *location += CHUNK_SIZE as u128;
        }
        let indices = chunk.to_indices();
        for index in indices {
            self.sbf.increment(index);
        }
    }

    pub fn set_bit(&mut self, index: usize) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `set_bit`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );
        self.sbf.increment(index as u128);
    }

    pub fn unset_bit(&mut self, index: usize) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `unset_bit`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );
        self.sbf.decrement(index as u128);
    }

    pub fn get_bit(&self, index: usize) -> bool {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `get_bit`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );

        self.sbf.isset(index as u128)
    }

    pub fn to_vec_u32(&self) -> Vec<u32> {
        self.sbf.to_vec_u32()
    }

    pub fn from_vec_u32(vector: &[u32]) -> Self {
        Self {
            sbf: SparseBloomFilter::from_vec_u32(vector),
            _hasher: PhantomData,
        }
    }
}

impl<H: AlgebraicHasher> InvertibleBloomFilter for ActiveWindow<H> {
    fn increment(&mut self, location: u128) {
        self.sbf.increment(location);
    }

    fn decrement(&mut self, location: u128) {
        self.sbf.decrement(location);
    }

    fn isset(&self, location: u128) -> bool {
        self.sbf.isset(location)
    }
}

impl<H: AlgebraicHasher> Hashable for ActiveWindow<H> {
    fn to_sequence(&self) -> Vec<twenty_first::shared_math::b_field_element::BFieldElement> {
        self.sbf
            .indices
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
        fn new_from(sbf: SparseBloomFilter<1048576>) -> Self {
            Self {
                sbf,
                _hasher: PhantomData,
            }
        }
    }

    #[test]
    fn get_set_unset_bits_pbt() {
        let sbf = SparseBloomFilter::<{ WINDOW_SIZE as u128 }>::new();
        let mut aw = ActiveWindow::<blake3::Hasher>::new_from(sbf);
        for i in 0..100 {
            assert!(!aw.get_bit(i as usize));
        }

        let mut prng = thread_rng();
        for _ in 0..100 {
            let index = prng.next_u32() as usize % WINDOW_SIZE;
            aw.set_bit(index);

            assert!(aw.get_bit(index));
        }

        // Set all bits, then check that they are set
        for i in 0..100 {
            aw.set_bit(i);
        }

        for i in 0..100 {
            assert!(aw.get_bit(i as usize));
        }
    }

    #[test]
    fn test_slide_window() {
        let mut aw = ActiveWindow::<blake3::Hasher>::new();

        let num_insertions = 100;
        let mut rng = thread_rng();
        for _ in 0..num_insertions {
            aw.increment(rng.next_u32() as u128 % WINDOW_SIZE as u128);
        }

        aw.slide_window();

        // Verify that last N elements are zero after window slide
        assert!(!aw
            .sbf
            .hasset((WINDOW_SIZE - CHUNK_SIZE) as u128, CHUNK_SIZE as u128));
    }

    #[test]
    fn test_slide_window_back() {
        type Hasher = blake3::Hasher;

        let mut active_window = ActiveWindow::<Hasher>::new();
        let num_insertions = 1000;
        let mut rng = thread_rng();
        for _ in 0..num_insertions {
            active_window.increment((rng.next_u32() as u128) % WINDOW_SIZE as u128);
        }
        let dummy_chunk = active_window.slid_chunk();
        active_window.slide_window();
        assert!(!active_window
            .sbf
            .hasset((WINDOW_SIZE - CHUNK_SIZE) as u128, WINDOW_SIZE as u128));

        active_window.slide_window_back(&dummy_chunk);
        for index in dummy_chunk.bits {
            assert!(active_window.isset(index as u128));
        }
    }

    #[test]
    fn test_slide_window_and_back() {
        type Hasher = blake3::Hasher;

        let mut active_window = ActiveWindow::<Hasher>::new();
        let num_insertions = 1000;
        let mut rng = thread_rng();
        for _ in 0..num_insertions {
            active_window.increment((rng.next_u32() as u128) % WINDOW_SIZE as u128);
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
        aw_1.increment(1u128);
        let aw_2 = ActiveWindow::<H>::new();

        assert_ne!(H::hash(&aw_1), H::hash(&aw_2));
    }

    #[test]
    fn test_hash_unequal_nocrash() {
        // This is just a test to ensure that the hashing of the active part of the SWBF
        // works in the runtime, for relevant hash functions. It also tests that different
        // bits being set results in different digests.
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
}
