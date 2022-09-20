use num_traits::identities::Zero;
use rusty_leveldb::DB;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use twenty_first::{
    shared_math::b_field_element::BFieldElement,
    util_types::{
        database_array::DatabaseArray,
        simple_hasher::{Hashable, Hasher},
    },
};

use super::{
    chunk::Chunk,
    shared::{BITS_PER_U32, CHUNK_SIZE, WINDOW_SIZE},
};
use crate::util_types::mutator_set::boxed_big_array::CompositeBigArray;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveWindow<H: Hasher> {
    // It's OK to store this in memory, since it's on the size of kilobytes, not gigabytes.
    // The byte array is boxed to prevent stack-overflows when deserializing this data
    // structure. Cf. https://neptune.builders/core-team/neptune-core/issues/32
    #[serde(with = "CompositeBigArray")]
    pub bits: Box<[u32; WINDOW_SIZE / BITS_PER_U32]>,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> ActiveWindow<H>
where
    u128: Hashable<<H as Hasher>::T>,
    Vec<BFieldElement>: Hashable<<H as Hasher>::T>,
{
    pub fn get_sliding_chunk_bits(&self) -> [u32; CHUNK_SIZE / BITS_PER_U32] {
        self.bits[0..CHUNK_SIZE / BITS_PER_U32].try_into().unwrap()
    }

    /// Populate an database with the values in this active window.
    /// This is used to persist the state of an archival mutator set.
    pub fn store_to_database(&self, db: DB) -> DB {
        let mut database_array: DatabaseArray<{ WINDOW_SIZE as u128 / BITS_PER_U32 as u128 }, u32> =
            DatabaseArray::restore(db);
        database_array.batch_set(
            &self
                .bits
                .into_iter()
                .enumerate()
                .map(|(i, v)| (i as u128, v))
                .collect::<Vec<_>>(),
        );
        database_array.extract_db()
    }

    /// Given a database object that has been stored on disk, return an ActiveWindow object
    pub fn restore_from_database(db: DB) -> Self {
        let mut database_array: DatabaseArray<{ WINDOW_SIZE as u128 / BITS_PER_U32 as u128 }, u32> =
            DatabaseArray::restore(db);
        let mut ret = Self::default();
        for i in 0..({ WINDOW_SIZE / BITS_PER_U32 }) {
            ret.bits[i] = database_array.get(i as u128);
        }

        ret
    }

    pub fn slide_window(&mut self) {
        for i in (CHUNK_SIZE / BITS_PER_U32)..(WINDOW_SIZE / BITS_PER_U32) {
            self.bits[i - CHUNK_SIZE / BITS_PER_U32] = self.bits[i]
        }
        for i in
            (WINDOW_SIZE / BITS_PER_U32 - CHUNK_SIZE / BITS_PER_U32)..(WINDOW_SIZE / BITS_PER_U32)
        {
            self.bits[i] = 0u32;
        }
    }

    pub fn slide_window_back(&mut self, chunk: &Chunk) {
        for i in
            (WINDOW_SIZE / BITS_PER_U32 - CHUNK_SIZE / BITS_PER_U32)..(WINDOW_SIZE / BITS_PER_U32)
        {
            assert!(
                self.bits[i].is_zero(),
                "Bits removed from active window must be all zero"
            );
        }
        for i in (0..(WINDOW_SIZE / BITS_PER_U32) - CHUNK_SIZE / BITS_PER_U32).rev() {
            self.bits[i + CHUNK_SIZE / BITS_PER_U32] = self.bits[i];
        }
        self.bits[0..CHUNK_SIZE / BITS_PER_U32].copy_from_slice(&chunk.bits);
    }

    pub fn set_bit(&mut self, index: usize) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `set_bit`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );
        self.bits[index / BITS_PER_U32] |= 1u32 << (index % BITS_PER_U32);
    }

    pub fn unset_bit(&mut self, index: usize) {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `unset_bit`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );
        self.bits[index / BITS_PER_U32] &= 0xFFFFFFFFu32 ^ (1u32 << (index % BITS_PER_U32));
    }

    pub fn get_bit(&self, index: usize) -> bool {
        assert!(
            index < WINDOW_SIZE,
            "index cannot exceed window size in `get_bit`. WINDOW_SIZE = {}, got index = {}",
            WINDOW_SIZE,
            index
        );

        self.bits[index / BITS_PER_U32] & (1u32 << (index % BITS_PER_U32)) != 0
    }

    /// Return the number of u128s that are required to represent the active window
    fn get_u128s_length() -> usize {
        if WINDOW_SIZE % (8 * 16) == 0 {
            WINDOW_SIZE / (8 * 16)
        } else {
            WINDOW_SIZE / (8 * 16) + 1
        }
    }

    /// FIXME: Explain what a u128 is in the context of an ActiveWindow.
    fn get_u128s(&self) -> Vec<u128> {
        let mut u128s: Vec<u128> = vec![0u128; Self::get_u128s_length()];
        for i in 0..(WINDOW_SIZE / BITS_PER_U32) {
            let shift = 32 * (i % 4) as u128;
            u128s[i / 4] += (self.bits[i] as u128 * (1 << shift)) as u128;
        }

        u128s
    }

    /// Get a commitment for the active part of the sliding-window bloom filter
    pub fn hash(&self) -> H::Digest {
        let seq: Vec<H::T> = self
            .get_u128s()
            .into_iter()
            .flat_map(|u128| u128.to_sequence())
            .collect();

        H::new().hash_sequence(&seq)
    }
}

impl<H: Hasher> Default for ActiveWindow<H> {
    /// The default instance has no bits set in the active window
    fn default() -> Self {
        Self {
            bits: Box::new([0u32; WINDOW_SIZE / BITS_PER_U32]),
            _hasher: PhantomData,
        }
    }
}

#[cfg(test)]
mod active_window_tests {
    use super::*;
    use rand::{thread_rng, RngCore};
    use twenty_first::shared_math::rescue_prime_regular::RescuePrimeRegular;

    impl<H: Hasher> ActiveWindow<H> {
        fn new(bits: Box<[u32; WINDOW_SIZE / BITS_PER_U32]>) -> Self {
            Self {
                bits,
                _hasher: PhantomData,
            }
        }
    }

    #[test]
    fn constant_sanity_check_test() {
        // This test assumes that the bits in the active window are represented as `u32`s. If they are,
        // then the window size should be a multiple of 32.
        assert_eq!(0, WINDOW_SIZE % 32);
    }

    #[test]
    fn get_set_unset_bits_pbt() {
        let mut aw = ActiveWindow::<blake3::Hasher>::default();
        for i in 0..WINDOW_SIZE {
            assert!(!aw.get_bit(i));
        }

        let mut prng = thread_rng();
        for _ in 0..WINDOW_SIZE {
            let index = prng.next_u32() as usize % WINDOW_SIZE;
            let set = prng.next_u32() % 2 == 0;
            if set {
                aw.set_bit(index);
            } else {
                aw.unset_bit(index);
            }

            assert!(set == aw.get_bit(index));
        }

        // Set all bits, then check that they are set
        for i in 0..WINDOW_SIZE {
            aw.set_bit(i);
        }

        for i in 0..WINDOW_SIZE / BITS_PER_U32 {
            assert_eq!(0xFFFFFFFFu32, aw.bits[i]);
        }

        for i in 0..WINDOW_SIZE {
            assert!(aw.get_bit(i));
        }
    }

    #[test]
    /// Verify that we can store an active window to the database, and that we can recreate it again from the database
    fn db_store_and_recover() {
        let mut init_array = [0xFFFFFFFFu32; WINDOW_SIZE / BITS_PER_U32];
        init_array[2] = 42u32;
        let aw = ActiveWindow::<blake3::Hasher>::new(Box::new(init_array));
        let opt = rusty_leveldb::in_memory();
        let db = DB::open("mydatabase", opt).unwrap();
        let aw_as_db = aw.store_to_database(db);
        let restored_aw = ActiveWindow::<blake3::Hasher>::restore_from_database(aw_as_db);
        assert_eq!(aw.bits, restored_aw.bits);
        assert_eq!(0xFFFFFFFFu32, restored_aw.bits[0]);
        assert_eq!(0xFFFFFFFFu32, restored_aw.bits[1]);
        assert_eq!(42u32, restored_aw.bits[2]);
    }

    #[test]
    fn slide_window_test() {
        // This test assumes that element with index 2 is part of the active window that slides when window slides
        let mut init_array = [0xFFFFFFFFu32; WINDOW_SIZE / BITS_PER_U32];
        init_array[2] = 42u32;
        let mut aw = ActiveWindow::<blake3::Hasher>::new(Box::new(init_array));
        let new_chunk_array: [u32; CHUNK_SIZE / BITS_PER_U32] = aw.get_sliding_chunk_bits();
        for (i, elem) in new_chunk_array.into_iter().enumerate() {
            if i == 2 {
                assert_eq!(42u32, elem);
            } else {
                assert_eq!(0xFFFFFFFFu32, elem);
            }
        }

        aw.slide_window();

        // Verify that last N elements are zero after window slide
        for i in 0..CHUNK_SIZE / BITS_PER_U32 {
            assert_eq!(0x00u32, aw.bits[aw.bits.len() - 1 - i]);
        }
    }

    #[test]
    fn slide_window_back_test() {
        type Hasher = blake3::Hasher;
        let array: [u32; WINDOW_SIZE / BITS_PER_U32] = (0..WINDOW_SIZE / BITS_PER_U32)
            .map(|_| rand::random::<u32>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut active_window = ActiveWindow::<Hasher>::new(Box::new(array));
        let chunk_bits = active_window.get_sliding_chunk_bits();
        let chunk = Chunk { bits: chunk_bits };

        active_window.slide_window();

        // Sliding window forward must unset the last bits of the active window
        for i in
            (WINDOW_SIZE / BITS_PER_U32 - CHUNK_SIZE / BITS_PER_U32)..(WINDOW_SIZE / BITS_PER_U32)
        {
            assert_eq!(0, active_window.bits[i]);
        }

        active_window.slide_window_back(&chunk);

        assert_eq!(
            array, *active_window.bits,
            "Sliding forward and then back must be the identity operation"
        );
    }

    #[should_panic(expected = "Bits removed from active window must be all zero")]
    #[test]
    fn slide_window_back_panic_test() {
        type Hasher = blake3::Hasher;
        let array: [u32; WINDOW_SIZE / BITS_PER_U32] = (0..WINDOW_SIZE / BITS_PER_U32)
            .map(|_| rand::random::<u32>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut active_window = ActiveWindow::<Hasher>::new(Box::new(array));
        let dummy_chunk = Chunk {
            bits: [0u32; CHUNK_SIZE / BITS_PER_U32],
        };
        active_window.slide_window_back(&dummy_chunk);
    }

    #[test]
    fn u128s_length_test() {
        // Let's just compare the output of this function to the result from my calculator
        assert_eq!(250, ActiveWindow::<RescuePrimeRegular>::get_u128s_length());
    }

    #[test]
    fn get_u128s_test() {
        let mut bytes = [0u32; WINDOW_SIZE / BITS_PER_U32];
        bytes[0] = 124 + 125 * (1u32 << 8) + 127 * (1u32 << 16);
        bytes[3] = 144 * (1u32 << 16) + 65 * (1u32 << 24);
        bytes[5] = 98 * (1u32 << 8);
        let aw = ActiveWindow::<RescuePrimeRegular>::new(Box::new(bytes));
        let u128s = aw.get_u128s();
        assert_eq!(250, u128s.len());
        assert_eq!(98 * (1 << (5 * 8)), u128s[1]);
        assert_eq!(
            124 + 125 * (1 << 8) + 127 * (1 << 16) + 144 * (1 << (14 * 8)) + 65 * (1 << (15 * 8)),
            u128s[0]
        );
    }

    #[test]
    fn hash_no_crash_test() {
        // This is just a test to ensure that the hashing of the active part of the SWBF
        // works in the runtime, for relevant hash functions
        let hash_0 = ActiveWindow::<RescuePrimeRegular>::default().hash();
        let hash_1 = ActiveWindow::<RescuePrimeRegular>::new(Box::new(
            [0xFFFFFFFFu32; WINDOW_SIZE / BITS_PER_U32],
        ))
        .hash();
        let hash_2 = ActiveWindow::<blake3::Hasher>::default().hash();
        let hash_3 = ActiveWindow::<blake3::Hasher>::new(Box::new(
            [0xFFFFFFFFu32; WINDOW_SIZE / BITS_PER_U32],
        ))
        .hash();

        assert_ne!(hash_0, hash_1);
        assert_ne!(hash_2, hash_3);
    }

    #[test]
    fn active_window_serialize_test() {
        let aw0 = ActiveWindow::<RescuePrimeRegular>::default();
        let json_aw0 = serde_json::to_string(&aw0).unwrap();
        let aw0_back = serde_json::from_str::<ActiveWindow<RescuePrimeRegular>>(&json_aw0).unwrap();
        assert_eq!(aw0.bits, aw0_back.bits);
    }
}
