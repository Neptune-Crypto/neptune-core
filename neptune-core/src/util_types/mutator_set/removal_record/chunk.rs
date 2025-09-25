#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use thiserror::Error;

use super::super::shared::CHUNK_SIZE;

/// "Hard" max on the number of elements in a packed [`Chunk`].
/// Based on the Chernoff bound, the probability of finding a [`Chunk`] with
/// 4096 elements or more is less than 2^{-4000}. So without loss of generality,
/// a [`Chunk`] will never have 4096 elements. Packing a [`Chunk`] can therefore
/// result in (4095+1) * 12 / 32 = 1536 u32s.
///                           '--- u32 width
///                       '------- width of packed element and length indicator
///                 '------------- length indicator
///              '---------------- max # elements
const MAX_PACKED_LENGTH: usize = 1536;
const MAX_UNPACKED_LENGTH: usize = 4095;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum ChunkUnpackError {
    #[error(
        "payload is too large -- packed chunk can never be more than {MAX_PACKED_LENGTH} u32s"
    )]
    PayloadTooBig,

    #[error("actual length is inconsistent relative to length indicator")]
    InconsistentLength,

    #[error("remainder bits were not zero")]
    NonzeroTrailingPadding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
pub struct Chunk {
    pub relative_indices: Vec<u32>,
}

impl Chunk {
    pub fn empty_chunk() -> Self {
        Chunk {
            relative_indices: vec![],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.relative_indices.is_empty()
    }

    pub fn insert(&mut self, index: u32) {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `insert`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        self.relative_indices.push(index);
        self.relative_indices.sort();
    }

    pub fn remove_once(&mut self, index: u32) {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `remove`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );
        let mut drop = None;
        for i in 0..self.relative_indices.len() {
            if self.relative_indices[i] == index {
                drop = Some(i);
            }
        }

        if let Some(d) = drop {
            self.relative_indices.remove(d);
        }
    }

    pub fn contains(&self, index: u32) -> bool {
        assert!(
            index < CHUNK_SIZE,
            "index cannot exceed chunk size in `contains`. CHUNK_SIZE = {}, got index = {}",
            CHUNK_SIZE,
            index
        );

        self.relative_indices.contains(&index)
    }

    /// Return a chunk with indices which are the concatenation and sorting of indices in two input chunks
    pub fn combine(self, other: Self) -> Self {
        let mut ret = Self::empty_chunk();
        for idx in self.relative_indices {
            ret.relative_indices.push(idx);
        }
        for idx in other.relative_indices {
            ret.relative_indices.push(idx);
        }
        ret.relative_indices.sort();
        ret
    }

    /// Remove the indices in a chunk from a chunk.
    ///
    /// /// # Panics
    ///
    /// - If one of the subtracted indices are not present in the chunk.
    pub fn subtract(&mut self, other: Self) {
        for remove_index in other.relative_indices {
            // Find the 1st match and remove that
            match self
                .relative_indices
                .iter()
                .find_position(|x| **x == remove_index)
            {
                Some((i, _)) => self.relative_indices.remove(i),
                None => panic!("Attempted to remove index that was not present in chunk."),
            };
        }
    }

    pub fn to_indices(&self) -> Vec<u32> {
        self.relative_indices.clone()
    }

    pub fn from_indices(relative_indices: &[u32]) -> Self {
        Chunk {
            relative_indices: relative_indices.to_vec(),
        }
    }

    pub fn from_slice(sl: &[u32]) -> Chunk {
        Chunk {
            relative_indices: sl.to_vec(),
        }
    }

    /// Compresses a [`Chunk`] by encoding:
    ///  - the length of the vector of relative indices as a u12
    ///  - every element as a u12
    ///  - the resulting bitvec as `Vec<u32>`.
    pub(crate) fn pack(&self) -> Chunk {
        if self.relative_indices.is_empty() {
            return Self {
                relative_indices: vec![],
            };
        }

        // assert that we haven't already packed. I.e. that high bits are zero.
        assert!(self.relative_indices.iter().all(|x| *x < CHUNK_SIZE));

        assert!(
            self.relative_indices.len() <= MAX_UNPACKED_LENGTH,
            "Unpacked length of a chunk may not exceed {MAX_UNPACKED_LENGTH}"
        );

        let mut packed = vec![];
        let mut width = 0_usize;
        let mut current = 0_u64;
        for &element in [self.relative_indices.len() as u32]
            .iter()
            .chain(&self.relative_indices)
        {
            width += 12;
            current = (current << 12) | u64::from(element);

            if width >= 32 {
                let remainder = width % 32;
                packed.push(
                    u32::try_from(current >> remainder)
                        .expect("width of `current` should always be less than 44"),
                );
                width -= 32;
                current &= (1 << remainder) - 1;
            }
        }

        if width != 0 {
            packed.push(
                u32::try_from(current << (32 - width))
                    .expect("width of `current` should be less than 32 here"),
            );
        }

        Self {
            relative_indices: packed,
        }
    }

    /// Inverse of [`Self::pack`].
    pub(crate) fn try_unpack(&self) -> Result<Self, ChunkUnpackError> {
        if self.relative_indices.is_empty() {
            return Ok(Self {
                relative_indices: vec![],
            });
        }

        if self.relative_indices.len() > MAX_PACKED_LENGTH {
            return Err(ChunkUnpackError::PayloadTooBig);
        }

        let mut unpacked = vec![];

        let mut current = 0_u64;
        let mut width = 0_usize;
        let indicated_length = (self.relative_indices[0] >> 20) & ((1 << 12) - 1);

        #[expect(clippy::manual_div_ceil, reason = "approach tasm implementation")]
        let indicated_packed_length = ((indicated_length + 1) * 12 + 31) / 32;
        if indicated_packed_length != u32::try_from(self.relative_indices.len()).unwrap() {
            return Err(ChunkUnpackError::InconsistentLength);
        }

        let mut remaining_elements = indicated_length + 1;
        // Invariant: number of elements left to iterate over is
        // N == (remaining_elements * 12 - width + 31) / 32.
        //
        // Loop invariant before:
        // N == self.relative_indices.len()
        //   == indicated_packed_length
        //               (as per above if-statement)
        //   == ((indicated_length + 1) * 12 + 31) / 32
        //               (by assignment above that)
        //   == (remaining_elements * 12 + 31) / 32
        //               (by assignment to remaining_elements)
        //   == (remaining_elements * 12 - width + 31) / 32
        //               (since width == 0).
        for &element in &self.relative_indices {
            current = (current << 32) | u64::from(element);
            width += 32;

            // At this point, width is guaranteed to be in [32;44). In every
            // iteration of the next loop, 12 is subtracted. Therefore, the next
            // loop can run for either 2 or 3 iterations -- tertium non datur.
            while width >= 12 && remaining_elements != 0 {
                let denominator = width / 12;
                let remainder = width % 12;
                let mask = (1 << 12) - 1;
                unpacked.push(
                    u32::try_from((current >> (remainder + (denominator - 1) * 12)) & mask)
                        .expect("complicated invariant not satisfied"),
                );
                remaining_elements -= 1;
                let mask = mask << (remainder + (denominator - 1) * 12);
                let mask = !mask;
                current &= mask;
                width -= 12;
            }

            // Loop invariant at end of iteration: new number of elements left
            // to iterate over N* = N - 1. Distinguish two cases.
            //
            //  1. Inner while-loop ran for 2 iterations.
            //     width in [0;4) and width* = width + 8 (mod 12)
            //                               = width + 8
            //     remaining_elements* == remaining_elements - 2
            //     N   == (remaining_elements * 12 + width + 31) / 32.
            //     N* + 1 == ((remaining_elements* + 2) * 12 - (width* - 8) + 31) / 32
            //     N* = (remaining_elements* * 12 + 24 - width* + 8 + 31 - 32) / 32
            //        = (remaining_elements* * 12 - width + 31) / 32.
            //
            //  2. Inner while-loop ran for 3 iterations.
            //     Then width is in [4;12) and width* = width + 8 (mod 12)
            //                                        = width - 4
            //     remaining_elements* == remaining_elements - 3
            //     N   == (remaining_elements * 12 + width + 31) / 32.
            //     N* + 1 == ((remaining_elements* + 3) * 12 - (width* + 4) + 31) / 32
            //     N* = (remaining_elements* * 12 + 36 - width* -4 + 31 - 32) / 32
            //        = (remaining_elements* * 12 - width + 31) / 32.
            //
            // So the invariant is restored.
        }

        // Loop invariant afterwards:
        // N == 0
        //   == (remaining_elements * 12 - width + 31) / 32, so
        //   remaining_elements * 12 - width + 31 < 32
        //   remaining_elements * 12 - width < 1
        // From width in [0;12) it follows that remaining_elements == 0.
        // So it is not necessary check that remaining_elements == 0.

        let total_bit_length = (indicated_length + 1) * 12;
        let num_non_padding_bits_in_last_element = total_bit_length % 32;
        let tail_length = if num_non_padding_bits_in_last_element != 0 {
            32 - num_non_padding_bits_in_last_element
        } else {
            0
        };
        let mask = (1 << tail_length) - 1;

        if *self.relative_indices.last().unwrap() & mask != 0 {
            return Err(ChunkUnpackError::NonzeroTrailingPadding);
        }

        Ok(Self {
            relative_indices: unpacked[1..].to_vec(),
        })
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> Arbitrary<'a> for Chunk {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let relative_indices = (0..410)
            .map(|_| u.int_in_range(0..=(CHUNK_SIZE - 1)))
            .collect_vec();
        if relative_indices.iter().any(|index| index.is_err()) {
            return arbitrary::Result::<Chunk>::Err(arbitrary::Error::IncorrectFormat);
        }
        Ok(Chunk {
            relative_indices: relative_indices
                .into_iter()
                .map(|i| i.unwrap())
                .collect_vec(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::collections::HashSet;

    use num_traits::Zero;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use rand::RngCore;
    use statrs::distribution::ContinuousCDF;
    use statrs::distribution::Normal;
    use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
    use test_strategy::proptest;

    use super::*;
    use crate::util_types::mutator_set::shared::BATCH_SIZE;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::util_types::mutator_set::shared::WINDOW_SIZE;

    #[test]
    fn chunk_is_reversible_bloom_filter() {
        let mut aw = Chunk::empty_chunk();

        // Insert an index twice, remove it once and the verify that
        // it is still there
        let index = 7;
        assert!(!aw.contains(index));
        aw.insert(index);
        assert!(aw.contains(index));
        aw.insert(index);
        assert!(aw.contains(index));
        aw.remove_once(index);
        assert!(aw.contains(index));
        aw.remove_once(index);
        assert!(!aw.contains(index));

        // Verify that we can remove once without index being present, without crashing
        aw.remove_once(index);
    }

    #[test]
    fn insert_remove_contains_pbt() {
        let mut aw = Chunk::empty_chunk();
        for i in 0..CHUNK_SIZE {
            assert!(!aw.contains(i));
        }

        let mut prng = rand::rng();
        for _ in 0..CHUNK_SIZE {
            let index = prng.next_u32() % CHUNK_SIZE;
            let set = prng.next_u32().is_multiple_of(2);
            if set {
                aw.insert(index);
            }

            assert_eq!(set, aw.contains(index));

            aw.remove_once(index);
        }

        // Set all indices, then check that they are present
        for i in 0..CHUNK_SIZE {
            aw.insert(i);
        }

        for i in 0..CHUNK_SIZE {
            assert!(aw.contains(i));
        }
    }

    #[test]
    fn chunk_hashpreimage_test() {
        let zero_chunk = Chunk::empty_chunk();

        // Encoded chunk is prepended with its length.
        let zero_chunk_preimage = zero_chunk.encode();
        println!("zero chunk preimage: {:?}", zero_chunk_preimage);
        assert!(zero_chunk_preimage
            .iter()
            .skip(1)
            .all(|elem| elem.is_zero()));

        let mut one_chunk = Chunk::empty_chunk();
        one_chunk.insert(32);
        let one_chunk_preimage = one_chunk.encode();

        assert_ne!(zero_chunk_preimage, one_chunk_preimage);

        let mut two_ones_chunk = Chunk::empty_chunk();
        two_ones_chunk.insert(32);
        two_ones_chunk.insert(33);
        let two_ones_preimage = two_ones_chunk.encode();

        assert_ne!(two_ones_preimage, one_chunk_preimage);
        assert_ne!(two_ones_preimage, zero_chunk_preimage);

        // Verify that inserting any index produces a unique hash-preimage value
        let mut previous_values: HashSet<Vec<BFieldElement>> = HashSet::new();
        for i in 0..CHUNK_SIZE {
            let mut chunk = Chunk::empty_chunk();
            chunk.insert(i);
            assert!(previous_values.insert(chunk.encode()));
        }
    }

    #[test]
    fn subtract_and_combine_and_is_empty_test() {
        let mut chunk_a = Chunk::empty_chunk();
        chunk_a.insert(12);
        chunk_a.insert(13);
        chunk_a.insert(48);

        let mut chunk_b = Chunk::empty_chunk();
        chunk_b.insert(48);
        chunk_b.insert(13);

        let mut expected_sub = Chunk::empty_chunk();
        expected_sub.insert(12);

        let mut chunk_c = chunk_a.clone();
        chunk_c.subtract(chunk_b.clone());

        assert_eq!(
            expected_sub, chunk_c,
            "subtract on chunks must behave as expected"
        );

        let mut expected_combine = Chunk::empty_chunk();
        expected_combine.insert(12);
        expected_combine.insert(13);
        expected_combine.insert(13);
        expected_combine.insert(48);
        expected_combine.insert(48);

        chunk_c = chunk_a.clone().combine(chunk_b.clone());
        assert_eq!(
            expected_combine, chunk_c,
            "combine on chunks must behave as expected"
        );

        // Verify that `is_empty` behaves as expected
        assert!(!chunk_a.is_empty());
        assert!(!chunk_b.is_empty());
        assert!(!chunk_c.is_empty());
        assert!(Chunk::empty_chunk().is_empty());
    }

    #[test]
    fn serialization_test() {
        // TODO: You could argue that this test doesn't belong here, as it tests the behavior of
        // an imported library. I included it here, though, because the setup seems a bit clumsy
        // to me so far.
        let chunk = Chunk::empty_chunk();
        let json = serde_json::to_string(&chunk).unwrap();
        let s_back = serde_json::from_str::<Chunk>(&json).unwrap();
        assert!(s_back.relative_indices.is_empty());
    }

    #[test]
    fn test_indices() {
        let mut chunk = Chunk::empty_chunk();
        let mut rng = rand::rng();
        let num_insertions = 100;
        for _ in 0..num_insertions {
            let index = rng.next_u32() % (CHUNK_SIZE);
            chunk.insert(index);
        }

        let indices = chunk.to_indices();

        let reconstructed_chunk = Chunk::from_indices(&indices);

        assert_eq!(chunk, reconstructed_chunk);
    }

    #[test]
    fn test_chunk_decode() {
        let mut chunk = Chunk::empty_chunk();
        let mut rng = rand::rng();
        let num_insertions = 100;
        for _ in 0..num_insertions {
            let index = rng.next_u32() % (CHUNK_SIZE);
            chunk.insert(index);
        }

        let encoded = chunk.encode();
        let decoded = *Chunk::decode(&encoded).unwrap();

        assert_eq!(chunk, decoded);
    }

    /// Collect statistics about the typical number of elements in a `Chunk`.
    ///
    /// This information is relevant in the context of densly representing
    /// `Chunk`s -- in particular, for answering the question, "how many bits
    /// should we use to encode the length?". The simplest proposal is to use 12
    /// bits -- the same as the bit length used for elements. However, there is
    /// a nonzero probability that a `Chunk` becomes so full that 12 bits is not
    /// enough to encode its length. We want to bound that probability to a
    /// negligible quantity.
    ///
    /// Using the Chernoff bound for binomial distributions, it is possible to
    /// bound this tail event probability to 2^-4367 [1]. However, this analysis
    /// might be wrong somewhere, so it's useful to have an independent piece of
    /// evidence (in the form of a unit test) supporting the viability of 12
    /// bits.
    ///
    /// If these statistics are correct --
    ///
    /// ```notest
    /// mean: 360.03576
    /// variance: 359.3943412223999
    /// stddev: 18.95769873224068
    /// ```
    ///
    /// -- then heuristically bound the tail end of the probability distribution
    /// by approximating it as a Gaussian. In fact, right off the bat, 4096 is
    /// around 185 standard deviations away from the mean. This number is a far
    /// cry from the standard 3-4-5 simgas in the 3-4-5 sigma rule. So maybe the
    /// 4367 bits is not too far off. But let's try and compute this probability
    /// anyway.
    #[ignore = "informative statistics"]
    #[test]
    fn chunk_length_statistics() {
        const NUM_CHUNKS_IN_WINDOW: u32 = WINDOW_SIZE / CHUNK_SIZE;
        const N: u32 = NUM_CHUNKS_IN_WINDOW * NUM_TRIALS * BATCH_SIZE;

        // sample histogram  chunk-size --> frequency
        let num_samples = 100000;
        let mut rng = rng();
        let mut hist = HashMap::<usize, usize>::new();
        for _ in 0..num_samples {
            let mut chunk_size = 0;
            for _ in 0..N {
                let index = rng.next_u32() % (1 << 20);
                chunk_size += usize::from(index < CHUNK_SIZE);
            }
            hist.entry(chunk_size).and_modify(|v| *v += 1).or_insert(1);
        }

        // calculate mean and stddev
        let mean: f64 = hist
            .iter()
            .map(|(k, v)| (*k as f64) * (*v as f64))
            .sum::<f64>()
            / f64::from(num_samples);
        let variance: f64 = hist
            .iter()
            .map(|(k, v)| ((*k as f64) - mean) * ((*k as f64) - mean) * (*v as f64))
            .sum::<f64>()
            / f64::from(num_samples);
        let stddev = variance.sqrt();

        println!("mean: {mean}");
        println!("variance: {variance}");
        println!("stddev: {stddev}");

        // compute frequencies of large chunks
        for threshold in [500, 600, 700, 800, 900] {
            let excess = hist
                .iter()
                .filter(|(k, _v)| **k >= threshold)
                .map(|(_k, v)| *v)
                .sum::<usize>();
            println!(
                "tail mass >= {threshold}: {excess} / {num_samples} = {}",
                (excess as f64) / f64::from(num_samples)
            );
        }

        // modeling the distribution as Gaussian, what's the probability of
        // having 4096 or more elements in one `Chunk`? The answer to this
        // question could motivate using 12 bits to store its length.
        let gauss = Normal::new(mean, stddev).unwrap();
        // let overfull_probability = gauss.cdf(4096);
        // Actually, we want the right tail, corresponding to 1 minus the above
        // quantity.
        // Computing 1 - that is not very precise -- so we compute the
        // equivalent left tail instead.
        let overfull_probability = gauss.cdf(-(4096.0 - mean) + mean);
        println!("Pr[#elements in Chunk >= 4096] ≈ {overfull_probability:e}");

        // note that underflow might send a negligible but nonzero probability
        // to 0e0.
    }

    mod packing {
        use rand::Rng;

        use super::*;

        #[test]
        fn packing_empty_chunk() {
            let chunk = Chunk::empty_chunk();
            assert!(chunk.pack().relative_indices.is_empty());
            assert!(chunk
                .pack()
                .try_unpack()
                .unwrap()
                .relative_indices
                .is_empty());
        }

        #[test]
        fn pack_unpack_unit_6_zeros() {
            let chunk = Chunk {
                relative_indices: vec![0; 6],
            };
            let packed = chunk.pack();
            let unpacked = packed.try_unpack().unwrap();
            assert_eq!(chunk, unpacked);
        }

        #[test]
        fn pack_unpack_unit_7_zeros() {
            let chunk = Chunk {
                relative_indices: vec![0; 7],
            };
            let packed = chunk.pack();
            let unpacked = packed.try_unpack().unwrap();
            assert_eq!(chunk, unpacked);
        }
        #[test]
        fn pack_unpack_unit_10_nonzeros() {
            let chunk = Chunk {
                relative_indices: vec![392, 1192, 2453, 527, 2430, 2423, 257, 290, 2807, 122],
            };
            let packed = chunk.pack();
            let unpacked = packed.try_unpack().unwrap();
            assert_eq!(chunk, unpacked);
        }

        #[test]
        fn packing_sparse_chunks() {
            let mut rng = rand::rng();
            for i in 0..20 {
                let chunk = Chunk {
                    relative_indices: vec![rng.random_range(0..CHUNK_SIZE); i],
                };
                let packed = chunk.pack();
                let unpacked = packed.try_unpack().unwrap();
                assert_eq!(chunk, unpacked);
            }
        }

        #[test]
        fn can_trigger_error_payload_too_big() {
            let packed_chunk = Chunk {
                relative_indices: vec![1; MAX_PACKED_LENGTH + 1],
            };
            assert_eq!(
                ChunkUnpackError::PayloadTooBig,
                packed_chunk.try_unpack().unwrap_err()
            );
        }

        #[test]
        fn can_trigger_error_inconsistent_length() {
            let chunk = Chunk {
                relative_indices: vec![392, 1192, 2453, 527, 2430, 2423, 257, 290, 2807, 122],
            };
            let mut packed = chunk.pack();
            packed.relative_indices.push(0);
            assert_eq!(
                ChunkUnpackError::InconsistentLength,
                packed.try_unpack().unwrap_err()
            );
        }

        #[test]
        fn can_trigger_error_nonzero_trailing_padding() {
            let chunk = Chunk {
                relative_indices: vec![392, 1192, 2453, 527, 2430, 2423, 257, 290, 2807, 122],
            };
            let mut packed = chunk.pack();
            *packed.relative_indices.last_mut().unwrap() |= 1;
            assert_eq!(
                ChunkUnpackError::NonzeroTrailingPadding,
                packed.try_unpack().unwrap_err()
            );
        }

        #[proptest]
        fn pack_unpack_happy(#[strategy(arb::<Chunk>())] chunk: Chunk) {
            let packed = chunk.pack();
            let unpacked = packed.try_unpack().unwrap();
            prop_assert_eq!(chunk, unpacked);
        }

        #[proptest]
        fn packing_must_be_minimal(#[strategy(arb::<Chunk>())] chunk: Chunk) {
            let mut packed = chunk.pack();
            packed.relative_indices.push(0);
            prop_assert_eq!(
                ChunkUnpackError::InconsistentLength,
                packed.try_unpack().unwrap_err()
            );
        }

        #[proptest]
        fn cannot_lie_about_lengths(#[strategy(arb::<Chunk>())] chunk: Chunk) {
            let mut packed = chunk.pack();
            // Indicated length must be off by at least 3 to guarantee failure
            packed.relative_indices[0] ^= 0x00_30_00_00;
            prop_assert!(packed.try_unpack().is_err());
        }
    }
}
