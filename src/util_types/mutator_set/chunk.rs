#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tasm_lib::prelude::TasmObject;
use twenty_first::math::bfield_codec::BFieldCodec;

use super::shared::CHUNK_SIZE;
use crate::prelude::twenty_first;

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
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> Arbitrary<'a> for Chunk {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let relative_indices = (0..10)
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
    use rand::rng;
    use rand::RngCore;
    use statrs::distribution::ContinuousCDF;
    use statrs::distribution::Normal;
    use twenty_first::math::b_field_element::BFieldElement;

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
            let set = prng.next_u32() % 2 == 0;
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

    proptest::proptest! {
        #[test]
        fn test_indices(indices in proptest::collection::vec(0u32..CHUNK_SIZE, 100)) {
            let mut chunk = Chunk::empty_chunk();
            for index in indices {
                chunk.insert(index);
            }

            let chunk_indices = chunk.to_indices();
            let reconstructed_chunk = Chunk::from_indices(&chunk_indices);

            proptest::prop_assert_eq!(chunk, reconstructed_chunk);
        }

        #[test]
        fn test_chunk_decode(indices in proptest::collection::vec(0u32..CHUNK_SIZE, 100)) {
            let mut chunk = Chunk::empty_chunk();
            for index in indices {
                chunk.insert(index);
            }

            let encoded = chunk.encode();
            let decoded = *Chunk::decode(&encoded).unwrap();

            proptest::prop_assert_eq!(chunk, decoded);
        }
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
}
