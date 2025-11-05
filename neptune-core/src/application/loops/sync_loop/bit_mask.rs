use itertools::Itertools;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

/// A `BitMask` is a representation of a set of indexed elements. It captures
/// the state of a system where all elements up to a certain bound can be
/// enumerated in principle, but some elements are present, and some are not.
#[derive(Debug, Clone)]
pub(crate) struct BitMask {
    // exclusive
    upper_bound: u64,
    limbs: Vec<u32>,
}

impl PartialEq for BitMask {
    fn eq(&self, other: &Self) -> bool {
        if self.upper_bound != other.upper_bound {
            return false;
        }
        if self.upper_bound.is_multiple_of(32) {
            return self.limbs == other.limbs;
        }
        let last = (self.upper_bound / 32) as usize;
        if last != 0
            && self
                .limbs
                .iter()
                .zip(other.limbs.iter())
                .take(last - 1)
                .any(|(l, r)| l != r)
        {
            return false;
        }
        let shamt = self.upper_bound % 32;
        let mask = (1u32 << shamt) - 1;
        (self.limbs[last] ^ other.limbs[last]) & mask == 0
    }
}
impl Eq for BitMask {}

impl BitMask {
    fn num_limbs(max_bit_index: u64) -> usize {
        (if (max_bit_index + 1).is_multiple_of(32) {
            (max_bit_index + 1) / 32
        } else {
            (max_bit_index / 32) + 1
        }) as usize
    }

    /// Create a new [`BitMask`] object.
    ///
    /// All bits are initialized to zero. The argument, `upper_bound` is
    /// exclusive, meaning that the max index is `upper_bound` - 1.
    ///
    /// # Panics
    ///  - If `upper_bound` == 0
    pub(crate) fn new(upper_bound: u64) -> Self {
        let num_limbs = Self::num_limbs(upper_bound - 1);
        let limbs = vec![0_u32; num_limbs];
        Self { upper_bound, limbs }
    }

    /// Increase the upper bound.
    ///
    /// Set all new bits to zero.
    ///
    /// # Panics
    ///
    ///  - If the new upper bound is less than the old.
    pub(crate) fn expand(self, new_upper_bound: u64) -> Self {
        assert!(new_upper_bound >= self.upper_bound);
        let new_num_limbs = Self::num_limbs(new_upper_bound - 1);
        let extra_limbs = usize::try_from(new_num_limbs).unwrap() - self.limbs.len();
        let new_limbs = [self.limbs, vec![0u32; extra_limbs]].concat();
        Self {
            upper_bound: new_upper_bound,
            limbs: new_limbs,
        }
    }

    /// Decrease the upper bound.
    ///
    /// # Panics
    ///
    ///  - If the new upper bound is greater than the old.
    pub(crate) fn shrink(mut self, new_upper_bound: u64) -> Self {
        assert!(new_upper_bound <= self.upper_bound);
        let new_num_limbs = Self::num_limbs(new_upper_bound - 1);
        while self.limbs.len() > new_num_limbs {
            self.limbs.pop();
        }
        for index in new_upper_bound..(32 * (new_num_limbs as u64)) {
            self.unset(index);
        }
        self.upper_bound = new_upper_bound;
        self
    }

    /// Determine whether the ith bit is set.
    pub(crate) fn contains(&self, index: u64) -> bool {
        let limb_index = usize::try_from(index / 32).unwrap();
        if limb_index >= self.limbs.len() {
            return false;
        }

        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index] & mask != 0
    }

    /// Set the ith bit.
    ///
    /// Ensure it is set to one.
    pub(crate) fn set(&mut self, index: u64) {
        let limb_index = usize::try_from(index / 32).unwrap();
        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index] |= mask;
    }

    /// Unset the ith bit.
    ///
    /// Ensure it is set to zero.
    pub(crate) fn unset(&mut self, index: u64) {
        let limb_index = usize::try_from(index / 32).unwrap();
        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        let mask = u32::MAX ^ mask;
        self.limbs[limb_index] &= mask;
    }

    /// Set bits min through max (ends inclusive).
    pub(crate) fn set_range(&mut self, min: u64, max: u64) {
        let first_full_limb = min.div_ceil(32);
        let first_index_in_full_limb = min.div_ceil(32) * 32;
        let successor_of_last_full_limb = max / 32;
        let first_index_after_last_full_limb = successor_of_last_full_limb * 32;

        for limb_i in first_full_limb..successor_of_last_full_limb {
            self.limbs[limb_i as usize] = u32::MAX;
        }
        for index in min..u64::min(max, first_index_in_full_limb) {
            self.set(index);
        }
        for index in u64::max(min, first_index_after_last_full_limb)..=max {
            self.set(index);
        }
    }

    /// Return the vector of indices of set bits.
    pub(crate) fn to_vec(&self) -> Vec<u64> {
        let mut offset = 0;
        let mut elements = vec![];
        for limb in &self.limbs {
            if *limb == 0 {
                offset += 32;
                continue;
            }

            for i in 0u64..32 {
                let mask = 1u32 << i;
                if limb & mask != 0 {
                    elements.push(offset + i);
                }
            }

            offset += 32;
        }

        elements
            .into_iter()
            .filter(|e| *e < self.upper_bound)
            .collect_vec()
    }

    /// Return the vector of indices of unset bits
    pub(crate) fn to_vec_complement(&self) -> Vec<u64> {
        let mut offset = 0;
        let mut elements = vec![];
        for limb in &self.limbs {
            if *limb == u32::MAX {
                offset += 32;
                continue;
            }

            for i in 0_u64..32 {
                let mask = 1u32 << i;
                if limb & mask == 0 {
                    elements.push(offset + i);
                }
            }

            offset += 32;
        }

        elements
            .into_iter()
            .filter(|e| *e < self.upper_bound)
            .collect_vec()
    }

    /// Sample an element from the set.
    ///
    /// In other words, sample an index into the bit array whose indicated
    /// element matches with value.
    pub(crate) fn sample(&self, value: bool, seed: [u8; 32]) -> u64 {
        let [single_element] = self.sample_many(value, seed);
        single_element
    }

    /// Sample elements from the set.
    ///
    /// In other words, sample an index into the bit array whose indicated
    /// element matches with value. Do this many times.
    pub(crate) fn sample_many<const N: usize>(&self, target: bool, seed: [u8; 32]) -> [u64; N] {
        let mut rng = StdRng::from_seed(seed);
        let mut elements = vec![];
        let mut num_misses = 0;
        while elements.len() != N {
            let index = rng.random_range(0u64..self.upper_bound);
            if self.contains(index) == target {
                elements.push(index);
            } else {
                num_misses += 1;
                if num_misses > 10 * (1 + elements.len()) {
                    let remainder =
                        self.sample_many_densified(target, N - elements.len(), rng.random());
                    return [elements, remainder].concat().try_into().unwrap();
                }
            }
        }

        elements.try_into().unwrap()
    }

    fn sample_many_densified(&self, target: bool, len: usize, seed: [u8; 32]) -> Vec<u64> {
        let mut rng = StdRng::from_seed(seed);
        let list = if target {
            self.to_vec()
        } else {
            self.to_vec_complement()
        };
        let mut elements = vec![];
        while elements.len() != len {
            elements.push(list[rng.random_range(0..list.len())]);
        }
        elements
    }

    /// Determine whether all bits are set.
    pub(crate) fn is_complete(&self) -> bool {
        if self.upper_bound == 0 {
            return true;
        }
        for limb in self.limbs.iter().take(self.limbs.len() - 1) {
            if *limb != u32::MAX {
                return false;
            }
        }
        for i in 0..=((self.upper_bound - 1) % 32) {
            if (1 << i) & *self.limbs.last().unwrap() == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use test_strategy::proptest;

    #[proptest]
    fn set_indices_are_set_and_unset_remain_unset(
        #[strategy(1..(1_u64<<15))] upper_bound: u64,
        #[strategy(vec(0u64..#upper_bound, u64::min(#upper_bound, 1000) as usize))]
        set_indices: Vec<u64>,
    ) {
        let mut bit_mask = BitMask::new(upper_bound);
        for index in &set_indices {
            bit_mask.set(*index);
        }

        for index in 0u64..upper_bound {
            prop_assert_eq!(set_indices.contains(&index), bit_mask.contains(index))
        }
    }

    #[proptest]
    fn bit_mask_is_complete_iff_all_its_are_set(
        #[strategy(2..(1_u64<<15))] upper_bound: u64,
        #[strategy(vec(0u64..#upper_bound,(#upper_bound-2) as usize))] bit_indices: Vec<u64>,
    ) {
        let mut bit_mask = BitMask::new(upper_bound);
        prop_assert!(!bit_mask.is_complete());

        for index in bit_indices {
            bit_mask.set(index);
        }
        prop_assert!(!bit_mask.is_complete());

        bit_mask.set_range(0, upper_bound - 1);
        prop_assert!(bit_mask.is_complete());
    }

    #[proptest]
    fn set_range_sets_range(
        #[strategy(2..(1_u64<<15))] upper_bound: u64,
        #[strategy(0..(#upper_bound-1))] range_start: u64,
        #[strategy(#range_start..#upper_bound)] range_stop: u64,
    ) {
        let mut bit_mask = BitMask::new(upper_bound);
        bit_mask.set_range(range_start, range_stop);

        for index in 0u64..upper_bound {
            prop_assert_eq!(
                (range_start..=range_stop).contains(&index),
                bit_mask.contains(index)
            )
        }
    }

    #[test]
    fn set_range_sets_range_unit() {
        for (upper_bound, range_start, range_stop) in [
            (38_u64, 0_u64, 32_u64),
            (5598, 11, 3263),
            (19666, 9718, 9718),
        ] {
            let mut bit_mask = BitMask::new(upper_bound);
            bit_mask.set_range(range_start, range_stop);

            for index in 0u64..upper_bound {
                assert_eq!(
                    (range_start..=range_stop).contains(&index),
                    bit_mask.contains(index)
                )
            }
        }
    }

    #[proptest]
    fn sample_dense_samples_target(
        #[strategy(100..(1_u64<<15))] upper_bound: u64,
        #[strategy(vec(0u64..#upper_bound, 10))] set_indices: Vec<u64>,
        #[strategy(0u64..u64::MAX)] seed: u64,
        target: bool,
    ) {
        let mut bit_mask = BitMask::new(upper_bound);
        if target {
            bit_mask.set_range(0, upper_bound - 1);
            for index in &set_indices {
                bit_mask.unset(*index);
            }
        } else {
            for index in &set_indices {
                bit_mask.set(*index);
            }
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let index = bit_mask.sample(target, rng.random());
        prop_assert_eq!(target, bit_mask.contains(index));
    }

    #[test]
    fn sample_dense_samples_target_unit() {
        for (upper_bound, seed, target) in [(100_u64, 0_u64, false), (100, 203, true)] {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..10)
                .map(|_| rng.random_range(0u64..upper_bound))
                .collect_vec();

            let mut bit_mask = BitMask::new(upper_bound);
            if target {
                bit_mask.set_range(0, upper_bound - 1);
                for index in &set_indices {
                    bit_mask.unset(*index);
                }
            } else {
                for index in &set_indices {
                    bit_mask.set(*index);
                }
            }

            let index = bit_mask.sample(target, rng.random());
            assert_eq!(target, bit_mask.contains(index));
        }
    }

    #[proptest]
    fn sample_sparse_samples_target(
        #[strategy(100..(1_u64<<15))] upper_bound: u64,
        #[strategy(vec(0u64..#upper_bound, 10))] set_indices: Vec<u64>,
        #[strategy(0u64..u64::MAX)] seed: u64,
        target: bool,
    ) {
        let mut bit_mask = BitMask::new(upper_bound);

        if target {
            for index in &set_indices {
                bit_mask.set(*index);
            }
        } else {
            bit_mask.set_range(0, upper_bound - 1);
            for index in &set_indices {
                bit_mask.unset(*index);
            }
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let index = bit_mask.sample(target, rng.random());
        prop_assert_eq!(target, bit_mask.contains(index));
    }

    #[test]
    fn sample_sparse_samples_target_unit() {
        for (upper_bound, seed, target) in [
            (100_u64, 0_u64, false),
            (100, 1, true),
            (145, 5528042011211264207, true),
        ] {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..10)
                .map(|_| rng.random_range(0..upper_bound))
                .collect_vec();

            let mut bit_mask = BitMask::new(upper_bound);

            if target {
                for index in &set_indices {
                    bit_mask.set(*index);
                }
            } else {
                bit_mask.set_range(0, upper_bound - 1);
                for index in &set_indices {
                    bit_mask.unset(*index);
                }
            }

            let index = bit_mask.sample(target, rng.random());
            assert_eq!(target, bit_mask.contains(index));
        }
    }

    #[test]
    fn sample_sparse_samples_target_unit_proptest_regression() {
        for (upper_bound, set_indices, seed, target) in [
            (
                145_u64,
                vec![64, 64, 64, 0, 68, 64, 64, 3, 64, 64],
                5528042011211264207_u64,
                true,
            ),
            (
                105,
                vec![6, 9, 96, 16, 18, 12, 23, 49, 100, 12],
                9495413841520055326,
                false,
            ),
        ] {
            let mut bit_mask = BitMask::new(upper_bound);

            if target {
                for index in &set_indices {
                    bit_mask.set(*index);
                }
            } else {
                bit_mask.set_range(0, upper_bound - 1);
                for index in &set_indices {
                    bit_mask.unset(*index);
                }
            }

            let mut rng = StdRng::seed_from_u64(seed);
            let sampling_seed = rng.random();
            let index = bit_mask.sample(target, sampling_seed);
            assert_eq!(target, bit_mask.contains(index));
        }
    }

    #[proptest]
    fn expand_then_shrink_is_identity(
        #[strategy(2..(1_u64<<15))] large_upper_bound: u64,
        #[strategy(1..#large_upper_bound)] small_upper_bound: u64,
        #[strategy(vec(0u64..#small_upper_bound, u64::min(#small_upper_bound, 1000) as usize))]
        set_indices: Vec<u64>,
    ) {
        let mut bit_mask = BitMask::new(small_upper_bound);
        for index in &set_indices {
            bit_mask.set(*index);
        }

        let mut new_bit_mask = bit_mask.clone();
        new_bit_mask = new_bit_mask.expand(large_upper_bound);
        new_bit_mask = new_bit_mask.shrink(small_upper_bound);
        prop_assert_eq!(bit_mask, new_bit_mask);
    }

    #[test]
    fn expand_then_shrink_is_identity_unit() {
        for (large_upper_bound, small_upper_bound, seed) in [(2_u64, 1_u64, 0_u64), (200, 100, 483)]
        {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..1000)
                .map(|_| rng.random_range(0..small_upper_bound))
                .collect_vec();
            let mut bit_mask = BitMask::new(small_upper_bound);
            for index in &set_indices {
                bit_mask.set(*index);
            }

            let mut new_bit_mask = bit_mask.clone();
            new_bit_mask = new_bit_mask.expand(large_upper_bound);
            new_bit_mask = new_bit_mask.shrink(small_upper_bound);
            assert_eq!(bit_mask, new_bit_mask);
        }
    }

    #[proptest]
    fn shrink_then_expand_resets_dropped_bits(
        #[strategy(2..(1_u64<<15))] large_upper_bound: u64,
        #[strategy(1..#large_upper_bound)] small_upper_bound: u64,
        #[strategy(vec(0u64..#large_upper_bound, u64::min(#large_upper_bound, 1000) as usize))]
        set_indices: Vec<u64>,
    ) {
        let mut bit_mask = BitMask::new(large_upper_bound);
        for index in &set_indices {
            bit_mask.set(*index);
        }

        let mut new_bit_mask = bit_mask.clone();
        new_bit_mask = new_bit_mask.shrink(small_upper_bound);
        new_bit_mask = new_bit_mask.expand(large_upper_bound);
        for index in small_upper_bound..large_upper_bound {
            prop_assert!(!new_bit_mask.contains(index));
        }
    }

    #[test]
    fn shrink_then_expand_resets_dropped_bits_unit() {
        for (large_upper_bound, small_upper_bound, seed) in [(2_u64, 1_u64, 0_u64), (200, 100, 300)]
        {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..u64::min(large_upper_bound, 1000))
                .map(|_| rng.random_range(0..large_upper_bound))
                .collect_vec();

            let mut bit_mask = BitMask::new(large_upper_bound);
            for index in &set_indices {
                bit_mask.set(*index);
            }

            let mut new_bit_mask = bit_mask.clone();
            new_bit_mask = new_bit_mask.shrink(small_upper_bound);
            new_bit_mask = new_bit_mask.expand(large_upper_bound);
            for index in small_upper_bound..large_upper_bound {
                assert!(
                    !new_bit_mask.contains(index),
                    "index: {index}\nbit mask: {new_bit_mask:?}"
                );
            }
        }
    }

    #[test]
    fn can_sample_index_for_zero() {
        let mut bit_mask = BitMask::new(200);
        bit_mask.set_range(0, 100);
        for i in [122, 117, 136, 116, 105, 187, 111, 143, 108, 111] {
            bit_mask.set(i);
        }

        let seed = 4552531317295863509_u64;
        let mut rng = StdRng::seed_from_u64(seed);

        let index = bit_mask.sample(false, rng.random());

        assert!(!bit_mask.contains(index));
    }
}
