use std::collections::VecDeque;
use std::ops::BitOr;
use std::ops::Not;

use itertools::Itertools;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;

/// A [`SynchronizationBitMask`] is a representation of the synchronization
/// state of a set of indexed elements (such as blocks). It captures the state
/// of a system where all elements up to a certain bound can be enumerated in
/// principle, but some elements are present, and some are not.
///
/// [`SynchronizationBitMask`]s can be used to as a database to concisely
/// represent which blocks have been downloaded already and which have not, or
/// as a reconciliation primitive for syncing peers to rapidly determine which
/// blocks they can serve that their counterparts are missing.
//
// # Implementation Details
//
// Up to and including index `lower_bound`, all bits are implicitly set to 1.
// At and beyond index `upper_bound`, all bits are implicitly set to 0. Between
// the lower and upper bound, the bits can be 0 or 1, and so these bits are
// represented explicitly through a vector of u32s called `limbs`. The index
// boundary separating one limb from the next is independent of `lower_bound`
// and of `upper_bound`, but the values of these bounds can affect which slice
// of limbs is stored.
//
// Not every bit mask has a unique representation. Two SynchronizationBitMasks
// can be equivalent as bit masks but have a different upper bound.
//
// However, with respect to the lower bound, this value is guaranteed to be set
// to the highest possible value. So in particular, the bit at index
// `lower_bound` must always be 0. Whenever this bit is set to 1, the
// `lower_bound` increases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SynchronizationBitMask {
    // inclusive
    pub(crate) lower_bound: u64,

    // exclusive
    pub(crate) upper_bound: u64,

    limbs: VecDeque<u32>,
}

impl PartialEq for SynchronizationBitMask {
    fn eq(&self, other: &Self) -> bool {
        if self.lower_bound != other.lower_bound || self.upper_bound != other.upper_bound {
            return false;
        }
        if self.lower_bound == self.upper_bound {
            return true;
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
        let offset = (self.lower_bound / 32) as usize;
        let shamt = self.upper_bound % 32;
        let mask = (1u32 << shamt) - 1;
        (self.limbs[last - offset] ^ other.limbs[last - offset]) & mask == 0
    }
}
impl Eq for SynchronizationBitMask {}

impl Not for SynchronizationBitMask {
    type Output = SynchronizationBitMask;

    /// Inverts only the middle portion of the bit mask, not the all-ones at the
    /// start nor the infinite-zeros at the end.
    fn not(self) -> Self::Output {
        let mut limbs = self
            .limbs
            .iter()
            .map(|limb| !*limb)
            .collect::<VecDeque<u32>>();
        if let Some(limb) = limbs.back_mut() {
            let bound = self.upper_bound % 32;
            if bound != 0 {
                for i in bound..32 {
                    *limb &= !(1 << i);
                }
            }
        }
        SynchronizationBitMask {
            upper_bound: self.upper_bound,
            lower_bound: self.lower_bound,
            limbs,
        }
        .canonize()
    }
}

impl BitOr for SynchronizationBitMask {
    type Output = SynchronizationBitMask;

    fn bitor(self, rhs: Self) -> Self::Output {
        let upper_bound = u64::max(self.upper_bound, rhs.upper_bound);
        if upper_bound == 0 {
            return Self {
                lower_bound: 0,
                upper_bound,
                limbs: VecDeque::new(),
            };
        }

        let lower_bound = u64::max(self.lower_bound, rhs.lower_bound);
        if lower_bound == upper_bound {
            return Self {
                lower_bound,
                upper_bound,
                limbs: VecDeque::new(),
            };
        }

        let limbs = ((lower_bound / 32)..=((upper_bound.saturating_sub(1)) / 32))
            .map(|i| {
                let index = i.try_into().expect(
                    "SynchronizationBitMasks cannot handle more limbs than fit in a usize.",
                );
                self.limb(index) | rhs.limb(index)
            })
            .collect::<VecDeque<u32>>();
        Self::Output {
            lower_bound,
            upper_bound,
            limbs,
        }
        .canonize()
    }
}

impl SynchronizationBitMask {
    /// Take a [`SynchronizationBitMask`] not in canonical representation and
    /// put it into canonical representation. Canonical representation means
    /// the `lower_bound` field points to the first zero.
    fn canonize(mut self) -> SynchronizationBitMask {
        // TODO: very slow. improve perf!
        while self.contains(self.lower_bound) {
            self.lower_bound += 1;
            if self.lower_bound.is_multiple_of(32) {
                self.limbs.pop_front();
            }
        }

        if self.lower_bound == self.upper_bound {
            self.limbs = VecDeque::new();
        }

        self
    }

    /// Get the ith limb of the entire bit mask.
    fn limb(&self, index: usize) -> u32 {
        let offset = (self.lower_bound / 32)
            .try_into()
            .expect("SynchronizationBitMasks cannot handle more limbs than fit in a usize.");
        if index < offset {
            return u32::MAX;
        }

        let onset = (self.upper_bound.saturating_sub(1) / 32)
            .try_into()
            .expect("SynchronizationBitMasks cannot handle more limbs than fit in a usize.");
        if index <= onset && !self.limbs.is_empty() {
            return self.limbs[index - offset];
        }

        0
    }

    /// Create a new [`SynchronizationBitMask`] object.
    ///
    /// All bits are initialized to zero. The second argument, `upper_bound` is
    /// exclusive, meaning that the max index is `upper_bound` - 1.
    ///
    /// # Panics
    ///
    ///  - If `upper_bound` <= `lower_bound`.
    ///  - If the would-be number of limbs is greater than usize::MAX.
    pub(crate) fn new(lower_bound: u64, upper_bound: u64) -> Self {
        assert!(upper_bound > lower_bound);
        let offset = lower_bound / 32;
        let onset = upper_bound.saturating_sub(1) / 32;
        let num_limbs = if lower_bound == upper_bound {
            0
        } else {
            1_usize + usize::try_from(onset - offset).unwrap()
        };

        let mut limbs = VecDeque::from(vec![0_u32; num_limbs]);

        // set the limb bits below the lower bound
        if let Some(first) = limbs.front_mut() {
            for i in 0..(lower_bound % 32) {
                *first |= 1 << i;
            }
        }

        Self {
            lower_bound,
            upper_bound,
            limbs,
        }
    }

    /// Compute a bitmask whose zeros indicate items that the other does have
    /// and we don't.
    pub(crate) fn reconcile(&self, other: &Self) -> Self {
        let offset = self.lower_bound / 32;
        let onset = self.upper_bound.saturating_sub(1) / 32;

        let limbs = (offset..=onset)
            .map(|i| usize::try_from(i).expect("Limb indices fit in usizes."))
            .map(|i| self.limb(i) | !other.limb(i))
            .collect::<VecDeque<u32>>();

        Self {
            lower_bound: self.lower_bound,
            upper_bound: self.upper_bound,
            limbs,
        }
        .canonize()
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

        let offset = self.lower_bound / 32;
        let onset = new_upper_bound.saturating_sub(1) / 32;
        let num_limbs = if self.lower_bound == new_upper_bound {
            0
        } else {
            1_usize + usize::try_from(onset - offset).unwrap()
        };

        let extra_limbs = num_limbs.saturating_sub(self.limbs.len());
        let new_limbs = self
            .limbs
            .into_iter()
            .chain(std::iter::repeat_n(0u32, extra_limbs))
            .collect::<VecDeque<u32>>();
        Self {
            lower_bound: self.lower_bound,
            upper_bound: new_upper_bound,
            limbs: new_limbs,
        }
    }

    /// Determine whether the ith bit is set.
    ///
    /// # Panics
    ///  - If the limb index corresponding to the given bit index is smaller
    ///    than usize::MAX.
    pub(crate) fn contains(&self, index: u64) -> bool {
        if index < self.lower_bound {
            return true;
        } else if index >= self.upper_bound {
            return false;
        }

        let limb_index = usize::try_from(index / 32).unwrap();
        let offset = usize::try_from(self.lower_bound / 32).unwrap();

        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index - offset] & mask != 0
    }

    /// Set the ith bit.
    ///
    /// Ensure it is set to one.
    ///
    /// # Panics
    ///
    ///  - If the given index is greater than or equal to the upper bound.
    pub(crate) fn set(&mut self, index: u64) {
        if index < self.lower_bound {
            return;
        }

        assert!(index < self.upper_bound);
        if self.lower_bound == self.upper_bound {
            return;
        }

        let limb_index = usize::try_from(index / 32).unwrap();
        let offset = usize::try_from(self.lower_bound / 32).unwrap();
        if limb_index < offset {
            return;
        }

        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index - offset] |= mask;

        *self = self.clone().canonize();
    }

    /// Return the vector of indices of unset bits in between lower bound and
    /// upper bound.
    pub(crate) fn to_vec_complement(&self) -> Vec<u64> {
        (self.lower_bound..self.upper_bound)
            .filter(|i| !self.contains(*i))
            .collect_vec()
    }

    /// Sample an index between lower and upper bounds whose corresponding bit
    /// is zero.
    ///
    /// # Panics
    ///
    ///  - If lower bound >= upper bound.
    pub(crate) fn sample(&self, seed: [u8; 32]) -> u64 {
        let [single_element] = self.sample_many(seed);
        single_element
    }

    /// Sample an index between lower and upper bounds with the given value. Do
    /// this many times.
    ///
    /// # Panics
    ///
    ///  - If lower bound >= upper bound.
    pub(crate) fn sample_many<const N: usize>(&self, seed: [u8; 32]) -> [u64; N] {
        assert_ne!(self.lower_bound, self.upper_bound);
        let mut rng = StdRng::from_seed(seed);
        let mut elements = vec![];
        let mut num_misses = 0;
        while elements.len() != N {
            let index = rng.random_range(self.lower_bound..self.upper_bound);
            if !self.contains(index) {
                elements.push(index);
            } else {
                num_misses += 1;
                if num_misses > 10 * (1 + elements.len()) {
                    let remainder = self.sample_many_densified(N - elements.len(), rng.random());
                    return [elements, remainder].concat().try_into().unwrap();
                }
            }
        }

        elements.try_into().unwrap()
    }

    fn sample_many_densified(&self, len: usize, seed: [u8; 32]) -> Vec<u64> {
        let mut rng = StdRng::from_seed(seed);
        let list = self.to_vec_complement();
        let mut elements = vec![];
        while elements.len() != len {
            elements.push(list[rng.random_range(0..list.len())]);
        }
        elements
    }

    /// Determine whether all bits up to the upper bound are set.
    pub(crate) fn is_complete(&self) -> bool {
        // Canonicity requires that the lower bound be set as high as possible,
        // i.e. it is the index of the first zero. If the bit mask is complete,
        // then the first zero is exactly the point where the infinte string of
        // zeros starts.
        self.lower_bound == self.upper_bound
    }

    /// Count the number of ones between the lower and upper bounds.
    pub(crate) fn pop_count(&self) -> u64 {
        let mut pop_count = 0u64;
        for (i, limb) in self.limbs.iter().copied().enumerate() {
            if limb == 0 {
                continue;
            }

            if i == 0 && !self.lower_bound.is_multiple_of(32) {
                let mask = (1 << (self.lower_bound % 32)) - 1;
                pop_count += u64::from((limb & (!mask)).count_ones());
            } else if i == self.limbs.len() - 1 && !self.upper_bound.is_multiple_of(32) {
                let mask = (1 << (self.upper_bound % 32)) - 1;
                pop_count += u64::from((limb & mask).count_ones());
            } else {
                pop_count += u64::from(limb.count_ones());
            }
        }
        pop_count
    }

    /// Set bits min through max (ends inclusive).
    ///
    /// # Panics
    ///
    ///  - If either of the given indices is greater than the upper bound.
    ///  - If max < min.
    pub(crate) fn set_range(&mut self, min: u64, max: u64) {
        assert!(max < self.upper_bound);
        assert!(min < self.upper_bound);
        assert!(max >= min);
        let first_full_limb = min.div_ceil(32);
        let first_index_in_full_limb = min.div_ceil(32) * 32;
        let successor_of_last_full_limb = max / 32;
        let first_index_after_last_full_limb = successor_of_last_full_limb * 32;
        let offset = usize::try_from(self.lower_bound / 32).unwrap();

        for limb_i in first_full_limb..successor_of_last_full_limb {
            self.limbs[limb_i as usize - offset] = u32::MAX;
        }
        for index in min..u64::min(max, first_index_in_full_limb) {
            self.set(index);
        }
        for index in u64::max(min, first_index_after_last_full_limb)..=max {
            self.set(index);
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::hint::black_box;

    use proptest::collection::vec;
    use proptest::prelude::Just;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use rand::RngCore;
    use test_strategy::proptest;

    use super::*;

    impl SynchronizationBitMask {
        pub(crate) fn random(lower_bound: u64, upper_bound: u64) -> Self {
            assert!(upper_bound >= lower_bound);

            if lower_bound == upper_bound {
                return SynchronizationBitMask {
                    lower_bound,
                    upper_bound,
                    limbs: VecDeque::new(),
                };
            }

            let offset = lower_bound / 32;
            let onset = (upper_bound.saturating_sub(1)) / 32;
            let num_limbs = onset - offset + 1;
            let mut rng = rng();
            let mut limbs = (0..num_limbs)
                .map(|_| rng.next_u32())
                .collect::<VecDeque<u32>>();
            if let Some(first) = limbs.front_mut() {
                if !lower_bound.is_multiple_of(32) {
                    *first |= (1 << (lower_bound % 32)) - 1;
                }
            }
            if let Some(last) = limbs.back_mut() {
                if !upper_bound.is_multiple_of(32) {
                    *last &= u32::MAX >> (32 - (upper_bound % 32));
                }
            }

            SynchronizationBitMask {
                lower_bound,
                upper_bound,
                limbs,
            }
            .canonize()
        }

        /// Decrease the upper bound.
        ///
        /// # Panics
        ///
        ///  - If the new upper bound is greater than the old.
        pub(crate) fn shrink(mut self, new_upper_bound: u64) -> Self {
            assert!(new_upper_bound <= self.upper_bound);

            let new_lower_bound = u64::min(self.lower_bound, new_upper_bound);

            let offset = new_lower_bound / 32;
            let onset = new_upper_bound.saturating_sub(1) / 32;
            let num_limbs = if new_lower_bound == new_upper_bound {
                0
            } else {
                1_usize + usize::try_from(onset - offset).unwrap()
            };

            while self.limbs.len() > num_limbs {
                self.limbs.pop_back();
            }
            if let Some(last) = self.limbs.back_mut() {
                if !new_upper_bound.is_multiple_of(32) {
                    let shamt = 32 - (new_upper_bound % 32);
                    *last &= u32::MAX >> shamt;
                }
            }

            self.upper_bound = new_upper_bound;
            self.lower_bound = new_lower_bound;
            self
        }
    }

    #[proptest]
    fn can_sample_random_bitmask(
        #[strategy(0_u64..(1<<15))] lower_bound: u64,
        #[strategy(0u64..(1<<8))] length: u64,
    ) {
        let upper_bound = lower_bound + length;
        let bit_mask = SynchronizationBitMask::random(lower_bound, upper_bound);
        black_box(bit_mask);
    }

    #[proptest]
    fn random_bitmask_is_canonical_prop(
        #[strategy(0_u64..(1<<15))] lower_bound: u64,
        #[strategy(0u64..(1<<8))] length: u64,
    ) {
        let upper_bound = lower_bound + length;
        let bit_mask = SynchronizationBitMask::random(lower_bound, upper_bound);
        prop_assert!(!bit_mask.contains(bit_mask.lower_bound));
        prop_assert!(bit_mask.lower_bound < bit_mask.upper_bound || bit_mask.limbs.is_empty());
    }

    #[test]
    fn random_bitmask_is_canonical_unit() {
        let lower_bound = 5984;
        let length = 1;
        let upper_bound = lower_bound + length;
        let bit_mask = SynchronizationBitMask::random(lower_bound, upper_bound);
        assert!(!bit_mask.contains(bit_mask.lower_bound));
        assert!(bit_mask.lower_bound < bit_mask.upper_bound || bit_mask.limbs.is_empty());
    }

    #[proptest]
    fn setting_single_index_works(
        #[strategy(0_u64..(1<<15))] lower_bound: u64,
        #[strategy(1u64..(1<<12))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
        #[strategy(#lower_bound..#upper_bound)] index: u64,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        prop_assert!(!bit_mask.contains(index));
        bit_mask.set(index);
        prop_assert!(bit_mask.contains(index));
    }

    #[test]
    fn set_single_index_unit() {
        for (lower_bound, upper_bound, index) in [(17088, 17320, 17116), (31, 39, 31)] {
            let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
            assert!(!bit_mask.contains(index));
            bit_mask.set(index);
            assert!(bit_mask.contains(index));
        }
    }

    #[test]
    fn set_explicit_range_unit() {
        for (lower_bound, upper_bound, indices) in
            [(17088, 17320, 17088..=17116), (31, 39, 31..=31)]
        {
            let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
            for index in indices {
                assert!(!bit_mask.contains(index));
                bit_mask.set(index);
                assert!(bit_mask.contains(index));
            }
        }
    }

    #[proptest]
    fn set_indices_are_set_and_unset_remain_unset_prop(
        #[strategy(0_u64..(1<<6))] lower_bound: u64,
        #[strategy(1u64..(1<<5))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
        #[strategy(vec(#lower_bound..#upper_bound, u64::min(#_length, 1000) as usize))]
        set_indices: Vec<u64>,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        for index in &set_indices {
            bit_mask.set(*index);
        }

        for index in lower_bound..upper_bound {
            prop_assert_eq!(set_indices.contains(&index), bit_mask.contains(index))
        }
    }

    #[test]
    fn set_indices_are_set_and_unset_remain_unset_unit() {
        let lower_bound = 31;
        let upper_bound = 39;
        let set_indices = [31];
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        for index in &set_indices {
            bit_mask.set(*index);
        }

        for index in lower_bound..upper_bound {
            assert_eq!(set_indices.contains(&index), bit_mask.contains(index))
        }
    }

    #[proptest]
    fn bit_mask_is_complete_iff_all_bits_are_set(
        #[strategy(0_u64..(1<<7))] lower_bound: u64,
        #[strategy(3u64..(1<<5))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
        #[strategy(vec(#lower_bound..#upper_bound,(#_length-2) as usize))] bit_indices: Vec<u64>,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        prop_assert!(!bit_mask.is_complete());

        for index in bit_indices {
            bit_mask.set(index);
        }
        prop_assert!(!bit_mask.is_complete());

        bit_mask.set_range(lower_bound, upper_bound - 1);
        prop_assert!(bit_mask.is_complete());
    }

    #[proptest]
    fn set_range_sets_range(
        #[strategy(0_u64..(1<<15))] lower_bound: u64,
        #[strategy(2u64..(1<<12))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
        #[strategy(#lower_bound..(#upper_bound-1))] range_start: u64,
        #[strategy(#range_start..#upper_bound)] range_stop: u64,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        bit_mask.set_range(range_start, range_stop);

        for index in lower_bound..upper_bound {
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
            let mut bit_mask = SynchronizationBitMask::new(0, upper_bound);
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
    fn can_sample_missing_from_incomplete_bitmask(
        #[strategy(0_u64..(1<<50))] lower_bound: u64,
        #[strategy(1u64..(1<<12))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
    ) {
        let bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);

        let _ = bit_mask.sample(rng().random()); // no crash
    }

    #[proptest]
    fn not_of_bitmask_is_canonical(
        #[strategy(1usize..(1<<12))] _length: usize,
        #[strategy((#_length as u64)..(1u64<<50))] upper_bound: u64,
        #[strategy(Just(#upper_bound-(#_length as u64)))] lower_bound: u64,
        #[strategy(vec(#lower_bound..#upper_bound, usize::min(#_length-1, 1000)))] set_indices: Vec<
            u64,
        >,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        for index in set_indices {
            bit_mask.set(index);
        }

        let not = !bit_mask;

        prop_assert!(!not.contains(not.lower_bound));
    }

    #[test]
    fn can_sample_missing_simple_unit() {
        let upper_bound = 171510685654;
        let lower_bound = 171510685625;
        let bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        let mut rng = rng();

        for _ in 0..1000 {
            let _ = bit_mask.sample(rng.random()); // no crash
        }
    }

    #[proptest]
    fn sample_dense_samples_missing_prop(
        #[strategy(0_u64..(1<<15))] lower_bound: u64,
        #[strategy(2u64..(1<<12))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
        #[strategy(vec(#lower_bound..#upper_bound, u64::min(#_length-1, 1000) as usize))]
        set_indices: Vec<u64>,
        #[strategy(0u64..u64::MAX)] seed: u64,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);

        for index in &set_indices {
            bit_mask.set(*index);
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let index = bit_mask.sample(rng.random());
        prop_assert!(!bit_mask.contains(index));
    }

    #[test]
    fn sample_dense_samples_target_unit() {
        for (upper_bound, seed) in [(100_u64, 0_u64)] {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..10)
                .map(|_| rng.random_range(0u64..upper_bound))
                .collect_vec();

            let mut bit_mask = SynchronizationBitMask::new(0, upper_bound);

            for index in &set_indices {
                bit_mask.set(*index);
            }

            let index = bit_mask.sample(rng.random());
            assert!(!bit_mask.contains(index));
        }
    }

    #[proptest]
    fn sample_sparse_samples_missing_index_prop(
        #[strategy(0_u64..(1<<15))] lower_bound: u64,
        #[strategy(2u64..(1<<12))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
        #[strategy(vec(#lower_bound..#upper_bound, u64::min(#_length-1, 1000) as usize))]
        set_indices: Vec<u64>,
        #[strategy(0u64..u64::MAX)] seed: u64,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);

        for index in lower_bound..upper_bound {
            if set_indices.contains(&index) {
                continue;
            }
            bit_mask.set(index);
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let index = bit_mask.sample(rng.random());
        prop_assert!(!bit_mask.contains(index));
    }

    #[test]
    fn sample_sparse_samples_missing_index_unit() {
        for (upper_bound, seed) in [(100_u64, 0_u64)] {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..10)
                .map(|_| rng.random_range(0..upper_bound))
                .collect_vec();

            let mut bit_mask = SynchronizationBitMask::new(0, upper_bound);

            for index in 0..upper_bound {
                if set_indices.contains(&index) {
                    continue;
                }
                bit_mask.set(index);
            }

            let index = bit_mask.sample(rng.random());
            assert!(!bit_mask.contains(index));
        }
    }

    #[test]
    fn sample_sparse_samples_target_unit_proptest_regression() {
        for (upper_bound, set_indices, seed) in [(
            105,
            vec![6, 9, 96, 16, 18, 12, 23, 49, 100, 12],
            9495413841520055326,
        )] {
            let mut bit_mask = SynchronizationBitMask::new(0, upper_bound);

            for index in 0..upper_bound {
                if set_indices.contains(&index) {
                    continue;
                }
                bit_mask.set(index);
            }

            let mut rng = StdRng::seed_from_u64(seed);
            let sampling_seed = rng.random();
            let index = bit_mask.sample(sampling_seed);
            assert!(!bit_mask.contains(index));
        }
    }

    #[proptest]
    fn expand_then_shrink_is_identity_prop(
        #[strategy(0_u64..(1<<16))] lower_bound: u64,
        #[strategy(3u64..(1<<13))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] large_upper_bound: u64,
        #[strategy((#lower_bound+2)..#large_upper_bound)] small_upper_bound: u64,
        #[strategy(vec(#lower_bound..#small_upper_bound, u64::min(#_length, 1000) as usize))]
        set_indices: Vec<u64>,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, small_upper_bound);
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
        for (large_upper_bound, small_upper_bound, seed) in
            [(2_u64, 1_u64, 0_u64), (200, 100, 483), (50, 45, 44)]
        {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..1000)
                .map(|_| rng.random_range(0..small_upper_bound))
                .collect_vec();
            let mut bit_mask = SynchronizationBitMask::new(0, small_upper_bound);
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
    fn shrink_then_expand_resets_dropped_bits_prop(
        #[strategy(2..(1_u64<<15))] large_upper_bound: u64,
        #[strategy(1..#large_upper_bound)] small_upper_bound: u64,
        #[strategy(vec(0u64..#large_upper_bound, u64::min(#large_upper_bound, 1000) as usize))]
        set_indices: Vec<u64>,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(0, large_upper_bound);
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

    #[proptest]
    fn shrink_then_expand_resets_dropped_bits_unit_1() {
        let large_upper_bound = 2;
        let small_upper_bound = 1;
        let set_indices = [0, 1];

        let mut bit_mask = SynchronizationBitMask::new(0, large_upper_bound);
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
    fn shrink_then_expand_resets_dropped_bits_unit_2() {
        for (large_upper_bound, small_upper_bound, seed) in [(2_u64, 1_u64, 2_u64), (200, 100, 300)]
        {
            let mut rng = StdRng::seed_from_u64(seed);
            let set_indices = (0..u64::min(large_upper_bound, 1000))
                .map(|_| rng.random_range(0..large_upper_bound))
                .collect_vec();

            let mut bit_mask = SynchronizationBitMask::new(0, large_upper_bound);
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
        let mut bit_mask = SynchronizationBitMask::new(0, 200);
        bit_mask.set_range(0, 100);
        for i in [122, 117, 136, 116, 105, 187, 111, 143, 108, 111] {
            bit_mask.set(i);
        }

        let seed = 4552531317295863509_u64;
        let mut rng = StdRng::seed_from_u64(seed);

        let index = bit_mask.sample(rng.random());

        assert!(!bit_mask.contains(index));
    }

    #[proptest]
    fn reconcile_prop(
        #[strategy(0usize..5)] num_limbs: usize,
        #[strategy((#num_limbs as u64*32)..(1<<50))] upper_bound: u64,
        #[strategy(vec(arb::<u32>(), #num_limbs+1))] own_limbs: Vec<u32>,
        #[strategy(vec(arb::<u32>(), #num_limbs+1))] peer_limbs: Vec<u32>,
    ) {
        let lower_bound = upper_bound - (num_limbs as u64) * 32;
        let own_coverage = SynchronizationBitMask {
            lower_bound,
            upper_bound,
            limbs: VecDeque::from(own_limbs),
        }
        .canonize();
        let peer_coverage = SynchronizationBitMask {
            lower_bound,
            upper_bound,
            limbs: VecDeque::from(peer_limbs),
        }
        .canonize();

        let reconciliation = own_coverage.reconcile(&peer_coverage);

        print!("        own:  ");
        for i in lower_bound..upper_bound {
            print!("{}", u8::from(own_coverage.contains(i)));
        }
        println!();

        print!("       peer:  ");
        for i in lower_bound..upper_bound {
            print!("{}", u8::from(peer_coverage.contains(i)));
        }
        println!();

        print!("own | !peer:  ");
        for i in lower_bound..upper_bound {
            print!("{}", u8::from(reconciliation.contains(i)));
        }
        println!("\n");

        for index in lower_bound..upper_bound {
            if !own_coverage.contains(index) && peer_coverage.contains(index) {
                prop_assert!(!reconciliation.contains(index));
            } else {
                prop_assert!(reconciliation.contains(index));
            }
        }
    }

    #[test]
    fn reconcile_unit() {
        let num_limbs = 4;
        let upper_bound = 128;
        let own_limbs = [0, 0, 0, 2548952530].to_vec();
        let peer_limbs = [2561858424, 3351979687, 741446663, 3660427733].to_vec();
        let lower_bound = upper_bound - (num_limbs as u64) * 32;
        let own_coverage = SynchronizationBitMask {
            lower_bound,
            upper_bound,
            limbs: VecDeque::from(own_limbs),
        }
        .canonize();
        let peer_coverage = SynchronizationBitMask {
            lower_bound,
            upper_bound,
            limbs: VecDeque::from(peer_limbs),
        }
        .canonize();

        let reconciliation = own_coverage.reconcile(&peer_coverage);

        print!("        own:  ");
        for i in lower_bound..upper_bound {
            print!("{}", u8::from(own_coverage.contains(i)));
        }
        println!();

        print!("       peer:  ");
        for i in lower_bound..upper_bound {
            print!("{}", u8::from(peer_coverage.contains(i)));
        }
        println!();

        print!("own | !peer:  ");
        for i in lower_bound..upper_bound {
            print!("{}", u8::from(reconciliation.contains(i)));
        }
        println!("\n");

        for index in lower_bound..upper_bound {
            if !own_coverage.contains(index) && peer_coverage.contains(index) {
                assert!(!reconciliation.contains(index));
            } else {
                assert!(reconciliation.contains(index));
            }
        }
    }

    #[proptest]
    fn popcount_agrees_with_manual_count_prop(
        #[strategy(0_u64..(1<<16))] lower_bound: u64,
        #[strategy(3u64..(1<<13))] _length: u64,
        #[strategy(Just(#lower_bound + #_length))] upper_bound: u64,
        #[strategy(vec(#lower_bound..#upper_bound, u64::min(#_length, 10) as usize))]
        set_indices: Vec<u64>,
    ) {
        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        for index in &set_indices {
            bit_mask.set(*index);
        }

        let manual_count = (bit_mask.lower_bound..bit_mask.upper_bound)
            .map(|i| if bit_mask.contains(i) { 1 } else { 0 })
            .sum::<u64>();
        prop_assert_eq!(bit_mask.pop_count(), manual_count);
    }

    #[test]
    fn popcount_agrees_with_manual_count_unit() {
        let lower_bound = 30233;
        let length = 1287;
        let upper_bound = lower_bound + length;
        let set_indices = [
            30233, 30233, 30233, 31488, 30233, 30233, 30233, 30233, 30233, 30233,
        ]
        .to_vec();

        let mut bit_mask = SynchronizationBitMask::new(lower_bound, upper_bound);
        assert!(bit_mask.limbs.len() > 1);
        for index in &set_indices {
            bit_mask.set(*index);
        }

        let mut manual_count = 0;
        for index in bit_mask.lower_bound..bit_mask.upper_bound {
            if bit_mask.contains(index) {
                println!("found set bit at index {index}");
                manual_count += 1;
            }
        }

        assert_eq!(bit_mask.pop_count(), manual_count);
    }
}
