use rand::{rngs::StdRng, Rng, SeedableRng};

/// A `BitMask` is a representation of a set of indexed elements. It captures
/// the state of a system where all elements up to a certain bound can be
/// enumerated in principle, but some elements are present, and some are not.
#[derive(Debug, Clone)]
pub(crate) struct BitMask {
    upper_bound: u64,
    limbs: Vec<u32>,
}

impl BitMask {
    /// Create a new [`BitMask`] object.
    ///
    /// All bits are initialized to zero.
    pub(crate) fn new(upper_bound: u64) -> Self {
        let num_limbs = upper_bound.div_ceil(32);
        let limbs = vec![0_u32; num_limbs.try_into().unwrap()];
        Self { upper_bound, limbs }
    }

    /// Increase the upper bound.
    ///
    /// Set all new bits to zero.
    ///
    /// # Panics
    ///
    ///  - If the new upper bound is less than the old.
    pub(crate) fn extend(self, new_upper_bound: u64) -> Self {
        assert!(new_upper_bound >= self.upper_bound);
        let new_num_limbs = new_upper_bound.div_ceil(32);
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
        let new_num_limbs = new_upper_bound.div_ceil(32);
        while self.limbs.len() > new_num_limbs.try_into().unwrap() {
            self.limbs.pop();
        }
        self
    }

    /// Determine whether the ith bit is set.
    pub(crate) fn contains(&self, index: u64) -> bool {
        let limb_index = usize::try_from(index.div_ceil(32)).unwrap();
        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index] & mask != 0
    }

    /// Set the ith bit.
    ///
    /// Ensure it is set to one.
    pub(crate) fn set(&mut self, index: u64) {
        let limb_index = usize::try_from((index + 31) / 32).unwrap();
        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        self.limbs[limb_index] |= mask;
    }

    /// Unset the ith bit.
    ///
    /// Ensure it is set to zero.
    pub(crate) fn unset(&mut self, index: u64) {
        let limb_index = usize::try_from((index + 31) / 32).unwrap();
        let shift_amount = index % 32;
        let mask = 1_u32 << shift_amount;
        let mask = u32::MAX ^ mask;
        self.limbs[limb_index] &= mask;
    }

    /// Set bits min through max (ends inclusive).
    pub(crate) fn set_range(&mut self, min: u64, max: u64) {
        if max - min < 32 {
            for i in min..=max {
                self.set(i);
            }
            return;
        }

        if min % 32 != 0 {
            for i in min..=min.next_multiple_of(32) {
                self.set(i);
            }
        }

        if max % 32 != 0 {
            for i in (max.next_multiple_of(32) - 32)..max {
                self.set(i);
            }
        }

        for i in (min.next_multiple_of(32) / 32)..((max.next_multiple_of(32) - 32) / 32) {
            self.limbs[usize::try_from(i).unwrap()] = u32::MAX;
        }
    }

    /// Return the vector of indices of set bits.
    pub(crate) fn to_vec(&self) -> Vec<u64> {
        let mut offset = 0;
        let mut elements = vec![];
        for limb in self.limbs.iter() {
            if *limb == 0 {
                continue;
            }

            for i in 0..32 {
                let mask = 1u32 << i;
                if limb & mask != 0 {
                    elements.push(offset + i);
                }
            }

            offset += 32;
        }

        elements
    }

    /// Sample an element from the set.
    ///
    /// In other words, sample an integer whose index is a one-bit.
    pub(crate) fn sample(&self, seed: [u8; 32]) -> u64 {
        let [single_element] = self.sample_many(seed);
        single_element
    }

    pub(crate) fn sample_many<const N: usize>(&self, seed: [u8; 32]) -> [u64; N] {
        let mut rng = StdRng::from_seed(seed);
        let mut elements = vec![];
        let mut num_misses = 0;
        while elements.len() != N {
            let index = rng.random_range(0u64..self.upper_bound);
            if self.contains(index) {
                elements.push(index);
            } else {
                num_misses += 1;
                if num_misses > 10 * (1 + elements.len()) {
                    let remainder = self.sample_many_densified(rng.random(), N - elements.len());
                    return [elements, remainder].concat().try_into().unwrap();
                }
            }
        }

        elements.try_into().unwrap()
    }

    fn sample_many_densified(&self, seed: [u8; 32], len: usize) -> Vec<u64> {
        let mut rng = StdRng::from_seed(seed);
        let list = self.to_vec();
        let mut elements = vec![];
        while elements.len() != len {
            elements.push(list[rng.random_range(0..list.len())]);
        }
        elements
    }
}
