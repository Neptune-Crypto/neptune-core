use std::collections::HashMap;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Result;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Unstructured;
use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::Sponge;

use super::super::mutator_set_accumulator::MutatorSetAccumulator;
use super::super::shared::NUM_TRIALS;
use super::MutatorSetError;
use crate::util_types::mutator_set::shared::indices_to_hash_map;
use crate::util_types::mutator_set::shared::BATCH_SIZE;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;
use crate::util_types::mutator_set::shared::WINDOW_SIZE;

/// A set of 45 (=[`NUM_TRIALS`]) sliding window Bloom filter bit indices.
/// The indices live in a window that is at most 2^20 (=[`WINDOW_SIZE`]) wide.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, BFieldCodec, TasmObject, Hash, Serialize, Deserialize,
)]
pub struct AbsoluteIndexSet {
    minimum: u128,

    /// Distances of the indices relative to the minimum. Guaranteed to be in
    /// the range [0; 2^{20}-1].
    #[serde(with = "serde_arrays")]
    distances: [u32; NUM_TRIALS as usize],
}

impl GetSize for AbsoluteIndexSet {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        self.minimum.get_heap_size() + self.distances.get_heap_size()
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl AbsoluteIndexSet {
    /// Construct a new [`AbsoluteIndexSet`] from an array of [`NUM_TRIALS`]-
    /// many `u128`s.
    ///
    /// # Panics
    ///
    ///  - If the array contains elements that are apart by more than
    ///    [`WINDOW_SIZE`].
    pub fn new(absolute_indices: [u128; NUM_TRIALS as usize]) -> Self {
        let minimum = *(absolute_indices.iter().min().unwrap());
        let distances: [u32; NUM_TRIALS as usize] = absolute_indices
            .into_iter()
            .map(|x| x - minimum)
            .map(|x| {
                if x >= WINDOW_SIZE.into() {
                    panic!(
                        "indices must lie less than WINDOW_SIZE apart, but got a distance of {x}"
                    );
                } else {
                    x
                }
            })
            .map(u32::try_from)
            .map(Result::<_, _>::unwrap)
            .collect_vec()
            .try_into()
            .unwrap();

        Self { minimum, distances }
    }

    /// Get the (absolute) indices for removing this item from the mutator set.
    pub fn compute(
        item: Digest,
        sender_randomness: Digest,
        receiver_preimage: Digest,
        aocl_leaf_index: u64,
    ) -> Self {
        let batch_index: u128 = u128::from(aocl_leaf_index) / u128::from(BATCH_SIZE);
        let batch_offset: u128 = batch_index * u128::from(CHUNK_SIZE);
        let leaf_index_bfes = aocl_leaf_index.encode();
        let input = [
            item.encode(),
            sender_randomness.encode(),
            receiver_preimage.encode(),
            leaf_index_bfes,
        ]
        .concat();

        let mut sponge = Tip5::init();
        sponge.pad_and_absorb_all(&input);
        let relative_indices = sponge.sample_indices(WINDOW_SIZE, NUM_TRIALS as usize);
        let minimum = *(relative_indices.iter().min().unwrap());
        let distances: [u32; NUM_TRIALS as usize] = relative_indices
            .into_iter()
            .map(|x| x - minimum)
            .collect_vec()
            .try_into()
            .unwrap();

        Self {
            minimum: u128::from(minimum) + batch_offset,
            distances,
        }
    }

    pub fn to_vec(self) -> Vec<u128> {
        self.to_array().to_vec()
    }

    pub fn to_array(self) -> [u128; NUM_TRIALS as usize] {
        // Saturating add to guard overflow caused by malicious absolute index
        // sets. Malicious absolute index sets will not have a valid proof, so
        // there is no risk of applying such objects to the mutator set.
        self.distances
            .map(|x| u128::from(x).saturating_add(self.minimum))
    }

    /// Split the [`AbsoluteIndexSet`] into two parts, one for chunks in the
    /// inactive part of the Bloom filter and another one for chunks in the
    /// active part of the Bloom filter.
    ///
    /// Returns an error if a removal index is a future value, i.e. one that's
    /// not yet covered by the active window.
    #[expect(clippy::type_complexity)]
    pub(crate) fn split_by_activity(
        &self,
        mutator_set: &MutatorSetAccumulator,
    ) -> Result<(HashMap<u64, Vec<u128>>, Vec<u128>), MutatorSetError> {
        let (aw_chunk_index_min, aw_chunk_index_max) = mutator_set.active_window_chunk_interval();
        let (inactive, active): (HashMap<_, _>, HashMap<_, _>) =
            indices_to_hash_map(&self.to_array())
                .into_iter()
                .partition(|&(chunk_index, _)| chunk_index < aw_chunk_index_min);

        if let Some(chunk_index) = active.keys().find(|&&k| k > aw_chunk_index_max) {
            return Err(MutatorSetError::AbsoluteRemovalIndexIsFutureIndex {
                current_max_chunk_index: aw_chunk_index_max,
                saw_chunk_index: *chunk_index,
            });
        }

        let active = active.into_values().flatten().collect_vec();

        Ok((inactive, active))
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> Arbitrary<'a> for AbsoluteIndexSet {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let aocl_index = u64::arbitrary(u)? >> 1;
        let window_start = u128::from(aocl_index) / u128::from(BATCH_SIZE) * u128::from(CHUNK_SIZE);
        let mut relative_indices = vec![];
        for _ in 0..NUM_TRIALS {
            let index = u32::arbitrary(u)? & (super::super::shared::WINDOW_SIZE - 1);
            relative_indices.push(index);
        }
        let absolute_indices = relative_indices
            .into_iter()
            .map(|ri| u128::from(ri) + window_start)
            .collect_vec()
            .try_into()
            .unwrap();
        Ok(Self::new(absolute_indices))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    impl AbsoluteIndexSet {
        /// Test-function used for negative tests of removal records
        pub(crate) fn increment_bloom_filter_index(&mut self, index: usize) {
            let mut as_array = self.to_array();
            as_array[index] = as_array[index].wrapping_add(1);
            *self = Self::new(as_array)
        }

        /// Test-function used for negative tests of removal records
        pub(crate) fn decrement_bloom_filter_index(&mut self, index: usize) {
            let mut as_array = self.to_array();
            as_array[index] = as_array[index].wrapping_sub(1);
            *self = Self::new(as_array)
        }

        pub(crate) fn set_minimum(&mut self, new_minimum: u128) {
            self.minimum = new_minimum;
        }

        pub(crate) fn get_minimum(&self) -> u128 {
            self.minimum
        }

        pub(crate) fn set_distance(&mut self, index: usize, new_distance: u32) {
            self.distances[index] = new_distance;
        }

        pub(crate) fn new_raw(minimum: u128, distances: [u32; NUM_TRIALS as usize]) -> Self {
            Self { minimum, distances }
        }
    }

    #[proptest]
    fn to_array_followed_by_new_is_identity(#[strategy(arb())] ais: AbsoluteIndexSet) {
        let as_array = ais.to_array();
        let as_ais_again = AbsoluteIndexSet::new(as_array);
        prop_assert_eq!(ais, as_ais_again);

        let as_array_again = as_ais_again.to_array();
        prop_assert_eq!(as_array_again, as_array);
    }
}
