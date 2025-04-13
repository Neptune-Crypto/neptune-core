use std::collections::HashMap;
use std::marker::PhantomData;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Result;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Unstructured;
use get_size2::GetSize;
use itertools::Itertools;
use serde::de::SeqAccess;
use serde::de::Visitor;
use serde::ser::SerializeTuple;
use serde::Deserialize;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::util_types::mutator_set::shared::indices_to_hash_map;
#[cfg(any(test, feature = "arbitrary-impls"))]
use crate::util_types::mutator_set::shared::BATCH_SIZE;
#[cfg(any(test, feature = "arbitrary-impls"))]
use crate::util_types::mutator_set::shared::CHUNK_SIZE;

use super::super::mutator_set_accumulator::MutatorSetAccumulator;
use super::super::shared::NUM_TRIALS;
use super::dense_absolute_index_set::AbsoluteIndexSetUnpackError;
use super::dense_absolute_index_set::DenseAbsoluteIndexSet;
use super::MutatorSetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BFieldCodec, TasmObject, Hash)]
pub struct AbsoluteIndexSet(pub(super) [u128; NUM_TRIALS as usize]);

impl GetSize for AbsoluteIndexSet {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        self.0.get_heap_size()
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl AbsoluteIndexSet {
    pub fn new(indices: &[u128; NUM_TRIALS as usize]) -> Self {
        Self(*indices)
    }

    pub fn sort_unstable(&mut self) {
        self.0.sort_unstable();
    }

    pub fn to_vec(self) -> Vec<u128> {
        self.0.to_vec()
    }

    pub fn to_array(self) -> [u128; NUM_TRIALS as usize] {
        self.0
    }

    pub fn to_array_mut(&mut self) -> &mut [u128; NUM_TRIALS as usize] {
        &mut self.0
    }

    /// Split the [`AbsoluteIndexSet`] into two parts, one for chunks in the
    /// inactive part of the Bloom filter and another one for chunks in the
    /// active part of the Bloom filter.
    ///
    /// Returns an error if a removal index is a future value, i.e. one that's
    /// not yet covered by the active window.
    #[expect(clippy::type_complexity)]
    pub fn split_by_activity(
        &self,
        mutator_set: &MutatorSetAccumulator,
    ) -> Result<(HashMap<u64, Vec<u128>>, Vec<u128>), MutatorSetError> {
        let (aw_chunk_index_min, aw_chunk_index_max) = mutator_set.active_window_chunk_interval();
        let (inactive, active): (HashMap<_, _>, HashMap<_, _>) = indices_to_hash_map(&self.0)
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

impl serde::Serialize for AbsoluteIndexSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_tuple(NUM_TRIALS as usize)?;
        for b in self.0 {
            seq.serialize_element(&b)?;
        }
        seq.end()
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> Arbitrary<'a> for AbsoluteIndexSet {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let aocl_index = u64::arbitrary(u)?;
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
        Ok(Self(absolute_indices))
    }
}

/// ArrayVisitor
/// Used for deserializing large arrays, with size known at compile time.
/// Credit: MikailBag <https://github.com/serde-rs/serde/issues/1937>
struct ArrayVisitor<T, const N: usize>(PhantomData<T>);

impl<'de, T, const N: usize> Visitor<'de> for ArrayVisitor<T, N>
where
    T: Deserialize<'de>,
{
    type Value = [T; N];

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str(&format!("an array of length {}", N))
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        // can be optimized using MaybeUninit
        let mut data = Vec::with_capacity(N);
        for _ in 0..N {
            match (seq.next_element())? {
                Some(val) => data.push(val),
                None => return Err(serde::de::Error::invalid_length(N, &self)),
            }
        }
        match data.try_into() {
            Ok(arr) => Ok(arr),
            Err(_) => unreachable!(),
        }
    }
}

impl<'de> Deserialize<'de> for AbsoluteIndexSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(AbsoluteIndexSet::new(&deserializer.deserialize_tuple(
            NUM_TRIALS as usize,
            ArrayVisitor::<u128, { NUM_TRIALS as usize }>(PhantomData),
        )?))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    use super::*;

    impl AbsoluteIndexSet {
        /// Test-function used for negative tests of removal records
        pub(crate) fn increment_bloom_filter_index(&mut self, index: usize) {
            self.0[index] = self.0[index].wrapping_add(1);
        }

        /// Test-function used for negative tests of removal records
        pub(crate) fn decrement_bloom_filter_index(&mut self, index: usize) {
            self.0[index] = self.0[index].wrapping_sub(1);
        }

        pub(crate) fn set_bloom_filter_index(&mut self, index: usize, value: u128) {
            self.0[index] = value;
        }
    }
}
