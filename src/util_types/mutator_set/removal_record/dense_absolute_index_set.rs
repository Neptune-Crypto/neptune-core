use itertools::Itertools;
use thiserror::Error;

use super::super::shared::NUM_TRIALS;
use super::AbsoluteIndexSet;

/// Dense representation of an absolute index set. This structure is only
/// intended as an internal representation to a packing algorithm. So it should
/// not be exposed.
///
/// In fact, this data structure is deprecated and included only as reference
/// material. It might be used in the future. We will probably kill it, but who
/// knows?
///
/// This struct is useful for *packing* (and *unpacking*), which could result in
/// noticeable space savings. However, such packing complicates the permutation
/// check in the `Merge` branch of the `SingleProof` consensus program.
/// Specifically, that `Merge` branch would need to perform the unpacking, check
/// the permutation, and then pack the result -- all in tasm.
#[deprecated]
#[derive(Debug, Clone, Copy)]
pub(super) struct DenseAbsoluteIndexSet {
    /// At most 74 bits, because
    ///  - AOCL index is at most 64
    ///  - [super::BATCH_SIZE] is 3 (divided)
    ///  - [super::CHUNK_SIZE] is 12 (multiplied)
    ///  - [super::WINDOW_SIZE] is 20 (added not multiplied)
    offset: u128,

    /// At most 6 bits, because
    ///  - [super::NUM_TRIALS] is <6
    index_of_zero: usize,

    /// At most 20 bits each, because
    ///  - [super::WINDOW_SIZE] is 20
    relative_indices: [u32; (NUM_TRIALS as usize) - 1],
}

#[derive(Debug, Clone, Copy, Error)]
pub(super) enum AbsoluteIndexSetUnpackError {
    #[error("index of zero out of bounds; must be in [0;{NUM_TRIALS})")]
    IndexOfZeroTooLarge,
}

impl DenseAbsoluteIndexSet {
    pub(super) fn encode_as_u64_array(&self) -> [u64; 16] {
        let mut array = vec![];

        // 1. top 60 bits from offset
        array.push(u64::try_from(self.offset >> 14).expect("offset is at most 74 bits"));
        let mut remainder =
            u64::try_from(self.offset & ((1 << 14) - 1)).expect("14 bits fit in u64");
        let mut width = 14;

        // 2. 6 bits from index-of-zero
        remainder = (remainder << 6)
            | u64::try_from(self.index_of_zero).expect("index-of-zero has at most 6 bits");
        width += 6;

        // 3. 20 bits each from first two relative indices
        remainder = (remainder << 20) | u64::from(self.relative_indices[0]);
        width += 20;
        remainder = (remainder << 20) | u64::from(self.relative_indices[1]);
        width += 20;

        // 4. flush
        debug_assert_eq!(60, width);
        array.push(remainder);

        // 5. chunk remaining indices into goups of 3 and concatenate
        for chunk in self.relative_indices[2..].chunks(3) {
            let [a, b, c] = chunk.try_into().unwrap();
            array.push((u64::from(a) << 40) | (u64::from(b) << 20) | u64::from(c))
        }

        // clean division because ( 45 - 1 - 2 ) % 3 == 0
        //            NUM_TRIALS ----'   |   |     |
        //            offset ------------'   |     |
        //            step 3 ----------------'     |
        //            chunk size ------------------'
        // So there are no remaining bits or incomplete chunks.

        array.try_into().expect("pushed exactly 16 elements")
    }

    pub(super) fn encode_as_u128_array(&self) -> [u128; 8] {
        self.encode_as_u64_array()
            .chunks(2)
            .map(|chunk| (u128::from(chunk[0]) << 64) + u128::from(chunk[1]))
            .collect_vec()
            .try_into()
            .unwrap()
    }

    pub(super) fn decode_from_u64_array(
        array: [u64; 16],
    ) -> Result<Self, AbsoluteIndexSetUnpackError> {
        let mut elements = array.into_iter();

        // 1. top 60 bits of offset
        let mut offset = u128::from(elements.next().unwrap()) << 14;

        // 2. remaining 14 bits for offset ...
        let second_element = elements.next().unwrap();
        offset |= u128::from(second_element >> 46);

        // 3. next 6 bits are for index-of-zero
        let index_of_zero = usize::try_from((second_element >> 40) & ((1 << 6) - 1)).unwrap();
        if index_of_zero >= usize::try_from(NUM_TRIALS).unwrap() {
            return Err(AbsoluteIndexSetUnpackError::IndexOfZeroTooLarge);
        }

        // 4. next two chunks of 20 bits are relative indices
        let mut relative_indices = vec![];
        relative_indices.push(u32::try_from((second_element >> 20) & ((1 << 20) - 1)).unwrap());
        relative_indices.push(u32::try_from(second_element & ((1 << 20) - 1)).unwrap());

        // 5. all subsequent elements are triples of relative indices
        for _ in 0..14 {
            let element = elements.next().unwrap();
            relative_indices.push(u32::try_from((element >> 40) & ((1 << 20) - 1)).unwrap());
            relative_indices.push(u32::try_from((element >> 20) & ((1 << 20) - 1)).unwrap());
            relative_indices.push(u32::try_from(element & ((1 << 20) - 1)).unwrap());
        }

        Ok(Self {
            offset,
            index_of_zero,
            relative_indices: relative_indices
                .try_into()
                .expect("pushed exactly 44 times"),
        })
    }

    pub(crate) fn decode_from_u128_array(
        array: [u128; 8],
    ) -> Result<Self, AbsoluteIndexSetUnpackError> {
        Self::decode_from_u64_array(
            array
                .into_iter()
                .flat_map(|u| {
                    [
                        u64::try_from(u >> 64).unwrap(),
                        u64::try_from(u & u128::from(u64::MAX)).unwrap(),
                    ]
                })
                .collect_vec()
                .try_into()
                .unwrap(),
        )
    }

    /// Convert an [`AbsoluteIndexSet`] to [`DenseAbsoluteIndexSet`] without
    /// losing information.
    pub(super) fn convert_from_regular(ais: AbsoluteIndexSet) -> Self {
        let index_of_zero = ais.to_array().into_iter().position_min().unwrap();
        let offset = ais.to_array()[index_of_zero];

        let mut relative_indices = vec![];
        for (i, absolute_index) in ais.to_array().into_iter().enumerate() {
            if i == index_of_zero {
                continue;
            }

            // This is the only place this conversion can fail. All other
            // unwraps are safe.
            // BUT: We trust the input. So it is okay.
            let packed_index = u32::try_from(absolute_index - offset).expect(
                "all indices from one index set must live in a window at \
                most 2^20 wide",
            );
            assert!(
                packed_index < (1 << 20),
                "calculated relative index must fit within 20 bits"
            );
            relative_indices.push(packed_index);
        }

        let relative_indices = relative_indices.try_into().unwrap();
        Self {
            offset,
            index_of_zero,
            relative_indices,
        }
    }

    /// Inverse of [`Self::convert_from`].
    pub(super) fn convert_to_regular(self) -> AbsoluteIndexSet {
        let absolute_indices = (0_usize..(NUM_TRIALS as usize))
            .map(|i| {
                if i < self.index_of_zero {
                    self.offset + u128::from(self.relative_indices[i])
                } else if i == self.index_of_zero {
                    self.offset
                } else {
                    self.offset + u128::from(self.relative_indices[i - 1])
                }
            })
            .collect_vec()
            .try_into()
            .unwrap();
        AbsoluteIndexSet::new(&absolute_indices)
    }

    pub(super) fn pack(absolute_index_sets: Vec<AbsoluteIndexSet>) -> Vec<AbsoluteIndexSet> {
        absolute_index_sets
            .into_iter()
            .map(DenseAbsoluteIndexSet::convert_from_regular)
            .map(|dais| dais.encode_as_u128_array())
            .collect_vec()
            .chunks(5)
            .map(|chunk| {
                AbsoluteIndexSet::new(
                    &chunk
                        .iter()
                        .copied()
                        .flatten()
                        .pad_using(NUM_TRIALS as usize, |_| 0_u128)
                        .collect_vec()
                        .try_into()
                        .unwrap(),
                )
            })
            .collect_vec()
    }

    pub(super) fn try_unpack(
        packed_absolute_index_sets: Vec<AbsoluteIndexSet>,
    ) -> Result<Vec<AbsoluteIndexSet>, AbsoluteIndexSetUnpackError> {
        let mut absolute_index_sets = vec![];
        for chunk in packed_absolute_index_sets.into_iter().flat_map(|ais| {
            ais.to_vec()
                .into_iter()
                .take(40)
                .collect_vec()
                .chunks(8)
                .map(|chunk| chunk.to_vec())
                .collect_vec()
        }) {
            let dais = DenseAbsoluteIndexSet::decode_from_u128_array(chunk.try_into().unwrap())?;
            let ais = dais.convert_to_regular();
            if ais.to_vec().into_iter().all(|ai| ai == 0) {
                continue;
            }
            absolute_index_sets.push(ais);
        }
        Ok(absolute_index_sets)
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn convert_arbitrary_dense_absolute_index_set(
        #[strategy(arb::<AbsoluteIndexSet>())] ais: AbsoluteIndexSet,
    ) {
        let dais = DenseAbsoluteIndexSet::convert_from_regular(ais);
        let ais_again = DenseAbsoluteIndexSet::convert_to_regular(dais);
        prop_assert_eq!(ais, ais_again);
    }

    #[proptest]
    fn encode_arbitrary_dense_absolute_index_set_as_u64s(
        #[strategy(arb::<AbsoluteIndexSet>())] ais: AbsoluteIndexSet,
    ) {
        let dais = DenseAbsoluteIndexSet::convert_from_regular(ais);
        let u64s = dais.encode_as_u64_array();
        let dais_again = DenseAbsoluteIndexSet::decode_from_u64_array(u64s).unwrap();
        let ais_again = DenseAbsoluteIndexSet::convert_to_regular(dais_again);
        prop_assert_eq!(ais, ais_again);
    }

    #[proptest]
    fn pack_unpack_happy(
        #[strategy(vec(arb::<AbsoluteIndexSet>(), 0..10))] absolute_index_sets: Vec<
            AbsoluteIndexSet,
        >,
    ) {
        let packed = DenseAbsoluteIndexSet::pack(absolute_index_sets.clone());
        let unpacked = DenseAbsoluteIndexSet::try_unpack(packed).unwrap();
        prop_assert_eq!(absolute_index_sets, unpacked);
    }

    #[proptest]
    fn unpack_cannot_crash(
        #[strategy(vec(arb::<AbsoluteIndexSet>(), 0..10))] absolute_index_sets: Vec<
            AbsoluteIndexSet,
        >,
    ) {
        let _ = DenseAbsoluteIndexSet::try_unpack(absolute_index_sets); // no crash
    }
}
