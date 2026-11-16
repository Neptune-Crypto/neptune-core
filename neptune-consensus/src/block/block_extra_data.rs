use get_size2::GetSize;
use itertools::Itertools;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::chunk::Chunk;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordListUnpackError;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_mutator_set::removal_record::RemovalRecordValidityError;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::Mmr;
use thiserror::Error;

use crate::consensus_rule_set::ConsensusRuleSet;

/// The chunk data of a block's inputs, which the block's transaction kernel
/// does not carry from [`ConsensusRuleSet::HardforkZeta`] on.
///
/// Stored and propagated next to the block. Together with the absolute index
/// sets from the kernel and the mutator set the kernel is valid against, it
/// rebuilds the full removal records. Deduplicated across inputs and
/// canonical: one authentication structure per SWBFI tree, smallest tree
/// first, and the packed chunks in ascending chunk index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockExtraData {
    authentication_structures: Vec<Vec<Digest>>,
    chunks: Vec<Chunk>,
}

#[derive(Debug, Error)]
pub enum BlockExtraDataError {
    #[error("cannot rebuild removal records: {0}")]
    Unpack(#[from] RemovalRecordListUnpackError),

    #[error("rebuilt removal record {index} is invalid: {error:?}")]
    InvalidRemovalRecord {
        index: usize,
        error: RemovalRecordValidityError,
    },
}

impl BlockExtraData {
    /// Extract the chunk data from full (not packed) removal records that are
    /// synced to `mutator_set`.
    ///
    /// # Panics
    ///
    ///  - May panic if the removal records are invalid or mutually
    ///    inconsistent.
    pub fn new(
        removal_records: Vec<RemovalRecord>,
        mutator_set: &MutatorSetAccumulator,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Self {
        let (_index_sets, authentication_structures, chunks) = RemovalRecordList::deconstruct(
            removal_records,
            mutator_set.swbf_inactive.num_leafs(),
            consensus_rule_set.allow_big_chunks(),
        );

        Self {
            authentication_structures,
            chunks,
        }
    }

    /// Rebuild the full removal records from the inputs of a block's
    /// transaction kernel and verify them against `mutator_set`, the mutator
    /// set the kernel is valid against.
    ///
    /// Never panics, so this function is safe to run on untrusted extra data.
    pub fn try_rebuild(
        &self,
        inputs: &[RemovalRecord],
        mutator_set: &MutatorSetAccumulator,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Vec<RemovalRecord>, BlockExtraDataError> {
        let index_sets = inputs.iter().map(|rr| rr.absolute_indices).collect_vec();
        let removal_records = RemovalRecordList::try_construct(
            index_sets,
            self.authentication_structures.clone(),
            &self.chunks,
            mutator_set.swbf_inactive.num_leafs(),
            consensus_rule_set.allow_big_chunks(),
        )?;

        for (index, removal_record) in removal_records.iter().enumerate() {
            removal_record
                .validate_inner(mutator_set)
                .map_err(|error| BlockExtraDataError::InvalidRemovalRecord { index, error })?;
        }

        Ok(removal_records)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    const CONSENSUS_RULE_SET: ConsensusRuleSet = ConsensusRuleSet::HardforkZeta;

    fn stripped(removal_records: &[RemovalRecord]) -> Vec<RemovalRecord> {
        removal_records
            .iter()
            .map(|rr| RemovalRecord {
                absolute_indices: rr.absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            })
            .collect_vec()
    }

    #[proptest(cases = 20)]
    fn rebuild_recovers_removal_records(
        #[strategy(0usize..20)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=(u64::from(u16::MAX)))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let msa = &msa_and_records.mutator_set_accumulator;
        let removal_records = msa_and_records.unpacked_removal_records();
        let extra_data = BlockExtraData::new(removal_records.clone(), msa, CONSENSUS_RULE_SET);

        let rebuilt = extra_data
            .try_rebuild(&stripped(&removal_records), msa, CONSENSUS_RULE_SET)
            .unwrap();
        prop_assert_eq!(removal_records, rebuilt);
    }

    #[proptest(cases = 20)]
    fn rebuild_rejects_tampered_chunk(
        #[strategy(1usize..20)] _num_removals: usize,
        #[strategy((u64::from(u16::MAX) / 2)..=(u64::from(u16::MAX)))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let msa = &msa_and_records.mutator_set_accumulator;
        let removal_records = msa_and_records.unpacked_removal_records();
        let mut extra_data = BlockExtraData::new(removal_records.clone(), msa, CONSENSUS_RULE_SET);
        let Some(chunk) = extra_data.chunks.first_mut() else {
            return Ok(());
        };
        *chunk = Chunk::empty_chunk().pack(CONSENSUS_RULE_SET.allow_big_chunks());
        if extra_data.chunks[0]
            == BlockExtraData::new(removal_records.clone(), msa, CONSENSUS_RULE_SET).chunks[0]
        {
            return Ok(());
        }

        prop_assert!(extra_data
            .try_rebuild(&stripped(&removal_records), msa, CONSENSUS_RULE_SET)
            .is_err());
    }
}
