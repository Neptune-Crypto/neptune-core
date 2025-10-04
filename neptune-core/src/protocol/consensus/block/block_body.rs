use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::prelude::TasmObject;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::Digest;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::MerkleTree;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::api::export::AdditionRecord;
use crate::api::export::NativeCurrencyAmount;
use crate::prelude::twenty_first;
use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::proof_abstractions::mast_hash::HasDiscriminant;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockBodyField {
    TransactionKernel,
    MutatorSetAccumulator,
    LockFreeMmrAccumulator,
    BlockMmrAccumulator,
}

impl HasDiscriminant for BlockBodyField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

/// Public fields of `BlockBody` are read-only, enforced by #[readonly::make].
/// Modifications are possible only through `BlockBody` methods.
///
// ## About the private `mast_hash` field:
//
// The `mast_hash` field represents the `BlockBody` MAST hash.  It is an
// optimization so that the hash can be lazily computed at most once (per
// modification). Without it, the PoW hash rate depends on the number of inputs
// and outputs in a transaction. This caching of a hash value is similar to that
// of `Block`.
//
// The field must be reset whenever the block body is modified.  As such, we
// should not permit direct modification of internal fields.
//
// Therefore `[readonly::make]` is used to make public `BlockBody` fields read-
// only (not mutable) outside of this module.  All methods that modify BlockBody
// must reset this field.
//
// We manually implement `PartialEq` and `Eq` so that digest field will not be
// compared.  Otherwise, we could have identical blocks except one has
// initialized digest field and the other has not.
//
// The field should not be serialized, so it has the `#[serde(skip)]` attribute.
// Upon deserialization, the field will have Digest::default() which is desired
// so that the digest will be recomputed if/when hash() is called.
//
// We likewise skip the field for `BFieldCodec`, and `GetSize` because there
// exist no impls for `OnceLock<_>` so derive fails.
#[derive(Clone, Debug, Serialize, Deserialize, BFieldCodec, GetSize, TasmObject)]
pub struct BlockBody {
    /// Every block contains exactly one transaction, which represents the merger of all
    /// broadcasted transactions that the miner decided to confirm. The inputs
    /// to this transaction kernel must be packed if the consensus rule dictate
    /// that.
    pub transaction_kernel: TransactionKernel,

    /// The mutator set accumulator represents the UTXO set. It is simultaneously an
    /// accumulator (=> compact representation and membership proofs) and an anonymity
    /// construction (=> outputs from one transaction do not look like inputs to another).
    ///
    /// This field represents the state of the MS *after* applying the update
    /// induced by the transaction, but *before* applying the update induced by
    /// guesser fees (and perhaps later composer fees).
    ///
    /// For the final post-block state, refer to
    /// [`Self::mutator_set_accumulator_after`].
    pub(super) mutator_set_accumulator: MutatorSetAccumulator,

    /// Lock-free UTXOs do not come with lock scripts and do not live in the mutator set.
    pub lock_free_mmr_accumulator: MmrAccumulator,

    /// All blocks live in an MMR, so that we can efficiently prove that a given block
    /// lives on the line between the tip and genesis. This MMRA does not contain the
    /// current block.
    pub block_mmr_accumulator: MmrAccumulator,

    // This caching ensures that the hash rate is independent of the size of
    // the block's transaction.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[get_size(ignore)]
    #[tasm_object(ignore)]
    merkle_tree: OnceLock<MerkleTree>,
}

impl PartialEq for BlockBody {
    fn eq(&self, other: &Self) -> bool {
        self.mast_hash() == other.mast_hash()
    }
}
impl Eq for BlockBody {}

impl BlockBody {
    /// Caller must pack the removal records if required.
    pub(crate) fn new(
        transaction_kernel: TransactionKernel,
        mutator_set_accumulator: MutatorSetAccumulator,
        lock_free_mmr_accumulator: MmrAccumulator,
        block_mmr_accumulator: MmrAccumulator,
    ) -> Self {
        Self {
            transaction_kernel,
            mutator_set_accumulator,
            lock_free_mmr_accumulator,
            block_mmr_accumulator,
            merkle_tree: OnceLock::default(), // calc'd in merkle_tree()
        }
    }

    /// The kernel of the transaction contained in the block.
    pub fn transaction_kernel(&self) -> &TransactionKernel {
        &self.transaction_kernel
    }

    /// Return the mutator set as it looks after the application of this block.
    ///
    /// Includes the guesser-fee UTXOs which are not included by the
    /// `mutator_set_accumulator` field on the block body.
    pub(crate) fn mutator_set_accumulator_after(
        &self,
        guesser_fee_addition_records: Vec<AdditionRecord>,
    ) -> MutatorSetAccumulator {
        let mutator_set_update = MutatorSetUpdate::new(vec![], guesser_fee_addition_records);
        let mut msa = self.mutator_set_accumulator.clone();
        mutator_set_update.apply_to_accumulator(&mut msa).expect("mutator set update derived from guesser fees should be applicable to mutator set accumulator contained in body");

        msa
    }

    /// Return the mutator set as it looks after the application of the
    /// transaction in this block but before the guesser-fee UTXOs are applied.
    ///
    /// The returned mutator set accumulator is the same as the field
    /// [`Self::mutator_set_accumulator`].
    pub(crate) fn mutator_set_accumulator_without_guesser_fees(&self) -> MutatorSetAccumulator {
        self.mutator_set_accumulator.clone()
    }

    /// The amount rewarded to the guesser who finds a valid nonce for this
    /// block.
    pub(crate) fn total_guesser_reward(
        &self,
    ) -> Result<NativeCurrencyAmount, BlockValidationError> {
        let r = self.transaction_kernel.fee;
        if r.is_negative() {
            Err(BlockValidationError::NegativeFee)
        } else {
            Ok(r)
        }
    }
}

impl MastHash for BlockBody {
    type FieldEnum = BlockBodyField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        vec![
            self.transaction_kernel.mast_hash().encode(),
            self.mutator_set_accumulator.encode(),
            self.lock_free_mmr_accumulator.encode(),
            self.block_mmr_accumulator.encode(),
        ]
    }

    fn merkle_tree(&self) -> MerkleTree {
        self.merkle_tree
            .get_or_init(|| {
                let mut digests = self
                    .mast_sequences()
                    .iter()
                    .map(|seq| Tip5::hash_varlen(seq))
                    .collect_vec();

                // pad until length is a power of two
                while digests.len() & (digests.len() - 1) != 0 {
                    digests.push(Digest::default());
                }

                twenty_first::prelude::MerkleTree::par_new(&digests).unwrap()
            })
            .clone()
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> arbitrary::Arbitrary<'a> for BlockBody {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            transaction_kernel: u.arbitrary()?,
            mutator_set_accumulator: u.arbitrary()?,
            lock_free_mmr_accumulator: u.arbitrary()?,
            block_mmr_accumulator: u.arbitrary()?,
            merkle_tree: OnceLock::new(), // always empty in fuzzing
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prelude::BoxedStrategy;
    use proptest::strategy::Strategy;
    use proptest_arbitrary_interop::arb;

    use super::*;
    use crate::api::export::NativeCurrencyAmount;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;

    impl BlockBody {
        pub(crate) fn arbitrary_with_mutator_set_accumulator(
            mutator_set_accumulator: MutatorSetAccumulator,
        ) -> BoxedStrategy<BlockBody> {
            (NativeCurrencyAmount::arbitrary_non_negative())
                .prop_flat_map(move |fee| {
                    let transaction_kernel_strategy = TransactionKernel::strategy_with_fee(fee);
                    let lock_free_mmr_accumulator_strategy = arb::<MmrAccumulator>();
                    let block_mmr_accumulator_strategy = arb::<MmrAccumulator>();
                    let mutator_set_accumulator = mutator_set_accumulator.clone();
                    (
                        transaction_kernel_strategy,
                        lock_free_mmr_accumulator_strategy,
                        block_mmr_accumulator_strategy,
                    )
                        .prop_map(
                            move |(
                                transaction_kernel,
                                lock_free_mmr_accumulator,
                                block_mmr_accumulator,
                            )| {
                                let inputs =
                                    RemovalRecordList::pack(transaction_kernel.inputs.clone());
                                let transaction_kernel = TransactionKernelModifier::default()
                                    .inputs(inputs)
                                    .modify(transaction_kernel);
                                BlockBody {
                                    transaction_kernel,
                                    mutator_set_accumulator: mutator_set_accumulator.clone(),
                                    lock_free_mmr_accumulator,
                                    block_mmr_accumulator,
                                    merkle_tree: OnceLock::default(),
                                }
                            },
                        )
                })
                .boxed()
        }
    }
}
