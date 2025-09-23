use get_size2::GetSize;
use itertools::Itertools;
use num_traits::CheckedSub;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::block_appendix::BlockAppendix;
use super::block_body::BlockBody;
use super::block_header::BlockHeader;
use crate::api::export::AdditionRecord;
use crate::api::export::Timestamp;
use crate::api::export::Utxo;
use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
use crate::protocol::proof_abstractions::mast_hash::HasDiscriminant;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::util_types::mutator_set::commit;

/// The kernel of a block contains all data that is not proof data
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct BlockKernel {
    pub header: BlockHeader,
    pub body: BlockBody,

    pub(crate) appendix: BlockAppendix,
}

impl BlockKernel {
    pub(crate) fn new(header: BlockHeader, body: BlockBody, appendix: BlockAppendix) -> Self {
        Self {
            header,
            body,
            appendix,
        }
    }

    /// Get the block's guesser fee UTXOs.
    ///
    /// The amounts in the UTXOs are taken from the transaction fee.
    ///
    /// The genesis block does not have a guesser reward.
    pub fn guesser_fee_utxos(&self) -> Result<Vec<Utxo>, BlockValidationError> {
        const MINER_REWARD_TIME_LOCK_PERIOD: Timestamp = Timestamp::years(3);

        if self.header.height.is_genesis() {
            return Ok(vec![]);
        }

        let total_guesser_reward = self.body.total_guesser_reward()?;
        let mut value_timelocked = total_guesser_reward;
        value_timelocked.div_two();
        let value_unlocked = total_guesser_reward.checked_sub(&value_timelocked).unwrap();

        let coins_unlocked = value_unlocked.to_native_coins();
        let coins_timelocked = value_timelocked.to_native_coins();
        let lock_script_hash = self.header.guesser_receiver_data.lock_script_hash;
        let unlocked_utxo = Utxo::new(lock_script_hash, coins_unlocked);
        let locked_utxo = Utxo::new(lock_script_hash, coins_timelocked)
            .with_time_lock(self.header.timestamp + MINER_REWARD_TIME_LOCK_PERIOD);

        Ok(vec![locked_utxo, unlocked_utxo])
    }

    /// Compute the addition records that correspond to the UTXOs generated for
    /// the block's guesser
    ///
    /// The genesis block does not have this addition record.
    pub(crate) fn guesser_fee_addition_records(
        &self,
        block_hash: Digest,
    ) -> Result<Vec<AdditionRecord>, BlockValidationError> {
        Ok(self
            .guesser_fee_utxos()?
            .into_iter()
            .map(|utxo| {
                let item = Tip5::hash(&utxo);

                // Adding the block hash to the mutator set here means that no
                // composer can start proving before solving the PoW-race;
                // production of future proofs is impossible as they depend on
                // inputs hidden behind the veil of future PoW.
                let sender_randomness = block_hash;
                let receiver_digest = self.header.guesser_receiver_data.receiver_digest;

                commit(item, sender_randomness, receiver_digest)
            })
            .collect_vec())
    }
}

#[derive(Debug, Copy, Clone, EnumCount)]
pub enum BlockKernelField {
    Header,
    Body,
    Appendix,
}

impl HasDiscriminant for BlockKernelField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl MastHash for BlockKernel {
    type FieldEnum = BlockKernelField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let sequences = vec![
            self.header.mast_hash().encode(),
            self.body.mast_hash().encode(),
            self.appendix.encode(),
        ];
        sequences
    }
}
