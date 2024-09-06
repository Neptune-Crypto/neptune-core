use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::prelude::twenty_first;

pub mod lock_script;
pub mod primitive_witness;
pub mod transaction_kernel;
pub mod utxo;
pub mod validity;

use anyhow::{bail, Result};
use arbitrary::Arbitrary;
use get_size::GetSize;
use itertools::Itertools;
use num_bigint::BigInt;
use num_rational::BigRational;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use tasm_lib::prelude::TasmObject;
use tasm_lib::Digest;
use tracing::error;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use validity::proof_collection::ProofCollection;

use self::primitive_witness::PrimitiveWitness;
use self::transaction_kernel::TransactionKernel;
use super::block::Block;
use super::shared::Hash;
use crate::triton_vm::proof::Claim;
use crate::triton_vm::proof::Proof;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    GetSize,
    BFieldCodec,
    Default,
    TasmObject,
    Arbitrary,
)]
pub struct PublicAnnouncement {
    pub message: Vec<BFieldElement>,
}

impl PublicAnnouncement {
    pub fn new(message: Vec<BFieldElement>) -> Self {
        Self { message }
    }
}

const NUM_TX_SUBPROGRAMS: usize = 6;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, Default)]
pub enum TransactionProof {
    #[default]
    Invalid,
    Witness(PrimitiveWitness),
    SingleProof(Proof),
    ProofCollection(ProofCollection),
    MultiClaimProof(([Claim; NUM_TX_SUBPROGRAMS], Proof)),
}

impl TransactionProof {
    pub async fn verify(&self, kernel_mast_hash: Digest) -> bool {
        match self {
            TransactionProof::Invalid => false,
            TransactionProof::Witness(primitive_witness) => {
                primitive_witness.validate().await
                    && primitive_witness.kernel.mast_hash() == kernel_mast_hash
            }
            TransactionProof::SingleProof(_) => todo!(),
            TransactionProof::ProofCollection(proof_collection) => {
                proof_collection.verify(kernel_mast_hash)
            }
            TransactionProof::MultiClaimProof(_) => todo!(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum TransactionProofError {
    CannotUpdateProofVariant,
    CannotUpdatePrimitiveWitness,
    CannotUpdateSingleProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct Transaction {
    pub kernel: TransactionKernel,

    #[bfield_codec(ignore)]
    pub proof: TransactionProof,
}

/// Make `Transaction` hashable with `StdHash` for using it in `HashMap`.
///
/// The Clippy warning is safe to suppress, because we do not violate the invariant: k1 == k2 => hash(k1) == hash(k2).
#[allow(clippy::derived_hash_with_manual_eq)]
impl StdHash for Transaction {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let neptune_hash = Hash::hash(self);
        StdHash::hash(&neptune_hash, state);
    }
}

impl Transaction {
    /// Create a new `Transaction` from a `PrimitiveWitness` (which defines an old
    /// `Transaction`) by updating the mutator set records according to a new
    /// `Block`.
    fn new_with_updated_mutator_set_records_given_primitive_witness(
        old_primitive_witness: &PrimitiveWitness,
        block: &Block,
    ) -> Result<Transaction> {
        let mut msa_state: MutatorSetAccumulator =
            old_primitive_witness.mutator_set_accumulator.clone();
        let block_addition_records: Vec<AdditionRecord> =
            block.kernel.body.transaction_kernel.outputs.clone();
        let mut transaction_removal_records: Vec<RemovalRecord> =
            old_primitive_witness.kernel.inputs.clone();
        let mut transaction_removal_records: Vec<&mut RemovalRecord> =
            transaction_removal_records.iter_mut().collect();
        let mut block_removal_records = block.kernel.body.transaction_kernel.inputs.clone();
        block_removal_records.reverse();
        let mut block_removal_records: Vec<&mut RemovalRecord> =
            block_removal_records.iter_mut().collect::<Vec<_>>();
        let mut primitive_witness = old_primitive_witness.clone();

        // Apply all addition records in the block
        for block_addition_record in block_addition_records {
            // Batch update block's removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(&mut block_removal_records, &msa_state);

            // Batch update transaction's removal records
            RemovalRecord::batch_update_from_addition(&mut transaction_removal_records, &msa_state);

            // Batch update primitive witness membership proofs
            let membership_proofs = &mut primitive_witness
                .input_membership_proofs
                .iter_mut()
                .collect_vec();
            let own_items = primitive_witness
                .input_utxos
                .utxos
                .iter()
                .map(Hash::hash)
                .collect_vec();
            MsMembershipProof::batch_update_from_addition(
                membership_proofs,
                &own_items,
                &msa_state,
                &block_addition_record,
            )
            .expect("MS MP update from add must succeed in wallet handler");

            msa_state.add(&block_addition_record);
        }

        while let Some(removal_record) = block_removal_records.pop() {
            // Batch update block's removal records to keep them valid after next removal
            RemovalRecord::batch_update_from_remove(&mut block_removal_records, removal_record);

            // batch update transaction's removal records
            // Batch update block's removal records to keep them valid after next removal
            RemovalRecord::batch_update_from_remove(
                &mut transaction_removal_records,
                removal_record,
            );

            // Batch update primitive witness membership proofs
            let membership_proofs = &mut primitive_witness
                .input_membership_proofs
                .iter_mut()
                .collect_vec();
            if let Err(e) =
                MsMembershipProof::batch_update_from_remove(membership_proofs, removal_record)
            {
                bail!("`MsMembershipProof::batch_update_from_remove` must work when updating mutator set records on transaction. Got error: {}", e);
            }

            msa_state.remove(removal_record);
        }

        // Sanity check of block validity
        let block_msa_hash = block.kernel.body.mutator_set_accumulator.clone().hash();
        assert_eq!(
            msa_state.hash(),
            block_msa_hash,
            "Internal MSA state must match that from block"
        );

        let kernel = primitive_witness.kernel.clone();
        let witness = TransactionProof::Witness(primitive_witness);
        Ok(Transaction {
            kernel,
            proof: witness,
        })
    }

    /// Create a new `Transaction` by updating the given one with the mutator set
    /// update contained in the `Block`. No primitive witness is present, instead
    /// a proof (or faith witness) is given. So:
    ///  1. Verify the proof
    ///  2. Update the records
    ///  3. Prove correctness of 1 and 2
    ///  4. Use resulting proof as new witness.
    fn new_with_updated_mutator_set_records_given_proof(
        old_transaction: &Transaction,
        previous_mutator_set_accumulator: &MutatorSetAccumulator,
        block: &Block,
    ) -> Result<Transaction> {
        let block_addition_records = block.kernel.body.transaction_kernel.outputs.clone();
        let block_removal_records = block.kernel.body.transaction_kernel.inputs.clone();
        let mutator_set_update =
            MutatorSetUpdate::new(block_removal_records, block_addition_records);

        // apply mutator set update to get new mutator set accumulator
        let mut new_mutator_set_accumulator = previous_mutator_set_accumulator.clone();
        let mut new_inputs = old_transaction.kernel.inputs.clone();
        mutator_set_update
            .apply_to_accumulator_and_records(
                &mut new_mutator_set_accumulator,
                &mut new_inputs.iter_mut().collect_vec(),
            )
            .unwrap_or_else(|_| panic!("Could not apply mutator set update."));

        // Sanity check of block validity
        let msa_hash = new_mutator_set_accumulator.hash();
        assert_eq!(
            block.kernel.body.mutator_set_accumulator.hash(),
            msa_hash,
            "Internal MSA state must match that from block"
        );

        // compute new kernel
        let mut new_kernel = old_transaction.kernel.clone();
        new_kernel.inputs = new_inputs;
        new_kernel.mutator_set_hash = msa_hash;

        // compute updated proof through recursion
        let update_proof = todo!();

        Ok(Transaction {
            kernel: new_kernel,
            proof: TransactionProof::SingleProof(update_proof),
        })
    }

    /// Update mutator set data in a transaction to update its
    /// compatibility with a new block. Note that for Proof witnesses, this will
    /// invalidate the proof, requiring an update.
    pub fn new_with_updated_mutator_set_records(
        &self,
        previous_mutator_set_accumulator: &MutatorSetAccumulator,
        block: &Block,
    ) -> Result<Transaction, TransactionProofError> {
        match &self.proof {
            TransactionProof::Witness(primitive_witness) => {
                Self::new_with_updated_mutator_set_records_given_primitive_witness(
                    primitive_witness,
                    block,
                )
                .map_err(|_| TransactionProofError::CannotUpdatePrimitiveWitness)
            }
            TransactionProof::SingleProof(proof) => {
                Self::new_with_updated_mutator_set_records_given_proof(
                    self,
                    previous_mutator_set_accumulator,
                    block,
                )
                .map_err(|_| TransactionProofError::CannotUpdateSingleProof)
            }
            _ => Err(TransactionProofError::CannotUpdateProofVariant),
        }
    }

    /// Determine whether the transaction is valid (forget about confirmable).
    /// This method tests the transaction's internal consistency in isolation,
    /// without the context of the canonical chain.
    pub async fn is_valid(&self) -> bool {
        let kernel_hash = self.kernel.mast_hash();
        self.proof.verify(kernel_hash).await
    }

    fn merge_primitive_witnesses(
        self_witness: PrimitiveWitness,
        other_witness: PrimitiveWitness,
        merged_kernel: &TransactionKernel,
    ) -> PrimitiveWitness {
        PrimitiveWitness {
            input_utxos: self_witness
                .input_utxos
                .cat(other_witness.input_utxos.clone()),
            lock_scripts_and_witnesses: [
                self_witness.lock_scripts_and_witnesses.clone(),
                other_witness.lock_scripts_and_witnesses.clone(),
            ]
            .concat(),
            type_scripts_and_witnesses: self_witness
                .type_scripts_and_witnesses
                .iter()
                .cloned()
                .chain(other_witness.type_scripts_and_witnesses.iter().cloned())
                .unique()
                .collect_vec(),
            input_membership_proofs: [
                self_witness.input_membership_proofs.clone(),
                other_witness.input_membership_proofs.clone(),
            ]
            .concat(),
            output_utxos: self_witness
                .output_utxos
                .cat(other_witness.output_utxos.clone()),
            output_sender_randomnesses: [
                self_witness.output_sender_randomnesses.clone(),
                other_witness.output_sender_randomnesses.clone(),
            ]
            .concat(),
            output_receiver_digests: [
                self_witness.output_receiver_digests.clone(),
                other_witness.output_receiver_digests.clone(),
            ]
            .concat(),
            mutator_set_accumulator: self_witness.mutator_set_accumulator.clone(),
            kernel: merged_kernel.clone(),
        }
    }

    /// Merge two transactions. Both input transactions must have a valid
    /// Proof witness for this operation to work. The mutator sets are
    /// assumed to be identical; this is the responsibility of the caller.
    pub fn merge_with(self, other: Transaction) -> Transaction {
        assert_eq!(
            self.kernel.mutator_set_hash, other.kernel.mutator_set_hash,
            "Mutator sets must be equal for transaction merger."
        );
        let timestamp = max(self.kernel.timestamp, other.kernel.timestamp);

        let merged_coinbase = match self.kernel.coinbase {
            Some(_) => match other.kernel.coinbase {
                Some(_) => {
                    error!("Cannot merge two transactions with non-empty coinbase fields.");
                    return self;
                }
                None => self.kernel.coinbase,
            },
            None => other.kernel.coinbase,
        };

        let merged_kernel = TransactionKernel {
            inputs: [self.kernel.inputs.clone(), other.kernel.inputs.clone()].concat(),
            outputs: [self.kernel.outputs.clone(), other.kernel.outputs.clone()].concat(),
            public_announcements: [
                self.kernel.public_announcements.clone(),
                other.kernel.public_announcements.clone(),
            ]
            .concat(),
            fee: self.kernel.fee + other.kernel.fee,
            coinbase: merged_coinbase,
            timestamp,
            mutator_set_hash: self.kernel.mutator_set_hash,
        };

        let merger_proof = todo!("transaction merging not implemented yet");

        Transaction {
            kernel: merged_kernel,
            proof: TransactionProof::SingleProof(merger_proof),
        }
    }

    /// Calculates a fraction representing the fee-density, defined as:
    /// `transaction_fee/transaction_size`.
    pub fn fee_density(&self) -> BigRational {
        let transaction_as_bytes = bincode::serialize(&self).unwrap();
        let transaction_size = BigInt::from(transaction_as_bytes.get_size());
        let transaction_fee = self.kernel.fee.to_nau();
        BigRational::new_raw(transaction_fee, transaction_size)
    }

    /// Determine if the transaction can be validly confirmed if the block has
    /// the given mutator set accumulator. Specifically, test whether the
    /// removal records determine indices absent in the mutator set sliding
    /// window Bloom filter, and whether the MMR membership proofs are valid.
    pub fn is_confirmable_relative_to(
        &self,
        mutator_set_accumulator: &MutatorSetAccumulator,
    ) -> bool {
        self.kernel
            .inputs
            .iter()
            .all(|rr| rr.validate(mutator_set_accumulator))
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::Digest;
    use tests::primitive_witness::SaltedUtxos;

    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;

    use super::*;

    #[test]
    fn decode_encode_test_empty() {
        let empty_kernel = TransactionKernel {
            inputs: vec![],
            outputs: vec![],
            public_announcements: vec![],
            fee: NeptuneCoins::new(0),
            coinbase: None,
            timestamp: Default::default(),
            mutator_set_hash: Digest::default(),
        };
        let primitive_witness = PrimitiveWitness {
            input_utxos: SaltedUtxos::empty(),
            type_scripts_and_witnesses: vec![],
            lock_scripts_and_witnesses: vec![],
            input_membership_proofs: vec![],
            output_utxos: SaltedUtxos::empty(),
            output_sender_randomnesses: vec![],
            output_receiver_digests: vec![],
            mutator_set_accumulator: MutatorSetAccumulator::default(),
            kernel: empty_kernel,
        };

        let encoded = primitive_witness.encode();
        let decoded = *PrimitiveWitness::decode(&encoded).unwrap();
        assert_eq!(primitive_witness, decoded);
    }
}

#[cfg(test)]
mod transaction_tests {
    use lock_script::LockScript;
    use rand::random;
    use tracing_test::traced_test;
    use transaction_tests::utxo::Utxo;

    use super::*;
    use crate::{
        models::{
            blockchain::type_scripts::neptune_coins::NeptuneCoins,
            proof_abstractions::timestamp::Timestamp,
        },
        tests::shared::make_mock_transaction,
        util_types::mutator_set::commit,
    };

    #[traced_test]
    #[test]
    fn tx_get_timestamp_test() {
        let output_1 = Utxo {
            coins: NeptuneCoins::new(42).to_native_coins(),
            lock_script_hash: LockScript::anyone_can_spend().hash(),
        };
        let ar = commit(Hash::hash(&output_1), random(), random());

        // Verify that a sane timestamp is returned. `make_mock_transaction` must follow
        // the correct time convention for this test to work.
        let coinbase_transaction = make_mock_transaction(vec![], vec![ar]);
        assert!(Timestamp::now() - coinbase_transaction.kernel.timestamp < Timestamp::seconds(10));
    }

    #[test]
    fn encode_decode_empty_tx_test() {
        let empty_tx = make_mock_transaction(vec![], vec![]);
        let encoded = empty_tx.encode();
        let decoded = *Transaction::decode(&encoded).unwrap();
        assert_eq!(empty_tx, decoded);
    }

    // #[traced_test]
    // #[test]
    // fn merged_transaction_is_devnet_valid_test() {
    //     let wallet_1 = new_random_wallet();
    //     let output_amount_1: Amount = 42.into();
    //     let output_1 = Utxo {
    //         amount: output_amount_1,
    //         public_key: wallet_1.get_public_key(),
    //     };
    //     let randomness: Digest = Digest::new(random_elements_array());

    //     let coinbase_transaction = make_mock_transaction(vec![], vec![(output_1, randomness)]);
    //     let coinbase_amount = Some(output_amount_1);

    //     assert!(coinbase_transaction.is_valid_for_devnet(coinbase_amount));

    //     let input_1 = make_mock_unsigned_devnet_input(<i32 as Into<Amount>>::into(42), &wallet_1);
    //     let mut transaction_1 = make_mock_transaction(vec![input_1], vec![(output_1, randomness)]);

    //     assert!(!transaction_1.is_valid_for_devnet(None));
    //     transaction_1.sign(&wallet_1);
    //     assert!(transaction_1.is_valid_for_devnet(None));

    //     let input_2 = make_mock_unsigned_devnet_input(42.into(), &wallet_1);
    //     let mut transaction_2 = make_mock_transaction(vec![input_2], vec![(output_1, randomness)]);

    //     assert!(!transaction_2.is_valid_for_devnet(None));
    //     transaction_2.sign(&wallet_1);
    //     assert!(transaction_2.is_valid_for_devnet(None));

    //     let mut merged_transaction = transaction_1.merge_with(transaction_2);
    //     assert!(
    //         merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must be valid because of authority proof"
    //     );

    //     merged_transaction.authority_proof = None;
    //     assert!(
    //         !merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must not be valid without authority proof"
    //     );

    //     // Make an authority sign with a wrong secret key and verify failure
    //     let kernel: TransactionKernel = merged_transaction.get_kernel();
    //     let kernel_digest: Digest = Hash::hash(&kernel);
    //     let bad_authority_signature = wallet_1.sign_digest(kernel_digest);
    //     merged_transaction.authority_proof = Some(bad_authority_signature);
    //     assert!(
    //         !merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must not be valid with wrong authority proof"
    //     );

    //     // Restore valid proof
    //     merged_transaction.devnet_authority_sign();
    //     assert!(
    //         merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must be valid because of authority proof, 2"
    //     );
    // }

    // #[traced_test]
    // #[tokio::test]
    // async fn transaction_is_valid_after_block_update_simple_test() -> Result<()> {
    //     // We need the global state to construct a transaction. This global state
    //     // has a wallet which receives a premine-UTXO.
    //     let global_state = get_mock_global_state(Network::Main, 2, None).await;
    //     let other_wallet = wallet::WalletSecret::new(wallet::generate_secret_key());

    //     // Create a transaction that's valid after the Genesis block
    //     let receiver_data = vec![UtxoReceiverData {
    //         utxo: Utxo {
    //             lock_script: LockScript(vec![]),
    //             coins: Into::<Amount>::into(5).to_native_coins(),
    //         },
    //         sender_randomness: random(),
    //         receiver_privacy_digest: random(),
    //         pubscript: PubScript::default(),
    //         pubscript_input: vec![],
    //     }];
    //     let mut transaction = global_state
    //         .create_transaction(receiver_data, Amount::one())
    //         .await
    //         .unwrap();

    //     let genesis_block = Block::genesis_block();
    //     let (block_1, _, _) = make_mock_block(
    //         &genesis_block,
    //         None,
    //         other_wallet.nth_generation_spending_key(0).to_address(),
    //     );
    //     assert!(
    //         block_1.is_valid_for_devnet(&genesis_block),
    //         "Block 1 must be valid with only coinbase output"
    //     );

    //     assert!(transaction.is_valid(None));
    //     transaction.update_mutator_set_records(&block_1).unwrap();

    //     // Insert the updated transaction into block 2 and verify that this block is valid
    //     let mut block_2 = make_mock_block(&block_1, None, other_wallet.get_public_key());
    //     block_2.authority_merge_transaction(updated_tx.clone());
    //     assert!(block_2.is_valid_for_devnet(&block_1));

    //     // Mine 26 blocks, keep the transaction updated, and verify that it is valid after
    //     // all blocks
    //     let mut next_block = block_1.clone();
    //     let mut _previous_block = next_block.clone();
    //     for _ in 0..26 {
    //         _previous_block = next_block;
    //         next_block = make_mock_block(&_previous_block, None, other_wallet.get_public_key());
    //         updated_tx.update_ms_data(&next_block).unwrap();
    //     }

    //     _previous_block = next_block.clone();
    //     next_block = make_mock_block(&next_block, None, other_wallet.get_public_key());
    //     next_block.authority_merge_transaction(updated_tx.clone());
    //     assert!(next_block.is_valid_for_devnet(&_previous_block));

    //     Ok(())
    // }

    // #[traced_test]
    // #[tokio::test]
    // async fn transaction_is_valid_after_block_update_multiple_ios_test() -> Result<()> {
    //     // We need the global state to construct a transaction. This global state
    //     // has a wallet which receives a premine-UTXO.
    //     let own_global_state = get_mock_global_state(Network::Main, 2, None).await;
    //     let own_wallet_secret = &own_global_state.wallet_state.wallet_secret;

    //     // Create a transaction that's valid after the Genesis block
    //     let mut output_utxos: Vec<Utxo> = vec![];
    //     for i in 0..7 {
    //         let new_utxo = Utxo {
    //             amount: i.into(),
    //             public_key: own_wallet_secret.get_public_key(),
    //         };
    //         output_utxos.push(new_utxo);
    //     }

    //     // Create a transaction that's valid after genesis block
    //     let mut tx = own_global_state
    //         .create_transaction(output_utxos, 1.into())
    //         .await
    //         .unwrap();
    //     let original_tx = tx.clone();

    //     // Create next block and verify that transaction is not valid with this block as tip
    //     let genesis_block = Block::genesis_block();
    //     let other_wallet = WalletSecret::new(generate_secret_key());
    //     let block_1 = make_mock_block(&genesis_block, None, own_wallet_secret.get_public_key());
    //     let block_2 = make_mock_block(&block_1, None, other_wallet.get_public_key());
    //     assert!(
    //         block_1.is_valid_for_devnet(&genesis_block),
    //         "Block 1 must be valid with only coinbase output"
    //     );
    //     assert!(
    //         block_2.is_valid_for_devnet(&block_1),
    //         "Block 2 must be valid with only coinbase output"
    //     );

    //     let mut block_2_with_deprecated_tx = block_2.clone();
    //     block_2_with_deprecated_tx.authority_merge_transaction(tx.clone());
    //     assert!(
    //         !block_2_with_deprecated_tx.is_valid_for_devnet(&block_1),
    //         "Block with transaction with deprecated mutator set data must be invalid"
    //     );

    //     // Update the transaction with mutator set data from block 1. Verify that this
    //     // gives rise to a valid block.
    //     tx.update_ms_data(&block_1).unwrap();
    //     let mut block_2_with_updated_tx = block_2.clone();
    //     block_2_with_updated_tx.authority_merge_transaction(tx.clone());
    //     assert!(
    //         block_2_with_updated_tx.is_valid_for_devnet(&block_1),
    //         "Block with transaction with updated mutator set data must be valid"
    //     );

    //     // We would like to use more advanced blocks, that have multiple inputs and outputs.
    //     // Problem: If we start making with my own wallet, we consume the same inputs that are
    //     // consumed in `updated_tx`. Solution: Create another global state object, containing
    //     // another wallet, and use this to generate the transactions that go into these
    //     // blocks. This should keep the `updated_tx` valid as its inputs are not being spent.
    //     let other_global_state =
    //         get_mock_global_state(Network::Main, 2, Some(other_wallet.clone())).await;
    //     other_global_state
    //         .wallet_state
    //         .update_wallet_state_with_new_block(
    //             &block_1,
    //             &mut other_global_state.wallet_state.wallet_db.lock().await,
    //         )
    //         .unwrap();
    //     *other_global_state
    //         .chain
    //         .light_state
    //         .latest_block
    //         .lock()
    //         .await = block_1.clone();
    //     other_global_state
    //         .wallet_state
    //         .update_wallet_state_with_new_block(
    //             &block_2,
    //             &mut other_global_state.wallet_state.wallet_db.lock().await,
    //         )
    //         .unwrap();
    //     *other_global_state
    //         .chain
    //         .light_state
    //         .latest_block
    //         .lock()
    //         .await = block_2.clone();
    //     let mut updated_tx = original_tx;
    //     updated_tx.update_ms_data(&block_1).unwrap();
    //     updated_tx.update_ms_data(&block_2).unwrap();

    //     // Mine 12 blocks with non-trivial transactions, keep the transaction updated,
    //     // and verify that it is valid after all blocks.
    //     let mut next_block = block_2.clone();
    //     let mut _previous_block = next_block.clone();
    //     for i in 0..12 {
    //         _previous_block = next_block.clone();
    //         let utxo_a = Utxo {
    //             amount: (3 * i).into(),
    //             public_key: other_wallet.get_public_key(),
    //         };
    //         let utxo_b = Utxo {
    //             amount: (3 * i + 1).into(),
    //             public_key: other_wallet.get_public_key(),
    //         };
    //         let utxo_c = Utxo {
    //             amount: (3 * i + 2).into(),
    //             public_key: other_wallet.get_public_key(),
    //         };
    //         let other_transaction = other_global_state
    //             .create_transaction(vec![utxo_a, utxo_b, utxo_c], 1.into())
    //             .await
    //             .unwrap();
    //         next_block = make_mock_block(&_previous_block, None, other_wallet.get_public_key());

    //         next_block.authority_merge_transaction(other_transaction);
    //         assert!(
    //             next_block.is_valid_for_devnet(&_previous_block),
    //             "Produced block must be valid after merging new transaction"
    //         );

    //         // Update other's global state with this transaction, such that a new transaction
    //         // can be made in the next iteration of the loop.
    //         {
    //             let mut light_state = other_global_state
    //                 .chain
    //                 .light_state
    //                 .latest_block
    //                 .lock()
    //                 .await;
    //             *light_state = next_block.clone();
    //             other_global_state
    //                 .wallet_state
    //                 .update_wallet_state_with_new_block(
    //                     &next_block,
    //                     &mut other_global_state.wallet_state.wallet_db.lock().await,
    //                 )
    //                 .unwrap();
    //         }

    //         // After each new block, "our" transaction is updated with the information
    //         // from that block such that its mutator set data is kept up-to-date.
    //         updated_tx.update_ms_data(&next_block).unwrap();
    //     }

    //     _previous_block = next_block.clone();
    //     next_block = make_mock_block(&next_block, None, other_wallet.get_public_key());
    //     next_block.authority_merge_transaction(updated_tx.clone());
    //     assert!(
    //         next_block.is_valid_for_devnet(&_previous_block),
    //         "Block is valid when merged transaction is updated"
    //     );

    //     Ok(())
    // }
}
