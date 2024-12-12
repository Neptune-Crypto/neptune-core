use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::peer::transfer_transaction::TransactionProofQuality;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::SecretWitness;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::commit;

pub mod lock_script;
pub mod primitive_witness;
pub mod transaction_kernel;
pub mod utxo;
pub mod validity;

use anyhow::bail;
use anyhow::Result;
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use num_bigint::BigInt;
use num_rational::BigRational;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use tracing::info;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use utxo::Utxo;
use validity::proof_collection::ProofCollection;
use validity::single_proof::SingleProof;
use validity::single_proof::SingleProofWitness;
use validity::tasm::single_proof::merge_branch::MergeWitness;
use validity::tasm::single_proof::update_branch::UpdateWitness;

use self::primitive_witness::PrimitiveWitness;
use self::transaction_kernel::TransactionKernel;
use self::transaction_kernel::TransactionKernelModifier;
use self::transaction_kernel::TransactionKernelProxy;
use crate::triton_vm::proof::Claim;
use crate::triton_vm::proof::Proof;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// represents a utxo and secrets necessary for recipient to claim it.
///
/// these are built from one of:
///   onchain symmetric-key public announcements
///   onchain asymmetric-key public announcements
///   offchain expected-utxos
///
/// See [PublicAnnouncement], [UtxoNotification], [ExpectedUtxo]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AnnouncedUtxo {
    pub utxo: Utxo,
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
}

impl From<&ExpectedUtxo> for AnnouncedUtxo {
    fn from(eu: &ExpectedUtxo) -> Self {
        Self {
            utxo: eu.utxo.clone(),
            sender_randomness: eu.sender_randomness,
            receiver_preimage: eu.receiver_preimage,
        }
    }
}

impl AnnouncedUtxo {
    pub(crate) fn addition_record(&self) -> AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
    }

    pub(crate) fn into_expected_utxo(self, received_from: UtxoNotifier) -> ExpectedUtxo {
        ExpectedUtxo::new(
            self.utxo.to_owned(),
            self.sender_randomness,
            self.receiver_preimage,
            received_from,
        )
    }
}

/// represents arbitrary data that can be stored in a transaction on the public blockchain
///
/// initially these are used for transmitting encrypted secrets necessary
/// for a utxo recipient to identify and claim it.
///
/// See [Transaction], [UtxoNotification]
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum TransactionProof {
    Witness(PrimitiveWitness),
    SingleProof(Proof),
    ProofCollection(ProofCollection),
}

impl TransactionProof {
    /// A proof that will always be invalid
    #[cfg(test)]
    pub(crate) fn invalid() -> Self {
        Self::SingleProof(Proof(vec![]))
    }

    pub(crate) fn into_single_proof(self) -> Proof {
        match self {
            TransactionProof::SingleProof(proof) => proof,
            TransactionProof::Witness(_) => {
                panic!("Expected SingleProof, got Witness")
            }
            TransactionProof::ProofCollection(_) => {
                panic!("Expected SingleProof, got ProofCollection")
            }
        }
    }

    pub(crate) fn proof_quality(&self) -> Result<TransactionProofQuality> {
        match self {
            TransactionProof::Witness(_) => bail!("Primitive witness does not have a proof"),
            TransactionProof::ProofCollection(_) => Ok(TransactionProofQuality::ProofCollection),
            TransactionProof::SingleProof(_) => Ok(TransactionProofQuality::SingleProof),
        }
    }

    pub async fn verify(&self, kernel_mast_hash: Digest) -> bool {
        match self {
            TransactionProof::Witness(primitive_witness) => {
                primitive_witness.validate().await
                    && primitive_witness.kernel.mast_hash() == kernel_mast_hash
            }
            TransactionProof::SingleProof(single_proof) => {
                let claim = SingleProof::claim(kernel_mast_hash);
                triton_vm::verify(Stark::default(), &claim, single_proof)
            }
            TransactionProof::ProofCollection(proof_collection) => {
                proof_collection.verify(kernel_mast_hash)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum TransactionProofError {
    CannotUpdateProofVariant,
    CannotUpdatePrimitiveWitness,
    CannotUpdateSingleProof,
    ProverLockWasTaken,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct Transaction {
    pub kernel: TransactionKernel,

    pub proof: TransactionProof,
}

impl Transaction {
    /// Create a new `Transaction` by updating the given one with the mutator set
    /// update contained in the `Block`. No primitive witness is present, instead
    /// a proof is given. So:
    ///  1. Verify the proof
    ///  2. Update the records
    ///  3. Prove correctness of 1 and 2
    ///  4. Use resulting proof as new witness.
    pub(crate) async fn new_with_updated_mutator_set_records_given_proof(
        old_transaction_kernel: TransactionKernel,
        previous_mutator_set_accumulator: &MutatorSetAccumulator,
        mutator_set_update: &MutatorSetUpdate,
        old_single_proof: Proof,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Transaction> {
        // apply mutator set update to get new mutator set accumulator
        let addition_records = mutator_set_update.additions.clone();
        let mut calculated_new_mutator_set = previous_mutator_set_accumulator.clone();
        let mut new_inputs = old_transaction_kernel.inputs.clone();
        mutator_set_update
            .apply_to_accumulator_and_records(
                &mut calculated_new_mutator_set,
                &mut new_inputs.iter_mut().collect_vec(),
            )
            .unwrap_or_else(|_| panic!("Could not apply mutator set update."));

        let aocl_successor_proof = MmrSuccessorProof::new_from_batch_append(
            &previous_mutator_set_accumulator.aocl,
            &addition_records
                .iter()
                .map(|addition_record| addition_record.canonical_commitment)
                .collect_vec(),
        );

        // compute new kernel
        let new_kernel = TransactionKernelModifier::default()
            .inputs(new_inputs)
            .mutator_set_hash(calculated_new_mutator_set.hash())
            .clone_modify(&old_transaction_kernel);

        // compute updated proof through recursion
        let update_witness = UpdateWitness::from_old_transaction(
            old_transaction_kernel,
            old_single_proof,
            previous_mutator_set_accumulator.clone(),
            new_kernel.clone(),
            calculated_new_mutator_set,
            aocl_successor_proof,
        );
        // let update_claim = update_witness.claim();
        // let update_nondeterminism = update_witness.nondeterminism();
        // info!("updating transaction; starting update proof ...");
        // let update_proof = Update
        //     .prove(
        //         update_claim,
        //         update_nondeterminism,
        //         triton_vm_job_queue,
        //         proof_job_options,
        //     )
        //     .await?;
        // info!("done.");

        let new_single_proof_witness = SingleProofWitness::from_update(update_witness);
        let new_single_proof_claim = new_single_proof_witness.claim();

        info!("starting single proof via update ...");
        let new_single_proof = SingleProof
            .prove(
                new_single_proof_claim,
                new_single_proof_witness.nondeterminism(),
                triton_vm_job_queue,
                proof_job_options,
            )
            .await?;
        info!("done.");

        Ok(Transaction {
            kernel: new_kernel,
            proof: TransactionProof::SingleProof(new_single_proof),
        })
    }

    /// Determine whether the transaction is valid (forget about confirmable).
    /// This method tests the transaction's internal consistency in isolation,
    /// without the context of the canonical chain.
    pub async fn is_valid(&self) -> bool {
        let kernel_hash = self.kernel.mast_hash();
        self.proof.verify(kernel_hash).await
    }

    /// Merge two transactions. Both input transactions must have a valid
    /// Proof witness for this operation to work.
    ///
    /// # Panics
    ///
    /// Panics if the two transactions cannot be merged, if e.g. the mutator
    /// set hashes are not the same, if both transactions have coinbase a
    /// coinbase UTXO, or if either of the transactions are *not* a single
    /// proof.
    pub(crate) async fn merge_with(
        self,
        other: Transaction,
        shuffle_seed: [u8; 32],
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Result<Transaction> {
        assert_eq!(
            self.kernel.mutator_set_hash, other.kernel.mutator_set_hash,
            "Mutator sets must be equal for transaction merger."
        );

        assert!(
            self.kernel.coinbase.is_none() || other.kernel.coinbase.is_none(),
            "Cannot merge two coinbase transactions"
        );

        let self_single_proof = self.proof.into_single_proof();
        let other_single_proof = other.proof.into_single_proof();

        let merge_witness = MergeWitness::from_transactions(
            self.kernel,
            self_single_proof,
            other.kernel,
            other_single_proof,
            shuffle_seed,
        );
        let new_kernel = merge_witness.new_kernel.clone();
        let new_single_proof_witness = SingleProofWitness::from_merge(merge_witness);
        let new_single_proof_claim = new_single_proof_witness.claim();
        info!("Start: creating new single proof through merge");
        let new_single_proof = SingleProof
            .prove(
                new_single_proof_claim,
                new_single_proof_witness.nondeterminism(),
                triton_vm_job_queue,
                proof_job_options,
            )
            .await?;
        info!("Done: creating new single proof through merge");

        Ok(Transaction {
            kernel: new_kernel,
            proof: TransactionProof::SingleProof(new_single_proof),
        })
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
    ///
    /// Why not testing AOCL MMR membership proofs? These are being verified in
    /// PrimitiveWitness::validate and ProofCollection/RemovalRecordsIntegrity.
    /// AOCL membership is a feature of *validity*, which is a pre-requisite to
    /// confirmability.
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
    use tasm_lib::prelude::Digest;
    use tests::primitive_witness::SaltedUtxos;
    use triton_vm::prelude::Tip5;

    use super::*;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl Transaction {
        /// Create a new transaction with primitive witness for a new mutator set.
        pub(crate) fn new_with_primitive_witness_ms_data(
            old_primitive_witness: PrimitiveWitness,
            new_addition_records: Vec<AdditionRecord>,
            mut new_removal_records: Vec<RemovalRecord>,
        ) -> Transaction {
            new_removal_records.reverse();
            let mut block_removal_records: Vec<&mut RemovalRecord> =
                new_removal_records.iter_mut().collect::<Vec<_>>();
            let mut msa_state: MutatorSetAccumulator =
                old_primitive_witness.mutator_set_accumulator.clone();
            let mut transaction_removal_records: Vec<RemovalRecord> =
                old_primitive_witness.kernel.inputs.clone();
            let mut transaction_removal_records: Vec<&mut RemovalRecord> =
                transaction_removal_records.iter_mut().collect();

            let mut primitive_witness = old_primitive_witness.clone();

            // Apply all addition records in the block
            for block_addition_record in new_addition_records {
                // Batch update block's removal records to keep them valid after next addition
                RemovalRecord::batch_update_from_addition(&mut block_removal_records, &msa_state);

                // Batch update transaction's removal records
                RemovalRecord::batch_update_from_addition(
                    &mut transaction_removal_records,
                    &msa_state,
                );

                // Batch update primitive witness membership proofs
                let membership_proofs = &mut primitive_witness
                    .input_membership_proofs
                    .iter_mut()
                    .collect_vec();
                let own_items = primitive_witness
                    .input_utxos
                    .utxos
                    .iter()
                    .map(Tip5::hash)
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

                MsMembershipProof::batch_update_from_remove(membership_proofs, removal_record)
                    .expect("MS MP update from add must succeed in wallet handler");

                msa_state.remove(removal_record);
            }

            let kernel = TransactionKernelModifier::default()
                .inputs(
                    transaction_removal_records
                        .into_iter()
                        .map(|x| x.to_owned())
                        .collect_vec(),
                )
                .mutator_set_hash(msa_state.hash())
                .clone_modify(&primitive_witness.kernel);

            primitive_witness.kernel = kernel.clone();
            primitive_witness.mutator_set_accumulator = msa_state.clone();
            let witness = TransactionProof::Witness(primitive_witness);

            Transaction {
                kernel,
                proof: witness,
            }
        }
    }

    #[test]
    fn decode_encode_test_empty() {
        let empty_kernel = TransactionKernelProxy {
            inputs: vec![],
            outputs: vec![],
            public_announcements: vec![],
            fee: NeptuneCoins::new(0),
            coinbase: None,
            timestamp: Default::default(),
            mutator_set_hash: Digest::default(),
        }
        .into_kernel();
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
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::random;
    use tracing_test::traced_test;
    use transaction_tests::utxo::Utxo;
    use triton_vm::prelude::Tip5;

    use super::*;
    use crate::config_models::network::Network;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared::make_mock_transaction;
    use crate::tests::shared::mock_block_from_transaction_and_msa;
    use crate::util_types::mutator_set::commit;

    #[traced_test]
    #[test]
    fn tx_get_timestamp_test() {
        let output_1 =
            Utxo::new_native_currency(LockScript::anyone_can_spend(), NeptuneCoins::new(42));
        let ar = commit(Tip5::hash(&output_1), random(), random());

        // Verify that a sane timestamp is returned. `make_mock_transaction` must follow
        // the correct time convention for this test to work.
        let coinbase_transaction = make_mock_transaction(vec![], vec![ar]);
        assert!(Timestamp::now() - coinbase_transaction.kernel.timestamp < Timestamp::seconds(10));
    }

    // `traced_test` macro inserts return type that clippy doesn't like.
    // Macro is at fault.
    #[traced_test]
    #[tokio::test]
    #[allow(clippy::needless_return)]
    async fn update_single_proof_works() {
        async fn prop(to_be_updated: PrimitiveWitness, mined: PrimitiveWitness) {
            let as_single_proof = SingleProof::produce(
                &to_be_updated,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
            let original_tx = Transaction {
                kernel: to_be_updated.kernel,
                proof: TransactionProof::SingleProof(as_single_proof),
            };
            assert!(original_tx.is_valid().await);

            let mutator_set_update =
                MutatorSetUpdate::new(mined.kernel.inputs.clone(), mined.kernel.outputs.clone());
            let updated_tx = Transaction::new_with_updated_mutator_set_records_given_proof(
                original_tx.kernel,
                &to_be_updated.mutator_set_accumulator,
                &mutator_set_update,
                original_tx.proof.into_single_proof(),
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();

            assert!(updated_tx.is_valid().await)
        }

        for (to_be_updated_params, mined_params) in [
            ((4, 4, 4), (3, 3, 3)),
            ((0, 1, 0), (1, 1, 0)),
            ((1, 1, 0), (0, 1, 0)),
            ((0, 2, 1), (1, 1, 1)),
            ((2, 2, 2), (2, 2, 2)),
        ] {
            println!("to_be_updated_params: {to_be_updated_params:?}");
            println!("mined_params: {mined_params:?}");
            let mut test_runner = TestRunner::deterministic();
            let [to_be_updated, mined] =
                PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
                    to_be_updated_params,
                    mined_params,
                ])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
            prop(to_be_updated, mined).await;
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn primitive_witness_updaters_are_equivalent() {
        // Verify that various ways of updating a primitive witness are
        // equivalent, and that they all yield valid primitive witnesses.
        fn update_with_block(
            to_be_updated: PrimitiveWitness,
            mined: PrimitiveWitness,
        ) -> Transaction {
            let block = mock_block_from_transaction_and_msa(
                mined.kernel,
                mined.mutator_set_accumulator,
                Network::Main,
            );
            Transaction::new_with_primitive_witness_ms_data(
                to_be_updated.clone(),
                block.body().transaction_kernel.outputs.clone(),
                block.body().transaction_kernel.inputs.clone(),
            )
        }

        fn update_with_ms_data(
            to_be_updated: PrimitiveWitness,
            mined: PrimitiveWitness,
        ) -> Transaction {
            Transaction::new_with_primitive_witness_ms_data(
                to_be_updated,
                mined.kernel.outputs.clone(),
                mined.kernel.inputs.clone(),
            )
        }

        async fn assert_valid_as_pw(transaction: &Transaction) {
            let TransactionProof::Witness(pw) = &transaction.proof else {
                panic!("Expected primitive witness variant");
            };
            assert!(pw.validate().await)
        }

        let mut test_runner = TestRunner::deterministic();
        let [to_be_updated, mined] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([(4, 4, 4), (3, 3, 3)])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        assert!(to_be_updated.validate().await);
        assert!(mined.validate().await);

        let updated_with_block = update_with_block(to_be_updated.clone(), mined.clone());
        assert_valid_as_pw(&updated_with_block).await;

        let updated_with_ms_data = update_with_ms_data(to_be_updated.clone(), mined.clone());
        assert_valid_as_pw(&updated_with_ms_data).await;

        assert_eq!(updated_with_block, updated_with_ms_data);

        assert_eq!(
            to_be_updated.kernel.coinbase,
            updated_with_ms_data.kernel.coinbase
        );
        assert_eq!(to_be_updated.kernel.fee, updated_with_ms_data.kernel.fee);
        assert_eq!(
            to_be_updated.kernel.outputs,
            updated_with_ms_data.kernel.outputs
        );
        assert_eq!(
            to_be_updated.kernel.public_announcements,
            updated_with_ms_data.kernel.public_announcements
        );
        assert_ne!(
            to_be_updated.kernel.mutator_set_hash,
            updated_with_ms_data.kernel.mutator_set_hash
        );
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
    //     let tx_outputs = vec![TxOutput {
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
    //         .create_transaction(tx_outputs, Amount::one())
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
