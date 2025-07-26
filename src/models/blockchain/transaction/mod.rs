use std::sync::Arc;

use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::config_models::network::Network;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::transaction_kernel_id::TransactionKernelId;
use crate::triton_vm_job_queue::TritonVmJobQueue;

pub mod announcement;
pub mod lock_script;
pub mod primitive_witness;
pub mod transaction_kernel;
pub mod transaction_proof;
pub mod utxo;
pub(crate) mod utxo_triple;
pub mod validity;

use anyhow::ensure;
use anyhow::Result;
use get_size2::GetSize;
use itertools::Itertools;
use num_bigint::BigInt;
use num_rational::BigRational;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use tracing::info;
pub(crate) use transaction_proof::TransactionProof;
use validity::proof_collection::ProofCollection;
use validity::tasm::single_proof::merge_branch::MergeWitness;
use validity::tasm::single_proof::update_branch::UpdateWitness;

use self::primitive_witness::PrimitiveWitness;
use self::transaction_kernel::TransactionKernel;
use self::transaction_kernel::TransactionKernelModifier;
use self::transaction_kernel::TransactionKernelProxy;
use super::consensus_rule_set::ConsensusRuleSet;
use crate::models::blockchain::transaction::validity::neptune_proof::Proof;
use crate::triton_vm::proof::Claim;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct Transaction {
    pub kernel: TransactionKernel,

    pub proof: TransactionProof,
}

impl From<PrimitiveWitness> for Transaction {
    fn from(value: PrimitiveWitness) -> Self {
        Transaction {
            kernel: value.kernel.clone(),
            proof: TransactionProof::Witness(value),
        }
    }
}

// for simpler Arc compatibility with existing tests.
#[cfg(test)]
impl From<Arc<Transaction>> for Transaction {
    fn from(t: Arc<Transaction>) -> Self {
        (*t).clone()
    }
}

impl Transaction {
    /// return transaction id.
    ///
    /// note that transactions created by users are temporary.  Once confirmed
    /// into a block they are merged into a single block transaction.  So this
    /// id will not correspond to anything on the blockchain except for the
    /// single transaction in each block.
    ///
    /// These id are useful for referencing transactions in the mempool however.
    pub fn txid(&self) -> TransactionKernelId {
        self.kernel.txid()
    }

    /// Create a new `Transaction` by updating the given one with the mutator
    /// set update. If `new_timestamp` is `None`, the timestamp from the old
    /// transaction kernel will be used.
    ///
    /// No primitive witness is present, instead a proof is given. So:
    ///  1. Verify the proof
    ///  2. Update the records
    ///  3. Prove correctness of 1 and 2
    ///  4. Use resulting proof as new witness.
    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn new_with_updated_mutator_set_records_given_proof(
        old_transaction_kernel: TransactionKernel,
        previous_mutator_set_accumulator: &MutatorSetAccumulator,
        mutator_set_update: &MutatorSetUpdate,
        old_single_proof: Proof,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        new_timestamp: Option<Timestamp>,
        consensus_rule_set: ConsensusRuleSet,
    ) -> anyhow::Result<Transaction> {
        ensure!(
            old_transaction_kernel.mutator_set_hash == previous_mutator_set_accumulator.hash(),
            "Old transaction kernel's mutator set hash does not agree \
                with supplied mutator set accumulator."
        );

        // apply mutator set update to get new mutator set accumulator
        let addition_records = mutator_set_update.additions.clone();
        let mut calculated_new_mutator_set = previous_mutator_set_accumulator.clone();
        let mut new_inputs = old_transaction_kernel.inputs.clone();
        mutator_set_update
            .apply_to_accumulator_and_records(
                &mut calculated_new_mutator_set,
                &mut new_inputs.iter_mut().collect_vec(),
                &mut [],
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
        let mut modifier = TransactionKernelModifier::default()
            .inputs(new_inputs)
            .mutator_set_hash(calculated_new_mutator_set.hash());
        if let Some(new_timestamp) = new_timestamp {
            modifier = modifier.timestamp(new_timestamp);
        }
        let new_kernel = modifier.clone_modify(&old_transaction_kernel);

        // compute updated proof through recursion
        let update_witness = UpdateWitness::from_old_transaction(
            old_transaction_kernel,
            old_single_proof,
            previous_mutator_set_accumulator.clone(),
            new_kernel.clone(),
            calculated_new_mutator_set,
            aocl_successor_proof,
        );

        info!("starting single proof via update ...");
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .update_witness(&update_witness)
            .job_queue(triton_vm_job_queue)
            .proof_job_options(proof_job_options)
            .build()
            .await?;
        info!("done.");

        Ok(Transaction {
            kernel: new_kernel,
            proof,
        })
    }

    /// Determine whether the transaction is valid but not necessarily
    /// confirmable.
    ///
    /// This method tests the transaction's internal consistency in isolation,
    /// without the context of the canonical chain.
    pub async fn is_valid(&self, network: Network, consensus_rule_set: ConsensusRuleSet) -> bool {
        let kernel_hash = self.kernel.mast_hash();
        self.proof
            .verify(kernel_hash, network, consensus_rule_set)
            .await
    }

    /// Merge two transactions. Both input transactions must have a valid
    /// Proof witness for this operation to work. The `self` argument can be
    /// a transaction with a negative fee.
    ///
    /// # Panics
    ///
    /// Panics if the two transactions cannot be merged, if e.g. the mutator
    /// set hashes are not the same, if both transactions have coinbase a
    /// coinbase UTXO, if either of the transactions are *not* a single
    /// proof, or if the RHS (`other`) has a negative fee.
    pub(crate) async fn merge_with(
        self,
        other: Transaction,
        shuffle_seed: [u8; 32],
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
        _consensus_rule_set: ConsensusRuleSet,
    ) -> Result<Transaction> {
        assert_eq!(
            self.kernel.mutator_set_hash, other.kernel.mutator_set_hash,
            "Mutator sets must be equal for transaction merger."
        );

        assert!(
            self.kernel.coinbase.is_none() && other.kernel.coinbase.is_none(),
            "Don't use me for coinbase transactions, por favor"
        );

        let merge_witness = MergeWitness::from_transactions(self, other, shuffle_seed);
        MergeWitness::merge(merge_witness, triton_vm_job_queue, proof_job_options).await
    }

    /// Calculates a fraction representing the fee-density, defined as:
    /// `transaction_fee/transaction_size`.
    pub fn fee_density(&self) -> BigRational {
        let transaction_as_bytes = bincode::serialize(&self).unwrap();
        let transaction_size = BigInt::from(transaction_as_bytes.get_size());
        let transaction_fee = self.kernel.fee.to_nau();
        BigRational::new_raw(transaction_fee.into(), transaction_size)
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
            .is_confirmable_relative_to(mutator_set_accumulator)
            .is_ok()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use lock_script::LockScript;
    use macro_rules_attr::apply;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::random;
    use strum::IntoEnumIterator;
    use tasm_lib::prelude::Digest;
    use tasm_lib::triton_vm::error::InstructionError;
    use tasm_lib::triton_vm::isa::error::AssertionError;
    use tests::primitive_witness::SaltedUtxos;
    use tests::utxo::Utxo;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::{TxInputList, TxOutputList};
    use crate::api::tx_initiation::error::CreateProofError;
    use crate::config_models::network::Network;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::transaction::utxo_triple::UtxoTriple;
    use crate::models::blockchain::transaction::validity::single_proof::produce_single_proof;
    use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
    use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::models::proof_abstractions::tasm::prover_job::{ProverJobError, VmProcessError};
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::tests::shared::mock_tx::make_mock_transaction;
    use crate::tests::shared_tokio_runtime;
    use crate::triton_vm_job_queue::{vm_job_queue, TritonVmJobPriority};
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl Transaction {
        /// Create a new transaction with primitive witness for a new mutator set.
        ///
        /// Takes unpacked removal records as input.
        pub(crate) fn new_with_primitive_witness_ms_data(
            old_primitive_witness: PrimitiveWitness,
            new_addition_records: Vec<AdditionRecord>,
            new_removal_records: Vec<RemovalRecord>,
        ) -> Transaction {
            let mutator_set_update =
                MutatorSetUpdate::new(new_removal_records, new_addition_records);
            let primitive_witness = PrimitiveWitness::update_with_new_ms_data(
                old_primitive_witness,
                mutator_set_update,
            );
            let kernel = primitive_witness.kernel.clone();
            let witness = TransactionProof::Witness(primitive_witness);

            Transaction {
                kernel,
                proof: witness,
            }
        }

        /// Create a new [`Transaction`], backed by a [`SingleProof`].
        pub(crate) fn new_single_proof(kernel: TransactionKernel, proof: Proof) -> Self {
            Self {
                kernel,
                proof: TransactionProof::SingleProof(proof),
            }
        }
    }

    #[test]
    fn decode_encode_test_empty() {
        let empty_kernel = TransactionKernelProxy {
            inputs: vec![],
            outputs: vec![],
            announcements: vec![],
            fee: NativeCurrencyAmount::coins(0),
            coinbase: None,
            timestamp: Default::default(),
            mutator_set_hash: Digest::default(),
            merge_bit: false,
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

    #[traced_test]
    #[test]
    fn tx_get_timestamp_test() {
        let output_1 = Utxo::new_native_currency(
            LockScript::anyone_can_spend().hash(),
            NativeCurrencyAmount::coins(42),
        );
        let ar = UtxoTriple {
            utxo: output_1.clone(),
            sender_randomness: random(),
            receiver_digest: random(),
        }
        .addition_record();

        // Verify that a sane timestamp is returned. `make_mock_transaction` must follow
        // the correct time convention for this test to work.
        let coinbase_transaction = make_mock_transaction(vec![], vec![ar]);
        assert!(Timestamp::now() - coinbase_transaction.kernel.timestamp < Timestamp::seconds(10));
    }

    // `traced_test` macro inserts return type that clippy doesn't like.
    // Macro is at fault.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn update_single_proof_works() {
        async fn prop(
            to_be_updated: PrimitiveWitness,
            mined: PrimitiveWitness,
            consensus_rule_set: ConsensusRuleSet,
        ) {
            let network = Network::Main;
            let as_single_proof = produce_single_proof(
                &to_be_updated,
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
                consensus_rule_set,
            )
            .await
            .unwrap();
            let original_tx = Transaction {
                kernel: to_be_updated.kernel,
                proof: TransactionProof::SingleProof(as_single_proof),
            };
            assert!(original_tx.is_valid(network, consensus_rule_set).await);

            let mutator_set_update =
                MutatorSetUpdate::new(mined.kernel.inputs.clone(), mined.kernel.outputs.clone());
            let updated_tx = Transaction::new_with_updated_mutator_set_records_given_proof(
                original_tx.kernel,
                &to_be_updated.mutator_set_accumulator,
                &mutator_set_update,
                original_tx.proof.into_single_proof(),
                TritonVmJobQueue::get_instance(),
                TritonVmJobPriority::default().into(),
                None,
                consensus_rule_set,
            )
            .await
            .unwrap();

            assert!(updated_tx.is_valid(network, consensus_rule_set).await)
        }

        for consensus_rule_set in ConsensusRuleSet::iter() {
            for (to_be_updated_params, mined_params) in [
                ((4, 4, 4), (3, 3, 3)),
                ((1, 0, 1), (1, 1, 0)),
                ((1, 1, 0), (1, 0, 0)),
                ((6, 2, 1), (1, 1, 1)),
                ((2, 2, 2), (2, 2, 2)),
            ] {
                println!("consensus_rule_set: {consensus_rule_set}");
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
                assert!(to_be_updated.validate().await.is_ok());
                assert!(mined.validate().await.is_ok());

                prop(to_be_updated.clone(), mined.clone(), consensus_rule_set).await;
            }
        }
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn disallow_empty_transaction_with_non_zero_fee() {
        // Ensure that we cannot create a transaction with non-zero fee when
        // transaction has no inputs or outputs.
        let network = Network::Main;
        let genesis = Block::genesis(network);

        let msa = genesis.mutator_set_accumulator_after().unwrap();
        let now = network.launch_date() + Timestamp::hours(12);
        let cheated_fee = NativeCurrencyAmount::coins(100);
        let fee_tx = TransactionDetails::new_without_coinbase(
            TxInputList::default(),
            TxOutputList::default(),
            cheated_fee,
            now,
            msa.clone(),
            network,
        );

        let fee_tx = fee_tx.primitive_witness();
        let consensus_rule_set = ConsensusRuleSet::Reboot;
        let fee_sp_error = produce_single_proof(
            &fee_tx,
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
            consensus_rule_set,
        )
        .await
        .unwrap_err();
        let CreateProofError::ProverJobError(ProverJobError::TritonVmProverFailed(
            VmProcessError::TritonVmFailed(InstructionError::AssertionFailed(AssertionError {
                id: error_id,
                ..
            })),
        )) = fee_sp_error
        else {
            panic!("Expected Triton VM prover error");
        };

        assert_eq!(Some(NativeCurrency::NO_INFLATION_VIOLATION), error_id);
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn primitive_witness_update_properties() {
        async fn assert_valid_as_pw(transaction: &Transaction) {
            let TransactionProof::Witness(pw) = &transaction.proof else {
                panic!("Expected primitive witness variant");
            };
            assert!(pw.validate().await.is_ok())
        }

        let mut test_runner = TestRunner::deterministic();
        let [to_be_updated, mined] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([(4, 4, 4), (3, 3, 3)])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        assert!(to_be_updated.validate().await.is_ok());
        assert!(mined.validate().await.is_ok());

        let updated_with_block = Transaction::new_with_primitive_witness_ms_data(
            to_be_updated.clone(),
            mined.kernel.outputs.clone(),
            mined.kernel.inputs.clone(),
        );
        assert_valid_as_pw(&updated_with_block).await;

        // Asssert some properties of the updated transaction.
        assert_eq!(
            to_be_updated.kernel.coinbase,
            updated_with_block.kernel.coinbase
        );
        assert_eq!(to_be_updated.kernel.fee, updated_with_block.kernel.fee);
        assert_eq!(
            to_be_updated.kernel.outputs,
            updated_with_block.kernel.outputs
        );
        assert_eq!(
            to_be_updated.kernel.announcements,
            updated_with_block.kernel.announcements
        );
        assert_eq!(
            to_be_updated.kernel.inputs.len(),
            updated_with_block.kernel.inputs.len(),
        );
        assert_eq!(
            to_be_updated
                .kernel
                .inputs
                .iter()
                .map(|x| x.absolute_indices)
                .collect_vec(),
            updated_with_block
                .kernel
                .inputs
                .iter()
                .map(|x| x.absolute_indices)
                .collect_vec()
        );
        assert_ne!(
            to_be_updated.kernel.mutator_set_hash,
            updated_with_block.kernel.mutator_set_hash
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
    // #[apply(shared_tokio_runtime)]
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
    //     let (block_1, _, _) = make_mock_block(network,
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
    //     let mut block_2 = make_mock_block(network, &block_1, None, other_wallet.get_public_key());
    //     block_2.authority_merge_transaction(updated_tx.clone());
    //     assert!(block_2.is_valid_for_devnet(&block_1));

    //     // Mine 26 blocks, keep the transaction updated, and verify that it is valid after
    //     // all blocks
    //     let mut next_block = block_1.clone();
    //     let mut _previous_block = next_block.clone();
    //     for _ in 0..26 {
    //         _previous_block = next_block;
    //         next_block = make_mock_block(network, &_previous_block, None, other_wallet.get_public_key());
    //         updated_tx.update_ms_data(&next_block).unwrap();
    //     }

    //     _previous_block = next_block.clone();
    //     next_block = make_mock_block(network, &next_block, None, other_wallet.get_public_key());
    //     next_block.authority_merge_transaction(updated_tx.clone());
    //     assert!(next_block.is_valid_for_devnet(&_previous_block));

    //     Ok(())
    // }

    // #[traced_test]
    // #[apply(shared_tokio_runtime)]
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
    //     let block_1 = make_mock_block(network, &genesis_block, None, own_wallet_secret.get_public_key());
    //     let block_2 = make_mock_block(network, &block_1, None, other_wallet.get_public_key());
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
    //         next_block = make_mock_block(network, &_previous_block, None, other_wallet.get_public_key());

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
    //     next_block = make_mock_block(network, &next_block, None, other_wallet.get_public_key());
    //     next_block.authority_merge_transaction(updated_tx.clone());
    //     assert!(
    //         next_block.is_valid_for_devnet(&_previous_block),
    //         "Block is valid when merged transaction is updated"
    //     );

    //     Ok(())
    // }
}
