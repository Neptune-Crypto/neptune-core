use bytesize::ByteSize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::bfe;

use crate::api::export::BlockHeight;
use crate::api::export::ChangePolicy;
use crate::api::export::InputSelectionPriority;
use crate::api::export::KeyType;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Network;
use crate::api::export::OutputFormat;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
use crate::api::export::TxProvingCapability;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
use crate::application::config::cli_args;
use crate::protocol::consensus::block::block_transaction::BlockOrRegularTransaction;
use crate::protocol::consensus::block::block_transaction::BlockTransaction;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::single_proof::single_proof_claim;
use crate::protocol::consensus::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::verifier::cache_true_claims;
use crate::state::transaction::tx_creation_config::TxCreationConfig;
use crate::state::wallet::expected_utxo::UtxoNotifier;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::state::wallet::wallet_entropy::WalletEntropy;
use crate::state::GlobalStateLock;
use crate::state::StateLock;
use crate::tests::shared::globalstate::mock_genesis_global_state;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

pub mod testrunning;

pub(crate) fn make_plenty_mock_transaction_supported_by_invalid_single_proofs(
    count: usize,
) -> Vec<Transaction> {
    let mut sp_backeds =
        testrunning::make_plenty_mock_transaction_supported_by_primitive_witness(count);
    for pw_backed in &mut sp_backeds {
        pw_backed.proof = TransactionProof::invalid();
    }

    sp_backeds
}

/// Return a list of transactions backed by invalid single proofs where each
/// single proof has a specified size.
pub(crate) fn mock_transactions_with_sized_single_proof(
    count: usize,
    proof_size: ByteSize,
) -> Vec<Transaction> {
    let mut sp_backeds =
        testrunning::make_plenty_mock_transaction_supported_by_primitive_witness(count);
    let proof_size_in_bytes: usize = proof_size.as_u64().try_into().unwrap();
    let proof_size_in_num_bfes = proof_size_in_bytes / BFieldElement::BYTES;
    for sp_backed in &mut sp_backeds {
        sp_backed.proof =
            TransactionProof::SingleProof(Proof::from(vec![bfe!(0); proof_size_in_num_bfes]));
    }

    sp_backeds
}

/// A SingleProof-backed transaction with no inputs or outputs
pub(crate) fn invalid_empty_single_proof_transaction() -> Transaction {
    let tx = make_mock_transaction(vec![], vec![]);
    assert!(matches!(tx.proof, TransactionProof::SingleProof(_)));
    tx
}

/// Make a transaction with `Invalid` transaction proof.
pub fn make_mock_transaction(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
) -> Transaction {
    make_mock_transaction_with_mutator_set_hash(inputs, outputs, Digest::default())
}

pub(crate) fn make_mock_transaction_with_mutator_set_hash_and_timestamp(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
    timestamp: Timestamp,
) -> Transaction {
    Transaction {
        kernel:
            crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy {
                inputs,
                outputs,
                announcements: vec![],
                fee: NativeCurrencyAmount::coins(1),
                timestamp,
                coinbase: None,
                mutator_set_hash,
                merge_bit: false,
            }
            .into_kernel(),
        proof: TransactionProof::invalid(),
    }
}

pub(crate) fn make_mock_transaction_with_mutator_set_hash(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
) -> Transaction {
    let timestamp = Timestamp::now();

    make_mock_transaction_with_mutator_set_hash_and_timestamp(
        inputs,
        outputs,
        mutator_set_hash,
        timestamp,
    )
}

pub(crate) fn make_mock_block_transaction_with_mutator_set_hash(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
) -> BlockTransaction {
    let timestamp = Timestamp::now();

    let transaction = make_mock_transaction_with_mutator_set_hash_and_timestamp(
        inputs,
        outputs,
        mutator_set_hash,
        timestamp,
    );
    BlockTransaction::upgrade(transaction)
}

/// Create a `Transaction` from `TransactionDetails` such that verification
/// seems to pass but without the hassle of producing a proof for it. Behind the
/// scenes, this method updates the true claims cache, such that the call to
/// `triton_vm::verify` will be by-passed.
pub(super) async fn fake_create_transaction_from_details_for_tests(
    transaction_details: crate::api::export::TransactionDetails,
    consensus_rule_set: ConsensusRuleSet,
) -> Transaction {
    let kernel = PrimitiveWitness::from_transaction_details(&transaction_details).kernel;

    let claim = single_proof_claim(kernel.mast_hash(), consensus_rule_set);
    cache_true_claims([claim.clone()]).await;

    Transaction {
        kernel,
        proof: TransactionProof::SingleProof(Proof::invalid()),
    }
}

/// Merge two transactions for tests, resulting in a [`BlockTrasnaction`],
/// without the hassle of proving but such that the result seems valid.
pub(super) async fn fake_merge_block_transactions_for_tests(
    lhs: BlockOrRegularTransaction,
    rhs: Transaction,
    shuffle_seed: [u8; 32],
    consensus_rule_set: ConsensusRuleSet,
) -> anyhow::Result<BlockTransaction> {
    assert!(
        lhs.proof().is_single_proof(),
        "Argument2 must be single-proof-backed transaction"
    );
    assert!(
        rhs.proof.is_single_proof(),
        "Argument2 must be single-proof-backed transaction"
    );

    let merge_witness = MergeWitness::for_composition(lhs, rhs, shuffle_seed);
    let new_kernel = merge_witness.new_kernel.clone();

    let claim = single_proof_claim(new_kernel.mast_hash(), consensus_rule_set);
    cache_true_claims([claim]).await;

    Ok(BlockTransaction {
        kernel: new_kernel.try_into().unwrap(),
        proof: TransactionProof::SingleProof(Proof::invalid()),
    })
}

/// Return a valid, deterministic transaction with a specified proof type.
/// Returned transaction is synced to the genesis block.
pub(crate) async fn genesis_tx_with_proof_type(
    proof_type: TxProvingCapability,
    network: Network,
    fee: NativeCurrencyAmount,
) -> std::sync::Arc<Transaction> {
    let genesis_block = Block::genesis(network);
    let bob_wallet_secret = WalletEntropy::devnet_wallet();
    let bob_spending_key = bob_wallet_secret.nth_generation_spending_key_for_tests(0);
    let bob = mock_genesis_global_state(
        2,
        bob_wallet_secret.clone(),
        cli_args::Args::default_with_network(network),
    )
    .await;
    let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
    let config = TxCreationConfig::default()
        .recover_change_on_chain(bob_spending_key.into())
        .with_prover_capability(proof_type);

    let consensus_rule_set = ConsensusRuleSet::infer_from(network, BlockHeight::genesis());

    let transaction = bob
        .api()
        .tx_initiator_internal()
        .create_transaction(
            Vec::<TxOutput>::new().into(),
            fee,
            in_seven_months,
            config,
            consensus_rule_set,
        )
        .await
        .unwrap()
        .transaction;

    transaction
}

/// Send coins to somewhere.
///
/// Make the transaction. Update state accordingly. Return the
/// transaction. Fee in returned transaction is set to zero.
///
/// Notifies wallet of expected incoming UTXOs.
pub(crate) async fn send_coins(
    sender: &mut GlobalStateLock,
    outputs: impl IntoIterator<Item = impl Into<OutputFormat>>,
    timestamp: Timestamp,
) -> Transaction {
    let outputs = sender
        .api()
        .tx_initiator()
        .generate_tx_outputs(outputs)
        .await;
    let utxos_sent_to_self = sender
        .lock_guard()
        .await
        .wallet_state
        .extract_expected_utxos(outputs.iter(), UtxoNotifier::Myself);

    sender
        .lock_guard_mut()
        .await
        .wallet_state
        .add_expected_utxos(utxos_sent_to_self)
        .await;

    let amount = outputs.total_native_coins();
    let selected_inputs = sender
        .api()
        .tx_initiator()
        .select_inputs(
            InputSelectionPolicy::from(InputSelectionPriority::ByProvidedOrder),
            amount,
            timestamp,
        )
        .await;
    let unlocked_inputs = sender
        .lock_guard()
        .await
        .unlock_inputs(selected_inputs)
        .await;
    let transaction_details = TransactionDetailsBuilder::default()
        .inputs(unlocked_inputs)
        .outputs(outputs)
        .change_policy(ChangePolicy::RecoverToNextUnusedKey {
            key_type: KeyType::Symmetric,
            medium: UtxoNotificationMedium::OnChain,
        })
        .timestamp(timestamp)
        .build(&mut StateLock::Lock(Box::new(sender.clone())))
        .await
        .unwrap();

    let primitive_witness_proof = sender
        .api()
        .tx_initiator()
        .generate_witness_proof(transaction_details.into());
    let primitive_witness = primitive_witness_proof.into_primitive_witness();

    println!(
        "primitive witness has public announcements? (global state) {}",
        !primitive_witness.kernel.announcements.is_empty()
    );
    let kernel = primitive_witness.kernel;

    Transaction {
        kernel,
        proof: TransactionProof::invalid(),
    }
}
