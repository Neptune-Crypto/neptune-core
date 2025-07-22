use anyhow::bail;
use bytesize::ByteSize;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::bfe;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Network;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
use crate::api::export::TxProvingCapability;
use crate::config_models::cli_args;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::validity::neptune_proof::Proof;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::verifier::cache_true_claim;
use crate::models::state::tx_creation_config::TxCreationConfig;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::wallet_entropy::WalletEntropy;
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
            crate::models::blockchain::transaction::transaction_kernel::TransactionKernelProxy {
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

/// Create a `Transaction` from `TransactionDetails` such that verification
/// seems to pass but without the hassle of producing a proof for it. Behind the
/// scenes, this method updates the true claims cache, such that the call to
/// `triton_vm::verify` will be by-passed.
pub(super) async fn fake_create_transaction_from_details_for_tests(
    transaction_details: crate::api::export::TransactionDetails,
) -> Transaction {
    let kernel = PrimitiveWitness::from_transaction_details(&transaction_details).kernel;

    let claim = SingleProof::claim(kernel.mast_hash());
    cache_true_claim(claim.clone()).await;

    Transaction {
        kernel,
        proof: TransactionProof::SingleProof(Proof::invalid()),
    }
}

/// Merge two transactions for tests, without the hassle of proving but such
/// that the result seems valid.
pub(super) async fn fake_merge_transactions_for_tests(
    lhs: Transaction,
    rhs: Transaction,
    shuffle_seed: [u8; 32],
) -> anyhow::Result<Transaction> {
    let TransactionProof::SingleProof(lhs_proof) = lhs.proof else {
        bail!("arguments must be bogus singleproof transactions")
    };
    let TransactionProof::SingleProof(rhs_proof) = rhs.proof else {
        bail!("arguments must be bogus singleproof transactions")
    };
    let merge_witness =
        MergeWitness::from_transactions(lhs.kernel, lhs_proof, rhs.kernel, rhs_proof, shuffle_seed);
    let new_kernel = merge_witness.new_kernel.clone();

    let claim = SingleProof::claim(new_kernel.mast_hash());
    cache_true_claim(claim).await;

    Ok(Transaction {
        kernel: new_kernel,
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

    // Clippy is wrong here. You can *not* eliminate the binding.
    #[allow(clippy::let_and_return)]
    let transaction = bob
        .api()
        .tx_initiator_internal()
        .create_transaction(Vec::<TxOutput>::new().into(), fee, in_seven_months, config)
        .await
        .unwrap()
        .transaction;

    transaction
}
