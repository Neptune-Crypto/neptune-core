use anyhow::bail;
use tasm_lib::prelude::Digest;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::validity::neptune_proof::Proof;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::verifier::cache_true_claim;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

pub mod testrunning;

pub(crate) fn make_plenty_mock_transaction_supported_by_invalid_single_proofs(
    count: usize,
) -> Vec<Transaction> {
    let mut pw_backeds =
        testrunning::make_plenty_mock_transaction_supported_by_primitive_witness(count);
    for pw_backed in &mut pw_backeds {
        pw_backed.proof = TransactionProof::invalid();
    }

    pw_backeds
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
                public_announcements: vec![],
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
