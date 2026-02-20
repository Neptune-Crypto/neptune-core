use crate::protocol::proof_abstractions::tasm::program::ConsensusError;
use crate::protocol::proof_abstractions::SecretWitness;

use std::ops::Deref;

use crate::api::export::TxCreationArtifacts;
use crate::protocol::proof_abstractions::tasm::program::tests::TritonProgramSpecification;
use crate::state::wallet::wallet_state::tests::{bob_mines_one_block, outgoing_transaction};
use crate::state::GlobalStateLock;
use crate::tests::shared::blocks::invalid_block_with_transaction;
use crate::tests::shared::Randomness;
use futures::FutureExt;
use num_traits::CheckedSub;
use proptest::prop_assert;
use proptest::test_runner::RngSeed;
use rand::Rng;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

/// Helper function to set up a wallet with funds, create an outgoing transaction, and mine it in a block.
/// `spend_percent` tells what will be left in the wallet, `fee_percent` is how spend amount is split.
pub async fn setup_funded_wallet_with_mined_tx(
    spend_percent: f64,
    fee_percent: f64,
    rness: Randomness<0, 2>,
) -> (
    TxCreationArtifacts,
    GlobalStateLock,
    crate::api::export::GenerationSpendingKey,
    [crate::protocol::consensus::block::Block; 3],
    MmrAccumulator,
    MmrMembershipProof,
    u64,
) {
    assert!((0.0..=1.0).contains(&spend_percent));
    assert!((0.0..=1.0).contains(&fee_percent));

    let (block_1, mut gs_lock, key) = bob_mines_one_block(Default::default()).await;

    let spend_amount = gs_lock
        .lock_async(|x| x.get_balance_history().boxed())
        .await
        .into_iter()
        .last()
        .unwrap()
        .3
        .lossy_f64_fraction_mul(spend_percent);
    let fee_amount = spend_amount.lossy_f64_fraction_mul(fee_percent);
    let send_amount = spend_amount.checked_sub(&fee_amount).unwrap();

    let tx = outgoing_transaction(
        &mut gs_lock,
        send_amount,
        fee_amount,
        crate::api::export::Timestamp::now(),
        key.into(),
        rness,
    )
    .await
    .expect("Failed to create outgoing transaction");

    // mine the transaction in a block
    let block_with_tx = invalid_block_with_transaction(&block_1, tx.transaction().clone());

    // mine another block after the transaction
    let (block_after, _) = crate::tests::shared::blocks::make_mock_block(
        &block_with_tx,
        None,
        key,
        rand::rng().random(),
        Default::default(),
    )
    .await;

    let output_index: usize = 0;

    let aocl_before = block_1.mutator_set_accumulator_after().unwrap().aocl;
    let aocl_leaf_count_before = aocl_before.num_leafs();
    let target_addition_record = tx.details().tx_outputs.deref()[output_index].addition_record();

    let ms_update = block_with_tx.mutator_set_update().unwrap();
    let position_in_block_additions = ms_update
        .additions
        .iter()
        .position(|ar| *ar == target_addition_record)
        .expect("addition record from tx output must appear in block's mutator set update");
    let aocl_leaf_index = aocl_leaf_count_before + position_in_block_additions as u64;

    let mut witness_aocl = aocl_before.to_accumulator();
    let mut aocl_membership_proof: Option<MmrMembershipProof> = None;
    for (i, addition_record) in ms_update.additions.iter().enumerate() {
        let mp = witness_aocl.append(addition_record.canonical_commitment);
        if i == position_in_block_additions {
            aocl_membership_proof = Some(mp);
        }
    }
    let aocl_membership_proof = aocl_membership_proof.unwrap();

    (
        tx,
        gs_lock,
        key,
        [block_1, block_with_tx, block_after],
        witness_aocl,
        aocl_membership_proof,
        aocl_leaf_index,
    )
}

#[test_strategy::proptest(
    async = "tokio", 
    // cases = 2, 
    rng_seed = RngSeed::Fixed(0)
)]
async fn property_test_happy_path(
    #[strategy(0.0..=1.0)] spend_percent: f64,
    #[strategy(0.0..=1.0)] fee_percent: f64,
    #[strategy(proptest_arbitrary_interop::arb())] rness: Randomness<0, 2>,
) {
    let (tx, _gs_lock, _key, [_, _bl, _], aocl, aocl_mp, aocl_leaf_index) =
        setup_funded_wallet_with_mined_tx(spend_percent, fee_percent, rness).await;

    let tx_output = &tx.details.tx_outputs.deref()[0];
    let sender_randomness = tx_output.sender_randomness();
    let utxo = tx_output.utxo();
    let claim = super::claim_outputs(
        super::claim_inputs(
            tasm_lib::triton_vm::proof::Claim::new(super::hash()),
            tx_output.receiver_digest(),
            Default::default(),
        ),
        sender_randomness.hash(),
        aocl.bag_peaks(),
        utxo.lock_script_hash(),
        tx_output.native_currency_amount(),
    );
    let sent = super::ProofOfTransfer::new(
        claim.clone(),
        aocl.clone(),
        sender_randomness,
        aocl_leaf_index,
        utxo.clone(),
        aocl_mp,
    );
    // **A lib used doesn't have a Rust shadow.**
    // sent.assert_both_rust_tasm_returns_the_output(&sent);
    let t = &sent
        .run_tasm(&sent.standard_input(), sent.nondeterminism())
        .unwrap_or_else(|e| match e {
            ConsensusError::RustShadowPanic(rsp) => {
                panic!("Tasm run failed due to rust shadow panic (?): {rsp}");
            }
            ConsensusError::TritonVMPanic(err, instruction_error) => {
                panic!("Tasm run failed due to VM panic: {instruction_error}:\n{err}");
            }
        });
    assert!(
        &claim.output.eq(t),
        "Triton output was different\n{t:?}|run output\n{:?}|claim output",
        claim.output
    )
}

// Consolidated negative test: AOCL proof verification failure.
#[test_strategy::proptest(
    async = "tokio", 
    // cases = 2, 
    rng_seed = RngSeed::Fixed(0)
)]
async fn aocl_proof_verification_failed(
    #[strategy(0.0..=1.0)] spend_percent: f64,
    #[strategy(0.0..=1.0)] fee_percent: f64,
    #[strategy(proptest_arbitrary_interop::arb())] rness: Randomness<0, 2>,
    #[strategy(proptest_arbitrary_interop::arb())] aocl_mp_bad: MmrMembershipProof,
) {
    // Set up a valid witness/claim using the same helper as the happy path.
    let (tx, _wallet, _key, [_, _bl, _], aocl, aocl_mp, aocl_leaf_index) =
        setup_funded_wallet_with_mined_tx(spend_percent, fee_percent, rness).await;

    let tx_output = &tx.details.tx_outputs.deref()[0];
    let sender_randomness = tx_output.sender_randomness();
    let utxo = tx_output.utxo();

    let claim = super::claim_outputs(
        super::claim_inputs(
            tasm_lib::triton_vm::proof::Claim::new(super::hash()),
            tx_output.receiver_digest(),
            Default::default(),
        ),
        sender_randomness.hash(),
        aocl.bag_peaks(),
        utxo.lock_script_hash(),
        tx_output.native_currency_amount(),
    );

    let mut sent = super::ProofOfTransfer::new(
        claim.clone(),
        aocl.clone(),
        sender_randomness,
        aocl_leaf_index,
        utxo.clone(),
        aocl_mp,
    );

    proptest::prop_assume!(
        aocl_mp_bad != sent.0.aocl_membership_proof,
        "The 'bad' AOCL membership proof must actually be invalid for the test to be meaningful"
    );
    sent.0.aocl_membership_proof = aocl_mp_bad;

    // Run the program and expect a Triton VM panic with AOCL proof verification error id.
    if let Err(ConsensusError::TritonVMPanic(
        _,
        tasm_lib::triton_vm::error::InstructionError::AssertionFailed(inner),
    )) = sent.run_tasm(&sent.standard_input(), sent.nondeterminism())
    {
        proptest::prop_assert_eq![
            inner.id,
            Some(super::ERROR_AOCL_PROOF_VERIFICATION_FAILED),
            "Expected Triton VM error id {}, got: {:?}",
            super::ERROR_AOCL_PROOF_VERIFICATION_FAILED,
            inner.id
        ]
    } else {
        prop_assert!(
            false,
            "the program was expected to fail in the particular way"
        )
    };
}
