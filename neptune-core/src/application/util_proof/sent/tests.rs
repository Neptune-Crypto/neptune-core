use crate::protocol::proof_abstractions::SecretWitness;
use crate::protocol::proof_abstractions::tasm::program::ConsensusError;

use std::ops::Deref;

use crate::api::export::{NativeCurrencyAmount, TxCreationArtifacts};
use crate::protocol::consensus::block::INITIAL_BLOCK_SUBSIDY;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
use crate::state::GlobalStateLock;
use crate::state::wallet::wallet_state::tests::{bob_mines_one_block, outgoing_transaction};
use crate::tests::shared::Randomness;
use crate::tests::shared::blocks::invalid_block_with_transaction;
use crate::tests::shared_tokio_runtime;
use num_traits::CheckedSub;
use proptest::test_runner::RngSeed;
use proptest_arbitrary_interop::arb;
use rand::Rng;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

/// Helper function to set up a wallet with funds, create an outgoing transaction, and mine it in a block.
/// Returns (transaction, wallet_with_funds, spending_key, [genesis_block, block_with_tx, block_after_tx]).
/// spend is the percentage of `INITIAL_BLOCK_SUBSIDY` to send, `fee` is how that spend `amount` is split.
pub async fn setup_funded_wallet_with_mined_tx(
    spend_percent: f64,
    fee_percent: f64,
    // network: Network,
    rness: Randomness<0, 2>
    // sender_randomness: tasm_lib::prelude::Digest
) -> (
    TxCreationArtifacts,
    GlobalStateLock,
    crate::api::export::GenerationSpendingKey,
    [crate::protocol::consensus::block::Block; 3],
    MmrAccumulator,
    MmrMembershipProof,
    u64,
) {
    assert!(spend_percent >= 0.0 && spend_percent <= 1.0);
    assert!(fee_percent >= 0.0 && fee_percent <= 1.0);
    let total_amount = INITIAL_BLOCK_SUBSIDY.lossy_f64_fraction_mul(spend_percent);
    let fee_amount = total_amount.lossy_f64_fraction_mul(fee_percent);
    let send_amount = total_amount.checked_sub(&fee_amount).unwrap();

    let (block_1, mut wallet, key) = bob_mines_one_block(
        // network
        Default::default(),
    ).await;
    
    let tx = outgoing_transaction(
        &mut wallet,
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
    ).await;

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
        wallet,
        key,
        [block_1, block_with_tx, block_after],
        witness_aocl,
        aocl_membership_proof,
        aocl_leaf_index,
    )
}

// #[test]
// fn smoke() {super::library_and_code();}

// TODO tune `cases` but the single speeds up the development
#[test_strategy::proptest(async = "tokio", cases = 1, rng_seed = RngSeed::Fixed(0))]
async fn property_test_happy_path(
    #[strategy(0.0..=1.0)] spend_percent: f64,
    #[strategy(0.0..=1.0)] fee_percent: f64,
    // #[strategy(0.1..=1.0)] spend_percent: f64,
    // #[strategy(0.1..=1.0)] fee_percent: f64,
    #[strategy(proptest_arbitrary_interop::arb())] rness: Randomness<0, 2>,
) {
    // let receiver =
    //     crate::state::wallet::address::address_the_generation::ReceivingAddressForTheGeneration::derive_from_seed(rness.digests[0]);
    // let sender_randomness = rness.digests[1];
    let (tx, _wallet, _key, [_, _bl, _], aocl, aocl_mp, aocl_leaf_index) =
        setup_funded_wallet_with_mined_tx(spend_percent, fee_percent, rness).await;
    // let tx = TransactionKernelProxy::from(tx);

    // dbg![tx.details.tx_outputs.deref().len()];
    let tx_output = &tx.details.tx_outputs.deref()[0];
    let sender_randomness = tx_output.sender_randomness();
    let utxo = tx_output.utxo();
    // dbg![tasm_lib::triton_vm::prelude::BFieldCodec::encode(&utxo.coins().to_owned())];
    // dbg![tasm_lib::triton_vm::prelude::BFieldCodec::encode(&utxo).len()];
    dbg![tasm_lib::triton_vm::prelude::BFieldCodec::encode(&utxo)];
    dbg!("the proof data: start");
    let claim = super::claim_outputs(
        super::claim_inputs(
            tasm_lib::triton_vm::proof::Claim::new(super::hash()),
            tx_output.receiver_digest(),
            Default::default(),
        ),
        sender_randomness.hash(),
        Mmr::bag_peaks(&aocl),
        utxo.lock_script_hash(),
        tx_output.native_currency_amount(),
    );
    let sent = super::new(
        claim.clone(),
        aocl.clone(),
        sender_randomness,
        aocl_leaf_index,
        utxo.clone(),
        aocl_mp,
    );
    dbg!("the proof data: finish");
    // No Rust shadow for a lib used.
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

// impl rand::distr::Distribution<PercentageDecimal> for rand::distr::StandardUniform
// {
//     fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> PercentageDecimal {
//         PercentageDecimal::from(rng.gen_range(0.0..=1.0))
//     }
// }
