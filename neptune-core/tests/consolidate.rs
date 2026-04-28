mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use itertools::Itertools;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::TransactionProofType;
use neptune_cash::api::tx_initiation::consolidate::CONSOLIDATION_FEE_SP;
use neptune_cash::api::tx_initiation::consolidate::NUM_CONFIRMATIONS_REQUIRED_FOR_CONSOLIDATION;
use num_traits::ops::checked::CheckedSub;
use num_traits::Zero;
use tracing_test::traced_test;

/// Return a connected cluster where the Alice node has mining rewards.
///
/// Must be called with a unique test ID to avoid multiple tests requesting the
/// same ports from the OS, when tests run in parallel.
async fn wallet_with_mining_rewards(num_blocks: u32, test_id: u8) -> (GenesisNode, GenesisNode) {
    let timeout_secs = 5;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability =
        Some(neptune_cash::api::export::TxProvingCapability::SingleProof);

    let [mut alice, bob] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(Some(test_id)),
        2,
        Some(base_args),
        timeout_secs,
    )
    .await
    .unwrap();

    // alice mines a ton of blocks to her wallet
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(num_blocks, false)
        .await
        .unwrap();

    tracing::info!("alice mined a ton of blocks!");

    // wait 5 seconds to allow block to propagate to bob's node.
    // otherwise bob's node might receive the Tx before accepting the latest block
    // in which case it will reject it.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    (alice, bob)
}

/// test: basic consolidation
///
/// Scenario:
///
///  1. Alice and Bob run 2-node regtest network, from genesis.
///  2. Alice and both each have no funds initially.
///  3. Bob generates a receiving address and provides to Alice (out of band).
///  4. Alice mines a ton of blocks to her own wallet.
///  5. Alice consolidates 3 of her liquid to Bob's address
///  6. Bob verifies the unconfirmed balance matches consolidation amount.
///
#[tokio::test(flavor = "multi_thread")]
#[traced_test]
pub async fn consolidation_basic() {
    logging::tracing_logger();
    let timeout_secs = 5;

    let num_blocks_mined = 3 + NUM_CONFIRMATIONS_REQUIRED_FOR_CONSOLIDATION as u32;
    let (mut alice, mut bob) = wallet_with_mining_rewards(num_blocks_mined, 0).await;

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await
        .unwrap();

    // alice checks that payment is reflected in her unconfirmed wallet balance
    let alice_balances_before_consolidation =
        alice.gsl.api().wallet().balances(Timestamp::now()).await;
    tracing::info!(
        "Alice's balances before consolidation:\n{}",
        alice_balances_before_consolidation
    );

    assert_eq!(
        alice.gsl.lock_guard().await.chain.tip().header().height,
        u64::from(num_blocks_mined).into()
    );

    // Alice consolidates 3 of her UTXOs
    let accept_lustrations = true;
    let max_num_inputs = 3;
    let num_consolidations = alice
        .gsl
        .api_mut()
        .tx_initiator_mut()
        .consolidate(
            max_num_inputs,
            Some(bob_address),
            Timestamp::now(),
            accept_lustrations,
        )
        .await
        .unwrap();

    tracing::info!(
        "consolidation tx initiated! {} UTXOs consolidated",
        num_consolidations
    );

    // alice checks that payment is reflected in her unconfirmed wallet balance (only)
    let alice_balances_after_consolidation =
        alice.gsl.api().wallet().balances(Timestamp::now()).await;
    let fee = CONSOLIDATION_FEE_SP;

    // Actually, "32 coins" contains some (barely noticeable) error due to
    // floating point multiplication when dividing the block subsidy between
    // the composer and guesser.
    let amount_per_utxo = NativeCurrencyAmount::coins(32);
    let consolidation_amount = (amount_per_utxo
        .checked_scalar_mul(num_consolidations as u32)
        .unwrap())
    .checked_sub(&fee)
    .unwrap();

    tracing::info!(
        "alice balances after consolidation:\n{}",
        alice_balances_after_consolidation
    );

    assert_eq!(
        alice_balances_after_consolidation.confirmed_available,
        alice_balances_before_consolidation.confirmed_available
    );

    // Bob checks balances are still zero.
    let bob_balances_before = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert!(bob_balances_before.unconfirmed_available.is_zero());
    assert!(bob_balances_before.confirmed_available.is_zero());

    // bob waits until he has an unconfirmed balance discrepancy
    // indicating the tx has arrived in his mempool.
    bob.wait_until_unconfirmed_balance(timeout_secs)
        .await
        .unwrap();

    // bob checks balances are correct.
    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;

    // compare strings to correct for rounding errors
    assert_eq!(
        bob_balances.unconfirmed_available.to_string(),
        consolidation_amount.to_string(),
        "unconfirmed balance: {} ; consolidation amount: {consolidation_amount}",
        bob_balances.unconfirmed_available
    );
    assert!(bob_balances.confirmed_available.is_zero());

    // alice mines another block to her wallet
    let include_mempool_txs = true;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await
        .unwrap();

    // Block contains 3 announcements: 2 for the composer UTXOs and one for the
    // consolidation.
    let num_announcements_observed = alice
        .gsl
        .lock_guard()
        .await
        .chain
        .tip()
        .body()
        .transaction_kernel()
        .announcements
        .len();
    assert_eq!(3, num_announcements_observed);

    // alice checks that confirmed and unconfirmed balances are equal.
    let alice_balances_after_confirmed = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    println!(
        "alice balances after confirmed:\n{}",
        alice_balances_after_confirmed
    );
    assert_eq!(
        alice_balances_after_confirmed.confirmed_available,
        alice_balances_after_confirmed.unconfirmed_available
    );

    bob.wait_until_block_height(u64::from(num_blocks_mined + 1), timeout_secs)
        .await
        .unwrap();

    // bob checks payment is reflected in his confirmed wallet balance
    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    // compare strings to correct for rounding errors
    assert_eq!(
        bob_balances.confirmed_available.to_string(),
        consolidation_amount.to_string()
    );
    assert_eq!(
        bob_balances.unconfirmed_available.to_string(),
        consolidation_amount.to_string()
    );
}

#[tokio::test(flavor = "multi_thread")]
#[traced_test]
pub async fn consolidation_tx_with_lustration() {
    // Verify that consolidation transactions are correctly lustrated, and that
    // peers accept lustrated transactions into their mempools.
    logging::tracing_logger();

    let num_blocks_mined = 20;
    let (mut alice, bob) = wallet_with_mining_rewards(num_blocks_mined, 1).await;
    assert_eq!(
        alice.gsl.lock_guard().await.chain.tip_height(),
        u64::from(num_blocks_mined).into()
    );
    assert_eq!(
        bob.gsl.lock_guard().await.chain.tip_height(),
        u64::from(num_blocks_mined).into()
    );

    let lustration_status_before = alice
        .gsl
        .lock_guard()
        .await
        .chain
        .lustration_status()
        .expect("Test assumption: Lustration status is active");

    let accept_lustrations = true;
    let max_num_inputs = 3;
    let _ = alice
        .gsl
        .api_mut()
        .tx_initiator_mut()
        .consolidate(max_num_inputs, None, Timestamp::now(), accept_lustrations)
        .await
        .unwrap();

    let mempool_tx = alice
        .gsl
        .lock_guard()
        .await
        .mempool
        .fee_density_iter()
        .map(|(txid, _)| txid)
        .collect_vec();
    let mempool_tx = alice
        .gsl
        .lock_guard()
        .await
        .mempool
        .get(mempool_tx[0])
        .unwrap()
        .to_owned();
    assert!(mempool_tx
        .kernel
        .announcements
        .iter()
        .any(|ann| ann.looks_like_lustration()));

    let timeout_secs = 10;
    alice
        .wait_until_n_txs_in_mempool(1, TransactionProofType::SingleProof, timeout_secs)
        .await
        .unwrap();

    // Ensure that Bob accepts the lustrating tx into his mempool
    bob.wait_until_n_txs_in_mempool(1, TransactionProofType::SingleProof, timeout_secs)
        .await
        .unwrap();

    let new_block_height = 21;
    let include_mempool_txs = true;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await
        .unwrap();
    alice
        .wait_until_block_height(new_block_height, timeout_secs)
        .await
        .unwrap();

    bob.wait_until_block_height(new_block_height, timeout_secs)
        .await
        .unwrap();

    let lustration_status_after = alice
        .gsl
        .lock_guard()
        .await
        .chain
        .lustration_status()
        .expect("Test assumption: Lustration status is active");

    // Off by small deviation because of floting point error when dividing
    // block subsidy between composer and guesser.
    let expected_input_amount =
        NativeCurrencyAmount::coins(32).scalar_mul(max_num_inputs.try_into().unwrap());
    let epsilon = NativeCurrencyAmount::from_nau(NativeCurrencyAmount::coin_as_nau() / 10_000);
    let upper_limit = lustration_status_before
        .counter
        .checked_sub(&expected_input_amount)
        .unwrap()
        + epsilon;
    let lower_limit = lustration_status_before
        .counter
        .checked_sub(&expected_input_amount)
        .unwrap()
        .checked_sub(&epsilon)
        .unwrap();
    assert!(
        upper_limit > lustration_status_after.counter
            && lower_limit < lustration_status_after.counter,
        "New lustration counter match previous minus lustrated amount"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[traced_test]
pub async fn merge_consolidation_txs() {
    // check the the proof upgrading automatically merges two consolidation
    // transactions into one.
    logging::tracing_logger();
    let timeout_secs = 5;

    let num_blocks_mined = 23;
    let (mut alice, mut bob) = wallet_with_mining_rewards(num_blocks_mined, 2).await;

    assert_eq!(
        alice.gsl.lock_guard().await.chain.tip().header().height,
        u64::from(num_blocks_mined).into()
    );
    assert_eq!(
        bob.gsl.lock_guard().await.chain.tip().header().height,
        u64::from(num_blocks_mined).into()
    );

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await
        .unwrap();

    // Alice consolidates 3 UTXOs, twice
    for _ in 0..=1 {
        let accept_lustrations = true;
        let max_num_inputs = 3;
        let _ = alice
            .gsl
            .api_mut()
            .tx_initiator_mut()
            .consolidate(
                max_num_inputs,
                Some(bob_address.clone()),
                Timestamp::now(),
                accept_lustrations,
            )
            .await
            .unwrap();
    }

    // Give Alice time to broadcast single proof transaction
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    alice
        .wait_until_n_txs_in_mempool(1, TransactionProofType::SingleProof, timeout_secs)
        .await
        .unwrap();
    bob.wait_until_n_txs_in_mempool(1, TransactionProofType::SingleProof, timeout_secs)
        .await
        .unwrap();

    // Mine transaction, that's the merger of two consolidation txs
    let include_mempool_txs = true;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await
        .unwrap();

    let num_inputs_observed = alice
        .gsl
        .lock_guard()
        .await
        .chain
        .tip()
        .body()
        .transaction_kernel()
        .inputs
        .len();
    assert_eq!(
        6, num_inputs_observed,
        "The two consolidation transactions must have been merged."
    );
}
