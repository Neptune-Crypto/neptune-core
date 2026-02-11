mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::tx_initiation::consolidate::CONSOLIDATION_FEE_SP;
use num_traits::ops::checked::CheckedSub;
use num_traits::Zero;
use tracing_test::traced_test;

/// test: basic consolidation
///
/// Scenario:
///
///  1. Alice and Bob run 2-node regtest network, from genesis.
///  2. Alice and both each have no funds initially.
///  3. Bob generates a receiving address and provides to Alice (out of band).
///  4. Alice mines 3 blocks to her own wallet.
///  5. Alice consolidates her 3 liquid to Bob's address
///  6. Bob verifies the unconfirmed balance matches consolidation amount.
///
#[tokio::test(flavor = "multi_thread")]
#[traced_test]
pub async fn consolidation_basic() {
    logging::tracing_logger();
    let timeout_secs = 5;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability =
        Some(neptune_cash::api::export::TxProvingCapability::SingleProof);

    // alice and bob start 2 peer cluster (regtest)
    let [mut alice, mut bob] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(),
        2,
        Some(base_args),
        timeout_secs,
    )
    .await
    .unwrap();

    // bob generates receiving address
    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await
        .unwrap();

    // alice mines 3 blocks to her wallet
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await
        .unwrap();

    tracing::info!("alice mined 3 blocks!");

    // wait 5 seconds to allow block to propagate to bob's node.
    // otherwise bob's node might receive the Tx before accepting the latest block
    // in which case it will reject it.  see issue 560
    // https://github.com/Neptune-Crypto/neptune-core/issues/560
    // when that is fixed, this line should be removed.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // alice checks that payment is reflected in her unconfirmed wallet balance
    let alice_balances_before_consolidation =
        alice.gsl.api().wallet().balances(Timestamp::now()).await;
    tracing::info!(
        "Alice's balances before consolidation:\n{}",
        alice_balances_before_consolidation
    );

    assert_eq!(
        alice
            .gsl
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height,
        3u64.into()
    );

    // Alice consolidates
    let num_consolidations = alice
        .gsl
        .api_mut()
        .tx_initiator_mut()
        .consolidate(Some(3), Some(bob_address), Timestamp::now())
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

    bob.wait_until_block_height(4, timeout_secs).await.unwrap();

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
