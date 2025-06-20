mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::SymmetricKey;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::TxProvingCapability;
use num_traits::ops::checked::CheckedSub;
use num_traits::Zero;

/// test: alice sends funds to herself onchain
///
/// this is a basic test that block generation and
/// a simple payment works without error.
///
/// scenario:
/// 1. single unconnected node on regtest network
/// 2. alice mine's 3 blocks to her own wallet.
/// 3. alice sends a payment to herself.
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_sends_to_self() -> anyhow::Result<()> {
    logging::tracing_logger();

    // start alice's node, without any peers.
    let mut alice = GenesisNode::start_default_node().await?;

    // alice generates receiving address
    let alice_address = alice
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    // alice mines 3 blocks to her wallet
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    tracing::info!("alice mined 3 blocks!");

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

    // alice sends a payment to herself
    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(alice_address, NativeCurrencyAmount::coins_from_str("2.45")?)],
            Default::default(),
            NativeCurrencyAmount::zero(),
            Timestamp::now(),
        )
        .await?;

    tracing::info!("tx sent! {}", tx_artifacts);

    Ok(())
}

/// test: alice sends funds to bob onchain with primitive witness capability
///
/// see description of alice_sends_to_bob() for details
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_sends_to_bob_with_primitive_witness_capability() -> anyhow::Result<()> {
    alice_sends_to_bob(
        &GenesisNode::cluster_id(),
        TxProvingCapability::PrimitiveWitness,
    )
    .await
}

/// test: alice sends funds to bob onchain with proof collection capability
///
/// see description of alice_sends_to_bob() for details
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_sends_to_bob_with_proof_collection_capability() -> anyhow::Result<()> {
    alice_sends_to_bob(
        &GenesisNode::cluster_id(),
        TxProvingCapability::PrimitiveWitness,
    )
    .await
}

/// test: alice sends funds to bob onchain with single proof capability
///
/// see description of alice_sends_to_bob() for details
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_sends_to_bob_with_single_proof_capability() -> anyhow::Result<()> {
    alice_sends_to_bob(
        &GenesisNode::cluster_id(),
        TxProvingCapability::PrimitiveWitness,
    )
    .await
}

/// test: alice sends funds to bob onchain
///
/// this is a basic test of:
///  * peer connectivity
///  * block generation
///  * block propagation between nodes
///  * transaction initiation
///  * transaction propagation between nodes
///  * receipt of payment on remote node
///
/// scenario:
/// 1. alice and bob run 2-node regtest network, from genesis.
/// 2. alice and both each have no funds initially.
/// 3. bob generates a receiving address and provides to alice (out of band).
/// 4. alice mines 3 blocks to her own wallet.
/// 5. alice sends a payment to bob.
/// 6. bob verifies the unconfirmed balance matches payment amount.
pub async fn alice_sends_to_bob(
    cluster_id: &str,
    proving_capability: TxProvingCapability,
) -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 5;

    let mut base_args = GenesisNode::default_args();
    base_args.tx_proving_capability = Some(proving_capability);

    // alice and bob start 2 peer cluster (regtest)
    let [mut alice, mut bob] =
        GenesisNode::start_connected_cluster(cluster_id, 2, Some(base_args), timeout_secs).await?;

    // bob generates receiving address
    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    // alice mines 3 blocks to her wallet
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    tracing::info!("alice mined 3 blocks!");

    // wait 5 seconds to allow block to propagate to bob's node.
    // otherwise bob's node might receive the Tx before accepting the latest block
    // in which case it will reject it.  see issue 560
    // https://github.com/Neptune-Crypto/neptune-core/issues/560
    // when that is fixed, this line should be removed.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // alice checks that payment is reflected in her unconfirmed wallet balance
    let alice_balances_before_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    tracing::info!(
        "alice balances before send:\n{}",
        alice_balances_before_send
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

    // alice sends a payment to bob
    let payment_amount = NativeCurrencyAmount::coins_from_str("2.45")?;
    let fee_amount = NativeCurrencyAmount::coins_from_str("0.01")?;
    let alice_spend_amount = payment_amount + fee_amount;
    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address, payment_amount)],
            Default::default(),
            fee_amount,
            Timestamp::now(),
        )
        .await?;

    tracing::info!("tx sent! {}", tx_artifacts);

    // alice checks that payment is reflected in her unconfirmed wallet balance (only)
    let alice_balances_after_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;

    tracing::info!("alice balances after send:\n{}", alice_balances_after_send);
    tracing::info!("alice spend_amount:\n{}", alice_spend_amount);

    assert_eq!(
        alice_balances_after_send.confirmed_available,
        alice_balances_before_send.confirmed_available
    );
    assert_eq!(
        alice_balances_after_send.unconfirmed_available,
        alice_balances_after_send
            .confirmed_available
            .checked_sub(&alice_spend_amount)
            .unwrap()
    );

    // bob waits until he has an unconfirmed balance discrepancy
    // indicating the tx has arrived in his mempool.
    bob.wait_until_unconfirmed_balance(timeout_secs).await?;

    // alice waits until tx has been upgraded to single-proof in mempool
    // which is necessary before it can be included in a block.
    alice
        .wait_until_tx_in_mempool_has_single_proof(tx_artifacts.transaction().txid(), timeout_secs)
        .await?;

    // bob checks balances are correct.
    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(bob_balances.unconfirmed_available, payment_amount);
    assert!(bob_balances.confirmed_available.is_zero());

    // alice mines another block to her wallet
    let include_mempool_txs = true;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await?;

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

    bob.wait_until_block_height(4, timeout_secs).await?;

    // bob checks payment is reflected in his confirmed wallet balance
    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(bob_balances.confirmed_available, payment_amount);
    assert_eq!(bob_balances.unconfirmed_available, payment_amount);

    Ok(())
}

/// test: alice sends funds to random key.
///
/// this test is essentially a copy of alice_sends_to_bob()
/// but uses a single node instead of two.
///
/// This simplifies the scenario and the logged output.
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_sends_to_random_key() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 5;

    // alice starts a single node cluster
    let [mut alice] =
        GenesisNode::start_connected_cluster(&GenesisNode::cluster_id(), 1, None, timeout_secs)
            .await?;

    // alice generates a random symmetric key outside her wallet.
    let other_address = SymmetricKey::from_seed(rand::random());

    // alice mines 3 blocks to her wallet
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    tracing::info!("alice mined 3 blocks!");

    // alice checks that she received some funds from mining efforts.
    let alice_balances_before_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    tracing::info!(
        "alice balances before send:\n{}",
        alice_balances_before_send
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

    // alice sends a payment to the random key's "address".
    let payment_amount = NativeCurrencyAmount::coins_from_str("2.45")?;
    let fee_amount = NativeCurrencyAmount::coins_from_str("0.01")?;
    let alice_spend_amount = payment_amount + fee_amount;
    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(other_address.into(), payment_amount)],
            Default::default(),
            fee_amount,
            Timestamp::now(),
        )
        .await?;

    tracing::info!("tx sent! {}", tx_artifacts);

    // alice checks that payment is reflected in her unconfirmed wallet balance (only)
    let alice_balances_after_send = alice.gsl.api().wallet().balances(Timestamp::now()).await;

    tracing::info!("alice balances after send:\n{}", alice_balances_after_send);
    tracing::info!("alice spend_amount:\n{}", alice_spend_amount);

    assert_eq!(
        alice_balances_after_send.confirmed_available,
        alice_balances_before_send.confirmed_available
    );
    assert_eq!(
        alice_balances_after_send.unconfirmed_available,
        alice_balances_after_send
            .confirmed_available
            .checked_sub(&alice_spend_amount)
            .unwrap()
    );

    // after send() the tx in mempool initially has PrimitiveWitness proof
    // so we must wait until it has been upgraded to SingleProof
    // before it can be included in a block.
    //
    // another option would be to provide the single proof ourselves.
    alice
        .wait_until_tx_in_mempool_has_single_proof(tx_artifacts.transaction().txid(), timeout_secs)
        .await?;

    // alice mines another block to her wallet.
    let include_mempool_txs = true;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await?;

    // alice checks that confirmed and unconfirmed balances are now equal.
    let alice_balances_after_confirmed = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    tracing::info!(
        "alice balances after confirmed:\n{}",
        alice_balances_after_confirmed
    );

    assert_eq!(
        alice_balances_after_confirmed.confirmed_total.to_string(),
        alice_balances_after_confirmed.unconfirmed_total.to_string()
    );
    assert_eq!(
        (alice_balances_after_send.unconfirmed_total
            + NativeCurrencyAmount::coins(128)
            + fee_amount)
            .to_string(),
        alice_balances_after_confirmed.confirmed_total.to_string(),
    );

    Ok(())
}
