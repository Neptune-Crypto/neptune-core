mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Timestamp;

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
        .mine_regtest_blocks_to_wallet(3)
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
    let tx_creation_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(alice_address, NativeCurrencyAmount::coins_from_str("2.45")?)],
            Default::default(),
            0.into(),
            Timestamp::now(),
        )
        .await?;

    tracing::info!("tx sent! {}", tx_creation_artifacts);

    Ok(())
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
/// 3. bob generates a receiving address and provides to alice.
/// 4. alice mine's 3 blocks to her own wallet.
/// 5. alice sends a payment to bob.
/// 6. bob verifies the unconfirmed balance matches payment amount.
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_sends_to_bob() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 5;

    // alice and bob start 2 peer cluster (regtest)
    let [mut alice, mut bob] =
        GenesisNode::start_connected_cluster(&GenesisNode::cluster_id(), 2, timeout_secs).await?;

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
        .mine_regtest_blocks_to_wallet(3)
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

    // alice sends a payment to bob
    let payment_amount = NativeCurrencyAmount::coins_from_str("2.45")?;
    let tx_creation_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address, payment_amount)],
            Default::default(),
            0.into(),
            Timestamp::now(),
        )
        .await?;

    tracing::info!("tx sent! {}", tx_creation_artifacts);

    // alice obtains the tx id and provides it to bob.
    let txid = tx_creation_artifacts.transaction().txid();

    // bob waits until tx appears in his node's mempool
    bob.wait_until_tx_in_mempool(txid, timeout_secs).await?;

    // bob checks payment is reflected in his unconfirmed wallet balance
    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(bob_balances.unconfirmed_available, payment_amount);
    assert_eq!(bob_balances.confirmed_available, 0.into());

    // @alan, can you help?
    //
    // this fails during mempool tx update job spawned from main-loop.
    //
    // panic at tasm-lib-0.48.0/src/verifier/stark_verify.rs:145:61:
    // called `Result::unwrap()` on an `Err` value: DecodingError(SequenceEmptyForField("items"))
    //
    // seems to be trying to verify our mock SingleProof with just an empty vec![]
    //
    // It seems previous blocks in this test succeed because there is no user Tx in the mempool.

    /*
        // alice mines another block to her wallet
        alice.gsl
            .api_mut()
            .regtest_mut()
            .mine_regtest_blocks_to_wallet(1)
            .await?;

        bob.wait_until_block_height(4, timeout_secs).await?;

        // bob checks payment is reflected in his confirmed wallet balance
        let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
        assert_eq!(bob_balances.confirmed_available, payment_amount);
        assert_eq!(bob_balances.unconfirmed_available, payment_amount);
    */

    Ok(())
}
