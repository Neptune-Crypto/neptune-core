mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::TxProvingCapability;
use neptune_cash::models::state::mempool::upgrade_priority::UpgradePriority;
use tracing_test::traced_test;

/// Test: Alice creates a proof-collection backed transaction.
///
/// this is a test that proof collection backed transactions are updated on the
/// receival of new blocks.
///
/// Scenario:
/// 1. Single unconnected node on regtest network
/// 2. Alice mines 2 blocks to her own wallet
/// 3. Alice inserts a proof-collection backed tx into her mempool
/// 4. Alice receives a new block that does not include her transaction
/// 5. Verify that Alice's proof-collection backed transaction is updated
///    after the processing of the new block.
#[traced_test]
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_makes_proof_collection_transaction() {
    logging::tracing_logger();

    let mut cli_args = GenesisNode::default_args();
    cli_args.tx_proving_capability = Some(TxProvingCapability::ProofCollection);
    let mut alice = GenesisNode::start_node(cli_args).await.unwrap();

    // Mine two blocks to get a positive balance
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(2)
        .await
        .unwrap();
    assert_eq!(
        BlockHeight::from(2u64),
        alice
            .gsl
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height,
        "Expected block height: 2"
    );

    // Generate an address
    let alice_address = alice
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await
        .unwrap();

    // Create transaction to self
    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(
                alice_address,
                NativeCurrencyAmount::coins_from_str("2.45").unwrap(),
            )],
            Default::default(),
            NativeCurrencyAmount::coins(1),
            Timestamp::now(),
        )
        .await
        .unwrap();

    alice
        .gsl
        .lock_guard_mut()
        .await
        .mempool_insert(
            tx_artifacts.transaction().to_owned(),
            UpgradePriority::Critical,
        )
        .await;
    assert_eq!(1, alice.gsl.lock_guard().await.mempool.len());

    // Wait until tx is backed by a proof collection
    let timeout_secs = 5;
    alice
        .wait_until_tx_in_mempool_has_proof_collection(
            tx_artifacts.transaction().txid(),
            timeout_secs,
        )
        .await
        .unwrap();

    // Mine one block, and verify that transaction stays in the mempool.
    // Transaction will not be mined since it's only backed by a
    // proof-collection.
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1)
        .await
        .unwrap();
    assert_eq!(1, alice.gsl.lock_guard().await.mempool.len());
    let tip = alice.gsl.lock_guard().await.chain.light_state().clone();
    assert_eq!(
        BlockHeight::from(3u64),
        tip.header().height,
        "Expected block height: 3"
    );

    let tip_msa = tip.mutator_set_accumulator_after().unwrap();
    let tx_upgrade_timeout_secs = 20;
    alice
        .wait_until_tx_in_mempool_confirmable(
            tx_artifacts.transaction().txid(),
            &tip_msa,
            tx_upgrade_timeout_secs,
        )
        .await
        .unwrap();

    // Verify that transaction is confirmable against tip.
    let txid = tx_artifacts.transaction().txid();
    let tx = alice
        .gsl
        .lock_guard()
        .await
        .mempool
        .get(txid)
        .unwrap()
        .to_owned();
    assert!(tx.is_confirmable_relative_to(&tip.mutator_set_accumulator_after().unwrap()));
}
