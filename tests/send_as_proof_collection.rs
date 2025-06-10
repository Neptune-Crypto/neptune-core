mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::TxProvingCapability;
use neptune_cash::models::state::mempool::upgrade_priority::UpgradePriority;
use tracing_test::traced_test;

#[traced_test]
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_makes_proof_collection_transaction() -> anyhow::Result<()> {
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
        .await?;

    // Generate an address
    let alice_address = alice
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    // Create transaction to self
    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(alice_address, NativeCurrencyAmount::coins_from_str("2.45")?)],
            Default::default(),
            NativeCurrencyAmount::coins(1),
            Timestamp::now(),
        )
        .await?;

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
        .await?;

    // Mine one block, and verify that transaction stays in the mempool
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1)
        .await?;
    assert_eq!(1, alice.gsl.lock_guard().await.mempool.len());

    Ok(())
}
