mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::TxProvingCapability;
use tracing::info;
use tracing_test::traced_test;

#[traced_test]
#[tokio::test(flavor = "multi_thread")]
pub async fn bob_catches_up_to_alices_new_blocks_with_sync_state() {
    logging::tracing_logger();

    let timeout_secs = 5;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    base_args.sync_mode_threshold = 11;
    let [mut alice, mut bob] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(None),
        2,
        Some(base_args),
        timeout_secs,
    )
    .await
    .unwrap();

    // Stop transaction and block sharing to ensure Bob sees all mined blocks
    // at once.
    alice.gsl.api_mut().regtest_mut().freeze().await;

    // Alice mines 15 blocks that forces Bob into sync mode
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(15, false)
        .await
        .unwrap();

    alice
        .wait_until_block_height(15, timeout_secs)
        .await
        .unwrap();
    info!("Alice reached block height 15");

    // Start sharing blocks again
    alice.gsl.api_mut().regtest_mut().unfreeze().await;

    // Mine one more block to force a state share/update
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await
        .unwrap();

    bob.wait_until_sync_mode(timeout_secs).await.unwrap();
    bob.wait_until_synced(timeout_secs).await.unwrap();
    bob.wait_until_block_height(16, timeout_secs).await.unwrap();

    // Verify that block sharing still works, after syncing is complete.
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await
        .unwrap();
    alice
        .wait_until_block_height(19, timeout_secs)
        .await
        .unwrap();
    bob.wait_until_block_height(19, timeout_secs).await.unwrap();

    // Verify that block sharing works the other way too.
    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(2, false)
        .await
        .unwrap();
    bob.wait_until_block_height(21, timeout_secs).await.unwrap();
    alice
        .wait_until_block_height(21, timeout_secs)
        .await
        .unwrap();
}
