mod common;

use std::net::Ipv4Addr;
use std::net::SocketAddr;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::application::config::cli_args::Args;
use neptune_cash::application::config::parser::multiaddr::socketaddr_to_multiaddr;
use neptune_cash::application::loops::sync_loop::test_helpers::seed_sync_directory;
use neptune_cash::state::sync_status::SyncStatus;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_primitives::network::Network;
use tracing::info;

#[tokio::test(flavor = "multi_thread")]
pub async fn sync_with_validated_blocks() {
    logging::tracing_logger();
    let network = Network::RegTest;

    let timeout_secs = 20;

    // Set advertised version so that the validated-block machinery is
    // guaranteed to be active on both sides: Bob/ requests blocks authenticated
    // against his sync anchor, and ignores plain middle blocks from Alice, who
    // is capable of serving authenticated blocks.
    // The sync below can therefore only complete through `ValidatedBlock`
    // responses.
    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    base_args.sync_mode_threshold = 11;
    base_args.sync_dir = Some(
        GenesisNode::integration_test_data_directory(network)
            .unwrap()
            .root_dir_path()
            .join("rapid-block-download"),
    );
    base_args.advertised_version = Some("0.99.0".to_string());
    let [mut alice, bob] = GenesisNode::start_connected_cluster(
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

    // While Bob processes the downloaded blocks, his main loop must retain
    // each processed block's authentication path — the enabler for serving
    // his processed blocks to other syncing peers. The retained path is only
    // observable while the sync process is running.
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs.into());
    loop {
        if bob
            .gsl
            .lock_guard()
            .await
            .net
            .sync_tip_auth_path_is_retained()
        {
            break;
        }
        assert!(
            start.elapsed() < timeout,
            "Bob must retain a tip authentication path while syncing"
        );
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    info!("Bob retained the tip's authentication path during sync");

    bob.wait_until_synced(timeout_secs).await.unwrap();
    bob.wait_until_block_height(16, timeout_secs).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
pub async fn syncing_peers_complete_sync_from_each_other() {
    logging::tracing_logger();
    let network = Network::RegTest;

    let timeout_secs = 60;

    // Alice starts alone and mines a chain.
    let common_args = |mut args: Args| {
        args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
        args.sync_mode_threshold = 11;
        args.advertised_version = Some("0.99.0".to_string());
        args
    };
    let alice_args = common_args(GenesisNode::default_args().await);
    let mut bob_args = common_args(GenesisNode::default_args().await);
    let mut charlie_args = common_args(GenesisNode::default_args().await);

    // Bob and Charlie each get their own sync directory, to be seeded below,
    // and connect to Alice and to each other.
    let bob_sync_dir = GenesisNode::integration_test_data_directory(network)
        .unwrap()
        .root_dir_path()
        .join("rapid-block-download");
    let charlie_sync_dir = GenesisNode::integration_test_data_directory(network)
        .unwrap()
        .root_dir_path()
        .join("rapid-block-download");
    bob_args.sync_dir = Some(bob_sync_dir.clone());
    charlie_args.sync_dir = Some(charlie_sync_dir.clone());
    let multiaddr_of = |args: &Args| {
        socketaddr_to_multiaddr(SocketAddr::from((Ipv4Addr::LOCALHOST, args.peer_port)))
    };
    bob_args.peers = vec![multiaddr_of(&alice_args), multiaddr_of(&charlie_args)];
    charlie_args.peers = vec![multiaddr_of(&alice_args), multiaddr_of(&bob_args)];

    let mut alice = GenesisNode::start_node(alice_args).await.unwrap();
    let final_tip_height = 41u64;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(final_tip_height as u32, false)
        .await
        .unwrap();
    alice
        .wait_until_block_height(final_tip_height, timeout_secs)
        .await
        .unwrap();

    // Hand Bob the first half of the chain and Charlie the second half, as
    // sync stores to resume from. Neither of them can complete a sync of
    // Alice's chain on their own.
    let entries = alice
        .gsl
        .lock_guard()
        .await
        .blocks_with_authentication_paths(1..=final_tip_height)
        .await;
    seed_sync_directory(bob_sync_dir, network, &entries[..20])
        .await
        .unwrap();
    seed_sync_directory(charlie_sync_dir, network, &entries[20..])
        .await
        .unwrap();

    // Bob and Charlie join. Being behind Alice, each asks her for a block
    // notification when connecting, anchors on her tip, and enters sync mode,
    // where the resume machinery picks up the seeded halves.
    let bob = GenesisNode::start_node(bob_args).await.unwrap();
    let charlie = GenesisNode::start_node(charlie_args).await.unwrap();
    bob.wait_until_peers_connected(2, timeout_secs)
        .await
        .unwrap();
    charlie
        .wait_until_peers_connected(2, timeout_secs)
        .await
        .unwrap();

    // The moment both are in sync mode, freeze Alice. She ignores all
    // block-related messages from then on, so the only way Bob and Charlie
    // can complete their syncs is by sharing their blocks with each other.
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs.into());
    loop {
        let bob_is_syncing = matches!(
            bob.gsl.lock_guard().await.net.sync_status,
            SyncStatus::Syncing(_)
        );
        let charlie_is_syncing = matches!(
            charlie.gsl.lock_guard().await.net.sync_status,
            SyncStatus::Syncing(_)
        );
        if bob_is_syncing && charlie_is_syncing {
            break;
        }
        assert!(
            start.elapsed() < timeout,
            "Bob and Charlie must both enter sync mode"
        );
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    alice.gsl.api_mut().regtest_mut().freeze().await;

    // Alice must not have served all blocks before her state got frozen.
    // Otherwise, the test is meaningless.
    assert_ne!(
        bob.gsl.lock_guard().await.chain.tip_height(),
        final_tip_height.into()
    );
    assert_ne!(
        charlie.gsl.lock_guard().await.chain.tip_height(),
        final_tip_height.into()
    );
    assert!(
        !bob.gsl.lock_guard().await.net.sync_download_is_complete(),
        "Bob must still be missing blocks when Alice freezes"
    );
    assert!(
        !charlie
            .gsl
            .lock_guard()
            .await
            .net
            .sync_download_is_complete(),
        "Charlie must still be missing blocks when Alice freezes"
    );

    bob.wait_until_synced(timeout_secs).await.unwrap();
    bob.wait_until_block_height(final_tip_height, timeout_secs)
        .await
        .unwrap();
    charlie.wait_until_synced(timeout_secs).await.unwrap();
    charlie
        .wait_until_block_height(final_tip_height, timeout_secs)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
pub async fn basic_sync() {
    logging::tracing_logger();
    let network = Network::RegTest;

    let timeout_secs = 20;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    base_args.sync_mode_threshold = 11;
    base_args.sync_dir = Some(
        GenesisNode::integration_test_data_directory(network)
            .unwrap()
            .root_dir_path()
            .join("rapid-block-download"),
    );
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

    // Just ensure that Bob reaches block 15. No need to catch up fully yet.
    bob.wait_until_synced(timeout_secs).await.unwrap();
    bob.wait_until_block_height(15, timeout_secs).await.unwrap();

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
