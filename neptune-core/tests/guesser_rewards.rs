mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::ReceivingAddress;
use num_traits::Zero;

#[tokio::test(flavor = "multi_thread")]
pub async fn mining_rewards_go_to_overridden_mining_address() {
    logging::tracing_logger();
    let network = Network::RegTest;

    let timeout_secs = 5;
    let base_args = GenesisNode::default_args().await;
    let [alice, bob] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(None),
        2,
        Some(base_args),
        timeout_secs,
    )
    .await
    .unwrap();

    // Start another node, that mines to Bob's wallet. And that is connected
    // to the two other nodes.
    let mut cli_args = GenesisNode::default_args().await;
    let bobs_address: ReceivingAddress = bob
        .gsl
        .lock_guard()
        .await
        .wallet_state
        .wallet_entropy
        .composer_fee_key()
        .to_address()
        .into();
    cli_args.mining_address = Some(bobs_address.to_display_bech32m(network).unwrap());
    cli_args.peers = alice.gsl.cli().peers.clone();

    let mut eve = GenesisNode::start_node(cli_args).await.unwrap();

    // Mine one block and verify what was received
    eve.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await
        .unwrap();

    bob.wait_until_block_height(1u64, timeout_secs)
        .await
        .unwrap();

    // Verify expected balances:
    // - Alice: zero
    // - Bob: non-zero
    // - Eve: zero
    let alice = alice.gsl.api().wallet().balances(Timestamp::now()).await;
    assert!(alice.unconfirmed_available.is_zero());
    assert!(alice.confirmed_available.is_zero());

    let bob = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert!(!bob.unconfirmed_available.is_zero());
    assert!(!bob.confirmed_available.is_zero());

    let eve = eve.gsl.api().wallet().balances(Timestamp::now()).await;
    assert!(eve.unconfirmed_available.is_zero());
    assert!(eve.confirmed_available.is_zero());
}
