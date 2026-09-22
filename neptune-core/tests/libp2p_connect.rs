mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

/// test: two nodes on localhost connect to each other over libp2p.
///
/// scenario:
/// 1. alice starts with no peers, listening on localhost.
/// 2. bob starts with alice's QUIC address as his only peer. A QUIC address
///    is never dialed by the legacy socket stack, so the resulting connection
///    can only have been made by libp2p.
/// 3. both nodes see each other in their peer maps.
#[tokio::test(flavor = "multi_thread")]
pub async fn two_nodes_connect_over_libp2p() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 30;

    let alice_args = GenesisNode::default_args().await;
    let alice_quic_port = alice_args.quic_port;
    let alice = GenesisNode::start_node(alice_args).await?;

    let alice_address: Multiaddr =
        format!("/ip4/127.0.0.1/udp/{alice_quic_port}/quic-v1").parse()?;
    let mut bob_args = GenesisNode::default_args().await;
    bob_args.peers = vec![alice_address];
    let bob = GenesisNode::start_node(bob_args).await?;

    alice.wait_until_one_peer_connected(timeout_secs).await?;
    bob.wait_until_one_peer_connected(timeout_secs).await?;

    // Bob's record of alice must carry the QUIC port he dialed, which
    // confirms the connection went through libp2p.
    let alice_as_seen_by_bob = bob
        .gsl
        .lock_guard()
        .await
        .net
        .peer_map
        .values()
        .next()
        .expect("bob has a peer")
        .address();
    assert!(
        alice_as_seen_by_bob
            .iter()
            .any(|protocol| protocol == Protocol::Udp(alice_quic_port)),
        "expected a libp2p QUIC connection to alice, got {alice_as_seen_by_bob}"
    );

    Ok(())
}
