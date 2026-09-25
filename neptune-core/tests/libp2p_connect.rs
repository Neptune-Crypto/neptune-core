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
        .peers()
        .with_connected(|connected| connected.values().next().expect("bob has a peer").address());
    assert!(
        alice_as_seen_by_bob
            .iter()
            .any(|protocol| protocol == Protocol::Udp(alice_quic_port)),
        "expected a libp2p QUIC connection to alice, got {alice_as_seen_by_bob}"
    );

    Ok(())
}

/// test: three nodes on localhost form a complete graph over libp2p.
///
/// scenario:
/// 1. bob starts with no peers.
/// 2. alice and charlie each start with bob's QUIC address as their only
///    peer, so the only configured edges are alice-bob and bob-charlie.
/// 3. through identify and Kademlia, alice learns of charlie from bob and
///    dials him, so every node ends up with two peers.
#[tokio::test(flavor = "multi_thread")]
pub async fn three_nodes_form_complete_graph_over_libp2p() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 90;

    let bob_args = GenesisNode::default_args().await;
    let bob_quic_port = bob_args.quic_port;
    let bob = GenesisNode::start_node(bob_args).await?;
    let bob_address: Multiaddr = format!("/ip4/127.0.0.1/udp/{bob_quic_port}/quic-v1").parse()?;

    let mut alice_args = GenesisNode::default_args().await;
    alice_args.peers = vec![bob_address.clone()];
    let alice = GenesisNode::start_node(alice_args).await?;

    let mut charlie_args = GenesisNode::default_args().await;
    charlie_args.peers = vec![bob_address];
    let charlie_libp2p_ports = [
        Protocol::Udp(charlie_args.quic_port),
        Protocol::Tcp(charlie_args.tcp_port),
    ];
    let charlie = GenesisNode::start_node(charlie_args).await?;

    for node in [&alice, &bob, &charlie] {
        node.wait_until_peers_connected(2, timeout_secs).await?;
    }

    // Alice was never told about charlie through the CLI arguments. So her
    // entry of him in the peer map proves that a connection was established
    // through the libp2p peer discovery protocol.
    let alice_peer_addresses = alice.gsl.peers().with_connected(|connected| {
        connected
            .values()
            .map(|peer| peer.address())
            .collect::<Vec<_>>()
    });
    assert!(
        alice_peer_addresses.iter().any(|address| address
            .iter()
            .any(|protocol| charlie_libp2p_ports.contains(&protocol))),
        "expected alice to discover one of charlie's libp2p addresses, got {alice_peer_addresses:?}"
    );

    Ok(())
}
