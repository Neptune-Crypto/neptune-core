//! Nodes under sustained, concurrent peer activity must keep making
//! progress. Covers: simultaneous dials between all nodes, a node refusing
//! peers beyond its limit while the others keep reconnecting to it, block
//! propagation during continuous mining, a node syncing while the others
//! mine, and readers of the peer map throughout. A deadlock, or a lock held
//! so long that a loop stalls, shows up as a timeout.
//!
//! Ignored by default because it takes a while and is sensitive to machine
//! load. Run it with:
//!
//! ```text
//! cargo nextest run -p neptune-cash --run-ignored ignored-only -E 'binary(concurrent_peers)'
//! ```

mod common;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_primitives::network::Network;
use tracing::info;

const NUM_NODES: u8 = 5;
const BLOCKS: u64 = 13;
const LATE_JOINER_STARTS_AT_HEIGHT: u64 = 11;

#[ignore = "slow, and sensitive to machine load"]
#[tokio::test(flavor = "multi_thread")]
async fn peer_activity_does_not_stall_any_loop() -> anyhow::Result<()> {
    logging::tracing_logger();
    let network = Network::RegTest;
    let timeout_secs = 120;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    base_args.sync_mode_threshold = 10;
    base_args.peer_maintenance_interval = Duration::from_secs(3);
    let mut all_args = GenesisNode::instance_args_for_cluster(
        &GenesisNode::cluster_id(None),
        NUM_NODES,
        base_args,
    );

    // Node 1 lists no peers in CLI arguments and accepts only two peers. The
    // others list it as a peer, so they keep dialing it, get refused once it is
    //  full, and attempt to reconnect on every maintenance tick.
    all_args[1].peers.clear();
    all_args[1].max_num_peers = 2;

    // The last node joins late and far behind, so it syncs while the others
    // keep mining.
    let mut late_args = all_args.pop().unwrap();
    late_args.sync_dir = Some(
        GenesisNode::integration_test_data_directory(network)?
            .root_dir_path()
            .join("rapid-block-download"),
    );

    let mut early: [GenesisNode; 4] = GenesisNode::start_nodes(all_args).await?;
    early[0].wait_until_peers_connected(2, timeout_secs).await?;
    info!("Early nodes connected");

    // Read from the peer map and light state on every node
    let stop = Arc::new(AtomicBool::new(false));
    let mut readers = vec![];
    for node in &early {
        let gsl = node.gsl.clone();
        let stop = stop.clone();
        readers.push(tokio::spawn(async move {
            let mut reads = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let _num_peers = gsl.peers().len();
                let _tip_height = gsl.lock(|s| s.chain.tip_height()).await;
                reads += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            reads
        }));
    }

    // Node 0 mines one block at a time, for the whole run.
    let mut late = None;
    for height in 1..=BLOCKS {
        early[0]
            .gsl
            .api_mut()
            .regtest_mut()
            .mine_blocks_to_wallet(1, false)
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        if height == LATE_JOINER_STARTS_AT_HEIGHT {
            late = Some(GenesisNode::start_node(late_args.clone()).await?);
            info!("Late node started at height {height}");
        }
    }
    let late = late.expect("late node starts before mining ends");

    // Everyone must reach the final height: the early nodes through block
    // propagation, the late one through sync mode.
    for node in &early {
        node.wait_until_block_height(BLOCKS, timeout_secs).await?;
    }
    late.wait_until_synced(timeout_secs).await?;
    late.wait_until_block_height(BLOCKS, timeout_secs).await?;
    info!("All nodes reached height {BLOCKS}");

    stop.store(true, Ordering::Relaxed);
    for reader in readers {
        let reads = reader.await?;
        assert!(reads > 0, "readers must have kept running");
    }

    Ok(())
}
