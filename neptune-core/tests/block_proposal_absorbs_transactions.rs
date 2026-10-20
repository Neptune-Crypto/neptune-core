mod common;

use std::time::Duration;

use clap::Parser;
use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::application::config::cli_args::Args;
use neptune_cash::state::mining::block_proposal::BlockProposal;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::KeyType;
use neptune_wallet::address::ReceivingAddress;

/// test: a composing node's block proposal reaches its peer, and a new
/// proposal with a transaction the peer issues follows.
///
/// scenario:
/// 1. alice composes; bob holds the funds and is alice's only peer.
/// 2. bob mines three blocks to his wallet, which alice follows.
/// 3. bob sends transaction a; once alice has upgraded it, her next
///    proposal, with a's inputs, reaches bob.
/// 4. bob sends transaction b; alice's next proposal, with the inputs of
///    both a and b, reaches bob.
#[tokio::test(flavor = "multi_thread")]
pub async fn composers_proposal_absorbs_each_new_transaction() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 90;

    // The composing flags are not settable on the arguments directly, so
    // alice's come from the parser, on the ports and directory the harness
    // picks.
    let defaults = GenesisNode::default_args().await;
    let mut alice_args = Args::try_parse_from([
        "neptune-core",
        "--compose",
        "--max-num-compose-mergers",
        "2",
    ])?;
    alice_args.network = defaults.network;
    alice_args.data_dir = defaults.data_dir;
    alice_args.peer_listen_addr = defaults.peer_listen_addr;
    alice_args.peer_port = defaults.peer_port;
    alice_args.rpc_port = defaults.rpc_port;
    alice_args.quic_port = defaults.quic_port;
    alice_args.tcp_port = defaults.tcp_port;
    alice_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    alice_args.tx_proof_upgrading = true;
    let alice_quic_port = alice_args.quic_port;
    let alice = GenesisNode::start_node(alice_args).await?;

    let mut bob_args = GenesisNode::default_args().await;
    bob_args.peers = vec![GenesisNode::quic_address(alice_quic_port)];
    let mut bob = GenesisNode::start_node(bob_args).await?;
    alice.wait_until_one_peer_connected(timeout_secs).await?;
    bob.wait_until_one_peer_connected(timeout_secs).await?;

    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;
    alice.wait_until_block_height(3, timeout_secs).await?;

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    let tx_a = send(&mut bob, bob_address.clone(), "2").await?;
    wait_until_proposal_spends(&bob, &[&tx_a], timeout_secs).await?;

    let tx_b = send(&mut bob, bob_address, "3").await?;
    wait_until_proposal_spends(&bob, &[&tx_a, &tx_b], timeout_secs).await?;

    Ok(())
}

/// Bob's transaction of this many coins to the address, at a fee of half a
/// coin.
async fn send(
    bob: &mut GenesisNode,
    address: ReceivingAddress,
    amount: &str,
) -> anyhow::Result<Transaction> {
    let artifacts = bob
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(address, NativeCurrencyAmount::coins_from_str(amount)?)],
            Default::default(),
            NativeCurrencyAmount::coins_from_str("0.5")?,
            Timestamp::now(),
            true,
        )
        .await?;
    Ok(artifacts.transaction().clone())
}

/// Waits until the node holds a foreign block proposal whose inputs are
/// exactly those of these transactions.
async fn wait_until_proposal_spends(
    node: &GenesisNode,
    transactions: &[&Transaction],
    timeout_secs: u16,
) -> anyhow::Result<()> {
    let expected = transactions
        .iter()
        .flat_map(|tx| tx.kernel.inputs.iter().map(|input| input.absolute_indices))
        .collect::<Vec<_>>();
    assert!(
        !expected.is_empty(),
        "the transactions must spend something"
    );
    let start = std::time::Instant::now();
    loop {
        let inputs = match &node.gsl.lock_guard().await.mining_state.block_proposal {
            BlockProposal::ForeignComposition(block) => Some(
                block
                    .body()
                    .transaction_kernel
                    .inputs
                    .iter()
                    .map(|input| input.absolute_indices)
                    .collect::<Vec<_>>(),
            ),
            BlockProposal::OwnComposition(_) | BlockProposal::None => None,
        };
        if inputs.as_ref().is_some_and(|inputs| {
            inputs.len() == expected.len() && expected.iter().all(|index| inputs.contains(index))
        }) {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(timeout_secs.into()) {
            anyhow::bail!(
                "no proposal spending the {} inputs after {timeout_secs} seconds; saw {inputs:?}",
                expected.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
