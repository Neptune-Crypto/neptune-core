mod common;

use std::collections::HashSet;
use std::net::Ipv4Addr;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mempool::recent_mutator_sets::MAX_TX_SYNC_DEPTH;
use neptune_mempool::transaction_kernel_id::Txid;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::timestamp::Timestamp;
use neptune_rpc_api::api::ops::Namespace;
use neptune_rpc_api::api::rpc::RpcApi;
use neptune_rpc_api::model::wallet::transaction::RpcTransaction;
use neptune_rpc_client::http::HttpClient;
use neptune_wallet::address::KeyType;
use tokio::net::TcpListener;

/// Wait until the node's mempool holds a single-proof backed transaction
/// spending these inputs that is synced to the mutator set, and return it.
/// Found by inputs rather than by ID, since an update that charges a gobbling
/// fee changes the transaction's ID.
async fn wait_until_synced_single_proof_tx_spending(
    node: &GenesisNode,
    inputs: &HashSet<Vec<u128>>,
    mutator_set: &MutatorSetAccumulator,
    timeout_secs: u16,
) -> anyhow::Result<Transaction> {
    let start = std::time::Instant::now();
    loop {
        {
            let state = node.gsl.lock_guard().await;
            let synced = state
                .mempool()
                .fee_density_iter()
                .filter_map(|(txid, _)| state.mempool().get(txid))
                .find(|tx| {
                    tx.proof.is_single_proof()
                        && inputs.is_subset(&absolute_indices(tx))
                        && tx.kernel.mutator_set_hash == mutator_set.hash()
                        && tx.is_confirmable_relative_to(mutator_set)
                });
            if let Some(tx) = synced {
                return Ok(tx.to_owned());
            }
        }
        if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
            anyhow::bail!(
                "no synced single-proof tx spending the inputs after {timeout_secs} seconds"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// The inputs of a transaction, identified by their absolute index sets,
/// which an update of the transaction leaves unchanged.
fn absolute_indices(tx: &Transaction) -> HashSet<Vec<u128>> {
    tx.kernel
        .inputs
        .iter()
        .map(|input| input.absolute_indices.to_array().to_vec())
        .collect()
}

/// Alice pays bob with a transaction synced to an ancestor of bob's tip, this
/// many blocks behind it, submitted to bob over RPC as an external wallet
/// would. Bob accepts it, brings it to his tip, and mines it.
///
/// scenario:
/// 1. alice (with the given proving capability) and bob (SingleProof capable,
///    proof upgrading enabled) run a 2-node regtest network. alice mines 3
///    blocks to her wallet.
/// 2. alice is frozen for the rest of the test: she neither learns of new
///    blocks nor shares anything. bob mines the next blocks.
/// 3. alice pays bob. Her transaction is synced to block 3, and only the
///    test can pass it on.
/// 4. the test submits the transaction to bob over RPC. He accepts it, though
///    it is behind his tip.
/// 5. bob brings the transaction to his tip as a single proof. alice cannot
///    have done that, as she does not know the blocks after block 3.
/// 6. bob mines a block that includes the transaction.
async fn rpc_accepts_tx_synced_to_ancestor(
    cluster_id: &str,
    alice_proving_capability: TxProvingCapability,
    depth: u64,
) -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(alice_proving_capability);
    let mut all_args = GenesisNode::instance_args_for_cluster(cluster_id, 2, base_args);
    all_args[1].tx_proving_capability = Some(TxProvingCapability::SingleProof);
    all_args[1].tx_proof_upgrading = true;
    // An update of a foreign transaction gobbles nothing, so bob must be
    // willing to work for free.
    all_args[1].min_gobbling_fee = NativeCurrencyAmount::coins(0);
    let bob_rpc_address = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await?
        .local_addr()?;
    all_args[1].listen_rpc = Some(bob_rpc_address);
    all_args[1].rpc_modules.push(Namespace::Wallet);
    let cluster: [GenesisNode; 2] = GenesisNode::start_nodes(all_args).await?;
    GenesisNode::wait_until_all_peers_connected(&cluster, timeout_secs).await?;
    let [mut alice, mut bob] = cluster;

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;
    bob.wait_until_block_height(3, timeout_secs).await?;
    let block_3 = alice.gsl.lock_guard().await.chain.tip().to_owned();
    let mutator_set_3 = block_3.mutator_set_accumulator_after().unwrap();

    alice.gsl.api_mut().regtest_mut().freeze().await;
    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(depth as u32, false)
        .await?;
    let bob_tip = bob.gsl.lock_guard().await.chain.tip().to_owned();
    assert_eq!(3 + depth, u64::from(bob_tip.header().height));
    let bob_tip_mutator_set = bob_tip.mutator_set_accumulator_after().unwrap();

    let payment_amount = NativeCurrencyAmount::coins_from_str("2.45")?;
    let fee_amount = NativeCurrencyAmount::coins_from_str("0.5")?;
    let accept_lustrations = true;
    let tx_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address, payment_amount)],
            Default::default(),
            fee_amount,
            Timestamp::now(),
            accept_lustrations,
        )
        .await?;
    let txid = tx_artifacts.transaction().txid();

    // alice's node proves the transaction in the background; only the proven
    // form can leave her node.
    match alice_proving_capability {
        TxProvingCapability::ProofCollection => {
            alice
                .wait_until_tx_in_mempool_has_proof_collection(txid, timeout_secs)
                .await?
        }
        TxProvingCapability::SingleProof => {
            alice
                .wait_until_tx_in_mempool_has_single_proof(txid, timeout_secs)
                .await?
        }
        _ => unreachable!("alice must be able to prove her transaction"),
    }
    let sent_tx = alice
        .gsl
        .lock_guard()
        .await
        .mempool()
        .get(txid)
        .expect("alice must hold her own transaction")
        .to_owned();
    assert_eq!(mutator_set_3.hash(), sent_tx.kernel.mutator_set_hash);
    let inputs = absolute_indices(&sent_tx);

    let bob_rpc = HttpClient::new(format!("http://{bob_rpc_address}"));
    let rpc_tx = RpcTransaction::try_from(sent_tx.clone()).map_err(anyhow::Error::msg)?;
    let response = bob_rpc.submit_transaction(rpc_tx).await?;
    assert!(response.success, "bob must accept the transaction over RPC");

    bob.wait_until_tx_in_mempool(txid, timeout_secs).await?;
    assert_eq!(
        bob_tip.hash(),
        bob.gsl.lock_guard().await.chain.tip().hash()
    );

    // bob's upgrader ticks every N seconds, so allow for more than that.
    let upgrade_timeout_secs = 30;
    let updated_tx = wait_until_synced_single_proof_tx_spending(
        &bob,
        &inputs,
        &bob_tip_mutator_set,
        upgrade_timeout_secs,
    )
    .await?;
    assert_eq!(
        bob_tip_mutator_set.hash(),
        updated_tx.kernel.mutator_set_hash
    );

    // Mine the now-synced transaction
    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;
    let next_block = bob.gsl.lock_guard().await.chain.tip().to_owned();
    assert_eq!(4 + depth, u64::from(next_block.header().height));
    let mined_inputs = next_block
        .body()
        .transaction_kernel
        .inputs
        .iter()
        .map(|input| input.absolute_indices.to_array().to_vec())
        .collect::<HashSet<_>>();
    assert!(
        inputs.is_subset(&mined_inputs),
        "bob's next block must spend the inputs of alice's transaction"
    );

    // Sleep to give application time to send all messages before receivers
    // are dropped.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    Ok(())
}

/// test: bob accepts alice's single-proof transaction over RPC although it is
/// as many blocks behind his tip as the window allows, and updates it.
///
/// alice's proof is a single proof, so bob only has to update it.
#[tokio::test(flavor = "multi_thread")]
pub async fn rpc_accepts_single_proof_tx_synced_to_oldest_held_ancestor() -> anyhow::Result<()> {
    rpc_accepts_tx_synced_to_ancestor(
        &GenesisNode::cluster_id(None),
        TxProvingCapability::SingleProof,
        MAX_TX_SYNC_DEPTH as u64,
    )
    .await
}

/// test: bob accepts alice's proof-collection transaction over RPC although
/// it is as many blocks behind his tip as the window allows, raises it, and
/// updates it.
///
/// A proof collection cannot be updated, and alice alone holds the primitive
/// witness. So bob raises it to a single proof against the mutator set it was
/// built for, and then updates that.
#[tokio::test(flavor = "multi_thread")]
pub async fn rpc_accepts_proof_collection_tx_synced_to_oldest_held_ancestor() -> anyhow::Result<()>
{
    rpc_accepts_tx_synced_to_ancestor(
        &GenesisNode::cluster_id(None),
        TxProvingCapability::ProofCollection,
        MAX_TX_SYNC_DEPTH as u64,
    )
    .await
}
