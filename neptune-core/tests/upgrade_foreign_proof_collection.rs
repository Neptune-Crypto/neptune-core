mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mempool::transaction_kernel_id::Txid;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::KeyType;

/// Start two nodes, one PC-capable, and one SP-capable. The latter offers
/// proof upgrading.
async fn start_proof_collection_and_upgrader_cluster(
    cluster_id: &str,
    timeout_secs: u16,
) -> anyhow::Result<[GenesisNode; 2]> {
    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::ProofCollection);

    let mut all_args = GenesisNode::instance_args_for_cluster(cluster_id, 2, base_args);
    all_args[1].tx_proving_capability = Some(TxProvingCapability::SingleProof);
    all_args[1].tx_proof_upgrading = true;

    let cluster: [GenesisNode; 2] = GenesisNode::start_nodes(all_args).await?;
    GenesisNode::wait_until_all_peers_connected(&cluster, timeout_secs).await?;
    Ok(cluster)
}

/// Wait until the node's mempool contains a single-proof backed transaction
/// that is confirmable relative to the given mutator set, and return it.
///
/// Notice that a raise of a foreing transaction charges a gobbling fee, which
/// changes the transaction's ID. So the transaction is found by proof quality/
/// sync status instead.
async fn wait_until_confirmable_single_proof_tx(
    node: &GenesisNode,
    mutator_set: &MutatorSetAccumulator,
    timeout_secs: u16,
) -> anyhow::Result<Transaction> {
    let start = std::time::Instant::now();
    loop {
        {
            let state = node.gsl.lock_guard().await;
            let confirmable = state
                .mempool()
                .fee_density_iter()
                .filter_map(|(txid, _)| state.mempool().get(txid))
                .find(|tx| {
                    tx.proof.is_single_proof() && tx.is_confirmable_relative_to(mutator_set)
                });
            if let Some(tx) = confirmable {
                return Ok(tx.to_owned());
            }
        }
        if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
            anyhow::bail!(
                "no confirmable single-proof tx in mempool after {} seconds",
                timeout_secs
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// test: bob raises alice's proof-collection transaction to a single proof
///
/// this is a test of the proof upgrader's "raise" operation on a foreign
/// transaction: the transaction initiator cannot produce a single proof, so
/// a third party must.
///
/// scenario:
/// 1. alice (ProofCollection capable) and bob (SingleProof capable,
///    proof upgrading enabled) run a 2-node regtest network.
/// 2. alice mines 3 blocks to her own wallet.
/// 3. alice pays bob. Her node can back the transaction with no more than a
///    proof collection.
/// 4. the transaction reaches bob's mempool, and bob raises it to a single
///    proof, charging a gobbling fee for his troubles.
/// 5. no block was mined in the meantime, so the raise alone suffices: the
///    upgraded transaction is synced to the tip and confirmable as-is.
/// 6. the upgraded transaction propagates back to alice.
#[tokio::test(flavor = "multi_thread")]
pub async fn simple_raise() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;

    let [mut alice, mut bob] =
        start_proof_collection_and_upgrader_cluster(&GenesisNode::cluster_id(None), timeout_secs)
            .await?;

    // bob generates receiving address
    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    // alice mines 3 blocks to her wallet
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    // wait until the blocks have propagated to bob's node.
    bob.wait_until_block_height(3, timeout_secs).await?;

    // alice sends a payment to bob
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
    let mutator_set_hash_at_creation = tx_artifacts.transaction().kernel.mutator_set_hash;

    tracing::info!("tx sent! {}", tx_artifacts);

    // the transaction arrives in bob's mempool, proof-collection backed
    bob.wait_until_tx_in_mempool_has_proof_collection(txid, timeout_secs)
        .await?;

    // bob raises it to a single proof. His upgrade timer ticks every N
    // seconds, so allow for more than that. No block was mined since the
    // transaction was created, so the raise required no update: the upgraded
    // transaction is synced to the same mutator set as at creation.
    let upgrade_timeout_secs = 30;
    let tip = bob.gsl.lock_guard().await.chain.tip().to_owned();
    assert_eq!(3u64, u64::from(tip.header().height));
    let tip_msa = tip.mutator_set_accumulator_after().unwrap();
    let upgraded_tx =
        wait_until_confirmable_single_proof_tx(&bob, &tip_msa, upgrade_timeout_secs).await?;
    assert_eq!(
        mutator_set_hash_at_creation, upgraded_tx.kernel.mutator_set_hash,
        "the raise must not have changed the transaction's mutator set"
    );

    // bob announces his hard work, so the single proof also reaches alice
    wait_until_confirmable_single_proof_tx(&alice, &tip_msa, upgrade_timeout_secs).await?;

    // Sleep to give application time to send all messages before receivers
    // are dropped.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    Ok(())
}

/// test: bob raises alice's proof-collection transaction and must follow up
/// with an update
///
/// this is a test of the proof upgrader's "raise" operation on a foreign
/// transaction that is no longer synced to the tip: the raise is performed
/// against the transaction's own mutator set, after which the resulting
/// single proof must be updated to the tip before the transaction is
/// confirmable.
///
/// scenario:
/// 1. alice (ProofCollection capability) and bob (SingleProof capability,
///    proof upgrading enabled) run a 2-node regtest network.
/// 2. alice mines 3 blocks to her own wallet, then pays bob with a
///    proof-collection backed transaction.
/// 3. the transaction reaches bob's mempool. Alice then goes offline. She is
///    the only one holding the transaction's primitive witness, so from here
///    on nobody can update the proof collection itself.
/// 4. bob mines a block that does not include the transaction. The
///    proof-collection transaction in his mempool is now desynced, and stays
///    in the mempool.
/// 5. bob raises the transaction against its own (old) mutator set, and must
///    then update the resulting single proof to the tip.
/// 6. the transaction ends up single-proof backed, synced to the new tip, and
///    confirmable.
#[tokio::test(flavor = "multi_thread")]
pub async fn raise_followed_by_update() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;

    let [mut alice, mut bob] =
        start_proof_collection_and_upgrader_cluster(&GenesisNode::cluster_id(None), timeout_secs)
            .await?;

    // bob generates receiving address
    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    // alice mines 3 blocks to her wallet
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    // wait until the blocks have propagated to bob's node.
    bob.wait_until_block_height(3, timeout_secs).await?;

    // alice sends a payment to bob
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
    let mutator_set_hash_at_creation = tx_artifacts.transaction().kernel.mutator_set_hash;

    tracing::info!("tx sent! {}", tx_artifacts);

    // the transaction arrives in bob's mempool, proof-collection backed
    bob.wait_until_tx_in_mempool_has_proof_collection(txid, timeout_secs)
        .await?;

    // alice goes offline. As the transaction initiator she is the only one
    // holding the primitive witness, and a proof collection cannot be updated
    // without it. So whatever happens next is bob's work alone, and any
    // update must go through a raised single proof.
    alice.main_loop_join_handle.abort();

    // bob mines a block that does not include the transaction, desyncing the
    // proof-collection transaction in his mempool.
    let include_mempool_txs = false;
    bob.gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await?;
    let tip = bob.gsl.lock_guard().await.chain.tip().to_owned();
    assert_eq!(4u64, u64::from(tip.header().height));
    let tip_msa = tip.mutator_set_accumulator_after().unwrap();

    // bob raises the transaction and updates it to the tip. His upgrade timer
    // ticks every N seconds and several (mock) proving jobs must run, so allow
    // some time.
    let upgrade_timeout_secs = 20;
    let upgraded_tx =
        wait_until_confirmable_single_proof_tx(&bob, &tip_msa, upgrade_timeout_secs).await?;

    // the raise alone cannot have sufficed: the transaction was created on a
    // mutator set that predates the tip, so an update must have followed.
    assert_eq!(tip_msa.hash(), upgraded_tx.kernel.mutator_set_hash);
    assert_ne!(
        mutator_set_hash_at_creation, upgraded_tx.kernel.mutator_set_hash,
        "the raised transaction must have been updated to the new tip"
    );

    // Sleep to give application time to send all messages before receivers
    // are dropped.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    Ok(())
}
