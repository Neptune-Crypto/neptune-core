//! End-to-end scenarios for the transaction-chaining pipeline, on a connected
//! regtest cluster with mock proofs so that no real proving is needed.

mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::ChainedTxArtifacts;
use neptune_cash::api::export::LinkTxArtifacts;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mempool::transaction_kernel_id::Txid;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::KeyType;

/// test: alice pays bob, and bob pays the coins onward to charlie before the
/// next block -- through the chaining pipeline, entirely on bob's own node.
///
/// The simplest chaining scenario: every transaction on the network is
/// `SingleProof`-backed. Bob receives Alice's transaction as a `SingleProof`
/// through ordinary gossip, runs the whole chain pipeline privately --
/// witness over the unconfirmed UTXO, `Forge`, `Cast` of Alice's transaction,
/// `Chain`, `Fix`, all with mock proofs on regtest -- and shares only the
/// resulting chained `SingleProof` transaction. No link transaction crosses
/// the network, and block composition is untouched: the composer picks
/// `SingleProof` transactions from the mempool exactly as today.
///
/// scenario:
/// 1. alice, bob, and charlie run a connected 3-node regtest network, all
///    single-proof capable.
/// 2. bob and charlie generate receiving addresses (out of band).
/// 3. alice mines 3 blocks to her own wallet.
/// 4. alice sends 5 coins to bob; gossip carries the transaction to
///    every mempool, and bob's wallet sees the unconfirmed funds through the
///    onchain notification.
/// 5. before any block confirms it, bob sends 3 of those coins onward to
///    charlie via a chained send.
/// 6. the chained transaction replaces alice's in every mempool, by the
///    ordinary conflict contest.
/// 7. the next block confirms alice's payment and bob's onward payment at
///    once; charlie holds 3 coins, bob his change.
#[tokio::test(flavor = "multi_thread")]
pub async fn bob_pays_charlie_with_unconfirmed_funds_from_alice() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);

    let [mut alice, mut bob, mut charlie] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(None),
        3,
        Some(base_args),
        timeout_secs,
    )
    .await?;

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;
    let charlie_address = charlie
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;

    // alice mines 3 blocks to get non-zero balance
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(3, false)
        .await?;

    // wait to allow blocks to propagate, to ensure tx is synced to all peers.
    bob.wait_until_block_height(3, timeout_secs).await?;
    charlie.wait_until_block_height(3, timeout_secs).await?;

    // alice sends 5 coins to bob, notified onchain.
    let alice_to_bob_amount = NativeCurrencyAmount::coins(5);
    let alice_fee = NativeCurrencyAmount::coins(1);
    let accept_lustrations = true;
    let alice_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address, alice_to_bob_amount)],
            Default::default(),
            alice_fee,
            Timestamp::now(),
            accept_lustrations,
        )
        .await?;
    let alice_txid = alice_artifacts.transaction().txid();

    bob.wait_until_tx_in_mempool_has_single_proof(alice_txid, timeout_secs)
        .await?;
    bob.wait_until_unconfirmed_balance(timeout_secs).await?;
    assert_eq!(
        alice_to_bob_amount,
        bob.gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .unconfirmed_available,
        "bob must see alice's unconfirmed payment"
    );

    // ## bob pays charlie 3 coins from the unconfirmed funds, before any
    // block confirms alice's payment. On bob's node alone, the chain pipeline
    // forges his link transaction, casts alice's transaction, chains the two
    // with cut-through, and fixes the result into an ordinary
    // `SingleProof`-backed transaction -- the only thing that leaves his node.
    let bob_artifacts: ChainedTxArtifacts = bob
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send_chained(
            vec![(charlie_address, NativeCurrencyAmount::coins(3))],
            Default::default(),
            NativeCurrencyAmount::coins(1),
            Timestamp::now(),
        )
        .await?;
    let chained_txid = bob_artifacts.transaction().txid();

    // The chained transaction makes it into all mempools. It conflicts with
    // Alice's transaction, and must replace Alice's tx due to a higher fee
    // density.
    for node in [&alice, &bob, &charlie] {
        node.wait_until_tx_in_mempool(chained_txid, timeout_secs)
            .await?;
        let state = node.gsl.lock_guard().await;
        assert!(
            !state.mempool().contains(alice_txid),
            "the chained transaction must replace alice's in the mempool"
        );
        assert_eq!(1, state.mempool().len());
    }

    // charlie sees incoming unconfirmed funds.
    charlie.wait_until_unconfirmed_balance(timeout_secs).await?;

    // ## the next block confirms alice's payment and bob's onward payment at
    // once.
    let include_mempool_txs = true;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await?;
    bob.wait_until_block_height(4, timeout_secs).await?;
    charlie.wait_until_block_height(4, timeout_secs).await?;

    // charlie holds 3 coins, bob his 1 coin of change, and the payment never
    // waited for a confirmation of alice's transaction.
    let charlie_balances = charlie.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        NativeCurrencyAmount::coins(3),
        charlie_balances.confirmed_available
    );
    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        NativeCurrencyAmount::coins(1),
        bob_balances.confirmed_available
    );
    for node in [&alice, &bob, &charlie] {
        assert!(
            node.gsl.lock_guard().await.mempool().is_empty(),
            "the confirmed chained transaction must leave every mempool"
        );
    }

    Ok(())
}

/// test: like [bob_pays_charlie_with_unconfirmed_funds_from_alice], but bob's
/// chained transaction stays a link transaction: the pipeline runs without
/// the final `Fix`, and the chained, cut-through `LinkTx` is inserted into
/// bob's mempool and shared with the network. No block can mine it until
/// someone fixes it; what this test checks is construction, local admission,
/// and propagation.
#[tokio::test(flavor = "multi_thread")]
pub async fn bob_pays_charlie_with_a_shared_link_transaction() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    // let the nodes run the (free) fix proof-upgrade.
    base_args.tx_proof_upgrading = true;

    let [mut alice, mut bob, mut charlie] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(None),
        3,
        Some(base_args),
        timeout_secs,
    )
    .await?;

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;
    let charlie_address = charlie
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
    charlie.wait_until_block_height(3, timeout_secs).await?;

    let alice_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address, NativeCurrencyAmount::coins(5))],
            Default::default(),
            NativeCurrencyAmount::coins(1),
            Timestamp::now(),
            true,
        )
        .await?;
    let alice_txid = alice_artifacts.transaction().txid();
    bob.wait_until_tx_in_mempool_has_single_proof(alice_txid, timeout_secs)
        .await?;
    bob.wait_until_unconfirmed_balance(timeout_secs).await?;

    // bob builds the chained link transaction and shares it.
    let bob_artifacts: LinkTxArtifacts = bob
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send_chained_link(
            vec![(charlie_address, NativeCurrencyAmount::coins(3))],
            Default::default(),
            NativeCurrencyAmount::coins(1),
            Timestamp::now(),
        )
        .await?;
    let link_txid = bob_artifacts.link_tx().txid();
    assert!(
        bob_artifacts.link_tx().kernel.thruputs.is_empty(),
        "cut-through must resolve the thruput against alice's transaction"
    );

    // the chained transaction replaces alice's in bob's own mempool. It may
    // already have been fixed by bob's own (free) proof upgrader -- `Fix`
    // keeps the txid, so both forms answer to `contains`.
    {
        let state = bob.gsl.lock_guard().await;
        assert!(state.mempool().contains(link_txid));
        assert!(!state.mempool().contains(alice_txid));
        assert_eq!(1, state.mempool().len());
    }

    // ... and propagates to the peers' mempools -- as a link, or already
    // fixed -- replacing alice's transaction there too.
    for node in [&alice, &charlie] {
        node.wait_until_chained_tx_in_mempool(link_txid, timeout_secs)
            .await?;
        assert!(!node.gsl.lock_guard().await.mempool().contains(alice_txid));
    }

    // charlie's wallet sees the incoming unconfirmed funds from the link.
    charlie.wait_until_unconfirmed_balance(timeout_secs).await?;
    assert_eq!(
        NativeCurrencyAmount::coins(3),
        charlie
            .gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .unconfirmed_available,
    );

    // some proof upgrader on the network voluntarily fixes the link -- for
    // free -- turning it into a block-eligible `SingleProof` transaction
    // under the same txid, which replaces the link in every mempool. The
    // upgrade scheduler ticks every ten seconds, so allow for that.
    let fix_timeout_secs = 30;
    bob.wait_until_tx_in_mempool_has_single_proof(link_txid, fix_timeout_secs)
        .await?;

    // the next block confirms it.
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, true)
        .await?;
    bob.wait_until_block_height(4, timeout_secs).await?;
    charlie.wait_until_block_height(4, timeout_secs).await?;

    let charlie_balances = charlie.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        NativeCurrencyAmount::coins(3),
        charlie_balances.confirmed_available
    );
    let bob_balances = bob.gsl.api().wallet().balances(Timestamp::now()).await;
    assert_eq!(
        NativeCurrencyAmount::coins(1),
        bob_balances.confirmed_available
    );
    for node in [&alice, &bob, &charlie] {
        assert!(
            node.gsl.lock_guard().await.mempool().is_empty(),
            "the confirmed chained transaction must leave every mempool"
        );
    }

    Ok(())
}

/// test: a shared link transaction survives a block that does not confirm
/// it, by the automatic mutator-set update of link transactions.
///
/// Setup as in [bob_pays_charlie_with_a_shared_link_transaction], but no node
/// runs the proof upgrader, so the link stays a link -- and the next block is
/// mined without mempool transactions, leaving the link unsynced. Nodes that
/// generated the transaction update the proof to resync the transaction.
/// Charlie holds it as a third party and re-proves nothing -- he receives the
/// updated link through gossip from the upgraders.
#[tokio::test(flavor = "multi_thread")]
pub async fn stranded_link_transaction_is_updated_to_the_new_tip() -> anyhow::Result<()> {
    logging::tracing_logger();
    let timeout_secs = 15;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);

    let [mut alice, mut bob, mut charlie] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(Some(1)),
        3,
        Some(base_args),
        timeout_secs,
    )
    .await?;

    let bob_address = bob
        .gsl
        .api_mut()
        .wallet_mut()
        .next_receiving_address(KeyType::Generation)
        .await?;
    let charlie_address = charlie
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
    charlie.wait_until_block_height(3, timeout_secs).await?;

    let alice_artifacts = alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(bob_address, NativeCurrencyAmount::coins(5))],
            Default::default(),
            NativeCurrencyAmount::coins(1),
            Timestamp::now(),
            true,
        )
        .await?;
    let alice_txid = alice_artifacts.transaction().txid();
    bob.wait_until_tx_in_mempool_has_single_proof(alice_txid, timeout_secs)
        .await?;
    bob.wait_until_unconfirmed_balance(timeout_secs).await?;

    let bob_artifacts: LinkTxArtifacts = bob
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send_chained_link(
            vec![(charlie_address, NativeCurrencyAmount::coins(3))],
            Default::default(),
            NativeCurrencyAmount::coins(1),
            Timestamp::now(),
        )
        .await?;
    let link_txid = bob_artifacts.link_tx().txid();
    let stale_mutator_set_hash = bob_artifacts.link_tx().kernel.kernel.mutator_set_hash;

    for node in [&alice, &bob, &charlie] {
        node.wait_until_link_tx_in_mempool(link_txid, timeout_secs)
            .await?;
    }

    // The block does not mine a mempool transaction, so the transaction can be
    // included in the next block.
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await?;
    bob.wait_until_block_height(4, timeout_secs).await?;
    charlie.wait_until_block_height(4, timeout_secs).await?;

    // Bob and Alice update the transaction proof, since the transaction
    // originate from them. The updated transaction is shared with Charlie.
    for node in [&alice, &bob, &charlie] {
        let tip_mutator_set_hash = node
            .gsl
            .lock_guard()
            .await
            .chain
            .tip()
            .mutator_set_accumulator_after()?
            .hash();
        assert_ne!(stale_mutator_set_hash, tip_mutator_set_hash);
        node.wait_until_link_tx_synced(link_txid, tip_mutator_set_hash, timeout_secs)
            .await?;
        let state = node.gsl.lock_guard().await;
        let link = state.mempool().get_link(link_txid).unwrap();
        assert!(link.kernel.thruputs.is_empty());
    }

    Ok(())
}
