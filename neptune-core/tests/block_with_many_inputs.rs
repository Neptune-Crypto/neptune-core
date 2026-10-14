mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::transaction::transaction_proof::TransactionProofType;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::KeyType;
use num_traits::Zero;

/// test: a block spending hundreds of inputs propagates between nodes
///
/// scenario:
/// 1. alice and bob run a 2-node regtest network, from genesis.
/// 2. alice mines 3 blocks to her own wallet.
/// 3. alice pays many small outputs to herself and mines them into a block.
/// 4. alice spends her whole balance, consuming all of those outputs, and
///    mines that transaction into a block.
/// 5. bob receives both blocks and ends on the same tip as alice.
#[tokio::test(flavor = "multi_thread")]
pub async fn block_with_many_inputs_propagates() -> anyhow::Result<()> {
    const NUM_INPUTS: usize = 400;

    logging::tracing_logger();
    let timeout_secs = 120;

    let mut base_args = GenesisNode::default_args().await;
    base_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);
    let [mut alice, bob] = GenesisNode::start_connected_cluster(
        &GenesisNode::cluster_id(None),
        2,
        Some(base_args),
        timeout_secs,
    )
    .await?;

    let alice_address = alice
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

    // Fan out: one transaction paying many small outputs to alice herself.
    let accept_lustrations = true;
    let include_mempool_txs = true;
    let small_output = (
        alice_address.clone(),
        NativeCurrencyAmount::coins_from_str("0.01")?,
    );
    alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![small_output; NUM_INPUTS],
            Default::default(),
            NativeCurrencyAmount::zero(),
            Timestamp::now(),
            accept_lustrations,
        )
        .await?;
    alice
        .wait_until_n_txs_in_mempool(1, TransactionProofType::SingleProof, timeout_secs)
        .await?;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await?;
    bob.wait_until_block_height(4, timeout_secs).await?;

    // Fan in: spending the whole balance consumes every one of them.
    let balance = alice
        .gsl
        .api()
        .wallet()
        .balances(Timestamp::now())
        .await
        .confirmed_available;
    alice
        .gsl
        .api_mut()
        .tx_sender_mut()
        .send(
            vec![(alice_address, balance)],
            Default::default(),
            NativeCurrencyAmount::zero(),
            Timestamp::now(),
            accept_lustrations,
        )
        .await?;
    alice
        .wait_until_n_txs_in_mempool(1, TransactionProofType::SingleProof, timeout_secs)
        .await?;
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, include_mempool_txs)
        .await?;

    let alice_tip = alice.gsl.lock_guard().await.chain.tip().clone();
    let num_inputs = alice_tip.body().transaction_kernel.inputs.len();
    assert!(num_inputs >= NUM_INPUTS, "block spends {num_inputs} inputs");

    bob.wait_until_block_height(alice_tip.header().height, timeout_secs)
        .await?;
    let bob_tip = bob.gsl.lock_guard().await.chain.tip().clone();
    assert_eq!(alice_tip.hash(), bob_tip.hash());

    Ok(())
}
