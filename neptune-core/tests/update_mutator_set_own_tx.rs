mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::TxProvingCapability;
use rand::Rng;
use tracing_test::traced_test;

/// Test: Alice creates a proof-collection backed transaction.
///
/// this is a test that proof collection backed transactions are updated on the
/// receival of new blocks.
///
/// Scenario:
/// 1. Single unconnected node on regtest network
/// 2. Alice mines 2 blocks to her own wallet
/// 3. Alice inserts a primitive witness/proof collection/single proof backed tx
///    into her mempool
/// 4. Alice receives a new block that does not include her transaction
/// 5. Verify that Alice's proof-collection backed transaction is updated
///    after the processing of the new block.
#[traced_test]
#[tokio::test(flavor = "multi_thread")]
pub async fn alice_updates_mutator_set_data_on_own_transaction() {
    logging::tracing_logger();

    let mut rng = rand::rng();
    for tx_proving_capability in [
        TxProvingCapability::PrimitiveWitness,
        TxProvingCapability::ProofCollection,
        TxProvingCapability::SingleProof,
    ] {
        let mut cli_args = GenesisNode::default_args().await;
        cli_args.tx_proving_capability = Some(tx_proving_capability);

        // random ports to prevent multiple test runs from using same
        // socket.
        cli_args.peer_port = rng.random_range((1 << 10)..=u16::MAX);
        cli_args.rpc_port = rng.random_range((1 << 10)..=u16::MAX);
        let mut alice = GenesisNode::start_node(cli_args).await.unwrap();

        // Mine two blocks to get a positive balance
        alice
            .gsl
            .api_mut()
            .regtest_mut()
            .mine_blocks_to_wallet(2, false)
            .await
            .unwrap();
        assert_eq!(
            BlockHeight::from(2u64),
            alice
                .gsl
                .lock_guard()
                .await
                .chain
                .light_state()
                .header()
                .height,
            "Expected block height: 2"
        );

        // Generate an address
        let alice_address = alice
            .gsl
            .api_mut()
            .wallet_mut()
            .next_receiving_address(KeyType::Generation)
            .await
            .unwrap();

        // Create transaction to self
        let tx_artifacts = alice
            .gsl
            .api_mut()
            .tx_sender_mut()
            .send(
                vec![(
                    alice_address,
                    NativeCurrencyAmount::coins_from_str("2.45").unwrap(),
                )],
                Default::default(),
                NativeCurrencyAmount::coins(1),
                Timestamp::now(),
            )
            .await
            .unwrap();

        assert_eq!(1, alice.gsl.lock_guard().await.mempool.len());

        // Wait until tx has right proof quality
        let timeout_secs = 10;

        let txid = tx_artifacts.transaction().txid();
        match tx_proving_capability {
            TxProvingCapability::LockScript => unreachable!("Not testing this"),
            TxProvingCapability::PrimitiveWitness => alice
                .wait_until_tx_in_mempool(txid, timeout_secs)
                .await
                .unwrap(),
            TxProvingCapability::ProofCollection => alice
                .wait_until_tx_in_mempool_has_proof_collection(txid, timeout_secs)
                .await
                .unwrap(),
            TxProvingCapability::SingleProof => alice
                .wait_until_tx_in_mempool_has_single_proof(
                    tx_artifacts.transaction().txid(),
                    timeout_secs,
                )
                .await
                .unwrap(),
        };

        assert_eq!(1, alice.gsl.lock_guard().await.mempool.len());

        // Mine one block that does *not* include the transaction, and verify
        // that transaction stays in the mempool, and that it eventually gets
        // updated to the new mutator set.
        let mine_mempool_txs = false;
        alice
            .gsl
            .api_mut()
            .regtest_mut()
            .mine_blocks_to_wallet(1, mine_mempool_txs)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        assert_eq!(1, alice.gsl.lock_guard().await.mempool.len());

        let tip = alice.gsl.lock_guard().await.chain.light_state().clone();
        assert_eq!(
            BlockHeight::from(3u64),
            tip.header().height,
            "Expected block height: 3"
        );

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let tip_msa = tip.mutator_set_accumulator_after().unwrap();
        let tx_upgrade_timeout_secs = 15;
        alice
            .wait_until_tx_in_mempool_confirmable(
                tx_artifacts.transaction().txid(),
                &tip_msa,
                tx_upgrade_timeout_secs,
            )
            .await
            .unwrap();

        // Sleep to give application time to send all messages before receivers
        // are dropped. When the application shuts down after it goes out of
        // scope all messages must have been sent, otherwise there might be a
        // sender without a receiver and that causes a panic.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // Verify that transaction is confirmable against tip.
        let txid = tx_artifacts.transaction().txid();
        let tx = alice
            .gsl
            .lock_guard()
            .await
            .mempool
            .get(txid)
            .unwrap()
            .to_owned();
        assert!(tx.is_confirmable_relative_to(&tip.mutator_set_accumulator_after().unwrap()));
    }
}
