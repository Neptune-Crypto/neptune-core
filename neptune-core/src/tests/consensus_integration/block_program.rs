use macro_rules_attr::apply;
use neptune_primitives::timestamp::Timestamp;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tracing_test::traced_test;

use crate::application::config::cli_args;
use crate::application::loops::mine_loop::create_block_transaction_from;
use crate::application::loops::mine_loop::TxMergeOrigin;
use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::network::Network;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::proof_abstractions::tx_proving_capability::TxProvingCapability;
use crate::state::transaction::tx_creation_config::TxCreationConfig;
use crate::state::wallet::transaction_output::TxOutput;
use crate::state::wallet::wallet_entropy::WalletEntropy;
use crate::tests::shared::globalstate::mock_genesis_global_state;
use crate::tests::shared_tokio_runtime;
use crate::GlobalStateLock;

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn disallow_double_spends_across_blocks() {
    async fn mine_txs(
        state: &GlobalStateLock,
        txs: Vec<Transaction>,
        timestamp: Timestamp,
    ) -> Block {
        let predecessor = state.lock_guard().await.chain.tip().to_owned();
        let job_options = TritonVmProofJobOptions::default_with_network(state.cli().network);
        let (block_tx, _) = create_block_transaction_from(
            &predecessor,
            state.clone(),
            timestamp,
            job_options.clone(),
            TxMergeOrigin::ExplicitList(txs),
        )
        .await
        .unwrap();

        Block::compose(
            predecessor,
            block_tx,
            timestamp,
            TritonVmJobQueue::get_instance(),
            job_options.clone(),
        )
        .await
        .unwrap()
    }

    let network = Network::Testnet(42);
    let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
    let alice_wallet = WalletEntropy::devnet_wallet();
    let mut alice = mock_genesis_global_state(
        3,
        WalletEntropy::devnet_wallet(),
        cli_args::Args::default_with_network(network),
    )
    .await;

    let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
    let fee = NativeCurrencyAmount::coins(1);
    let tx_output = TxOutput::offchain_native_currency(
        NativeCurrencyAmount::coins(1),
        rng.random(),
        alice_key.to_address().into(),
        false,
    );

    let genesis_block = Block::genesis(network);

    // On networks where the gamma rule set (and thus lustration) is active from
    // genesis, block 1 *defines* the lustration status and its transactions are
    // exempt; only blocks at height 2 and above enforce lustration. So mine an
    // empty block 1 first and create the transaction against *that* tip -- then
    // it carries the lustration announcements that block 2, and the update into
    // block 3, require.
    let block1_timestamp = genesis_block.header().timestamp + Timestamp::months(11);
    let block1 = mine_txs(&alice, vec![], block1_timestamp).await;
    alice.set_new_tip(block1.clone()).await.unwrap();

    let now = genesis_block.header().timestamp + Timestamp::months(12);
    let config = TxCreationConfig::default()
        .recover_change_off_chain(alice_key.into())
        .with_network(network)
        .with_prover_capability(TxProvingCapability::SingleProof);

    let consensus_rule_set = ConsensusRuleSet::infer_from(network, block1.header().height.next());
    let tx: Transaction = alice
        .api()
        .tx_initiator_internal()
        .create_transaction(vec![tx_output].into(), fee, now, config, consensus_rule_set)
        .await
        .unwrap()
        .transaction
        .into();
    let block2 = mine_txs(&alice, vec![tx.clone()], now).await;
    alice.set_new_tip(block2.clone()).await.unwrap();

    // Update transaction, stick it into block 3, and verify that block 3
    // is invalid.
    let later = now + Timestamp::months(1);
    let tx = Transaction::new_with_updated_mutator_set_records_given_proof(
        tx.kernel,
        &block1.mutator_set_accumulator_after().unwrap(),
        &block2.mutator_set_update().unwrap(),
        tx.proof.into_single_proof(),
        TritonVmJobQueue::get_instance(),
        TritonVmProofJobOptions::default_with_network(network),
        Some(later),
        consensus_rule_set,
    )
    .await
    .unwrap();

    let block3 = mine_txs(&alice, vec![tx], later).await;
    assert_eq!(
        BlockValidationError::RemovalRecordsValidity,
        block3.validate(&block2, later, network,).await.unwrap_err(),
        "Block doing a double-spend must be invalid."
    );
}
