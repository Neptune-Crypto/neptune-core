use macro_rules_attr::apply;
use neptune_consensus::block::block_appendix::BlockAppendix;
use neptune_consensus::block::block_transaction::BlockTransaction;
use neptune_consensus::block::block_validation_error::BlockValidationError;
use neptune_consensus::block::mutator_set_update::MutatorSetCatchUp;
use neptune_consensus::block::test_helpers::invalid_empty_block_with_timestamp;
use neptune_consensus::block::Block;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use neptune_consensus::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::transaction::Transaction;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::transaction_output::TxOutput;
use neptune_wallet::wallet_entropy::WalletEntropy;
use rand::rngs::StdRng;
use rand::RngExt;
use rand::SeedableRng;
use tracing_test::traced_test;

use crate::application::config::cli_args;
use crate::application::loops::mine_loop::create_block_transaction_from;
use crate::application::loops::mine_loop::TxMergeOrigin;
use crate::state::transaction::tx_creation_config::TxCreationConfig;
use crate::tests::shared::blocks::guess_for_tests;
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

        let witness = state
            .lock_guard()
            .await
            .composer_witness(&predecessor)
            .await
            .unwrap();
        let (mut block, _) = Block::compose(
            predecessor,
            block_tx,
            timestamp,
            witness,
            TritonVmJobQueue::get_instance(),
            job_options.clone(),
        )
        .await
        .unwrap();
        guess_for_tests(&mut block, state).await;
        block
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
    let catch_up = MutatorSetCatchUp::from_update(
        &block1.mutator_set_accumulator_after().unwrap(),
        &tx.kernel.inputs,
        &block2.mutator_set_update(network).unwrap(),
    )
    .unwrap();
    let tx = Transaction::new_with_updated_mutator_set_records_given_proof(
        tx.kernel,
        &block1.mutator_set_accumulator_after().unwrap(),
        &catch_up,
        tx.proof.into_single_proof(),
        TritonVmJobQueue::get_instance(),
        TritonVmProofJobOptions::default_with_network(network),
        Some(later),
        consensus_rule_set,
    )
    .await
    .unwrap();

    // Build block manually since composer refuses to prove a double spend.
    let mut block3 = invalid_empty_block_with_timestamp(&block2, later, network);
    block3.set_transaction_kernel(BlockTransaction::from_tx_kernel(tx.kernel).kernel().clone());
    let claims = BlockAppendix::consensus_claims(
        block3.body(),
        block3.header().height,
        block2.hash(),
        &block2.mutator_set_accumulator_after().unwrap(),
        network,
    );
    block3.set_appendix(BlockAppendix::new(claims));
    assert_eq!(
        BlockValidationError::RemovalRecordsValidity,
        block3
            .validate_proposal(&block2, later, network)
            .await
            .unwrap_err(),
        "Double-spending block must be invalid."
    );
}
