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
use crate::protocol::proof_abstractions::triton_vm_job_queue::TritonVmJobPriority;
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
    async fn mine_tx(state: &GlobalStateLock, tx: Transaction, timestamp: Timestamp) -> Block {
        let predecessor = state.lock_guard().await.chain.tip().to_owned();
        let (block_tx, _) = create_block_transaction_from(
            &predecessor,
            state.clone(),
            timestamp,
            TritonVmProofJobOptions::default(),
            TxMergeOrigin::ExplicitList(vec![tx]),
        )
        .await
        .unwrap();

        Block::compose(
            predecessor,
            block_tx,
            timestamp,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    let network = Network::Main;
    let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
    let alice_wallet = WalletEntropy::devnet_wallet();
    let mut alice =
        mock_genesis_global_state(3, WalletEntropy::devnet_wallet(), cli_args::Args::default())
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
    let now = genesis_block.header().timestamp + Timestamp::months(12);
    let config = TxCreationConfig::default()
        .recover_change_off_chain(alice_key.into())
        .with_prover_capability(TxProvingCapability::SingleProof);

    let consensus_rule_set =
        ConsensusRuleSet::infer_from(network, genesis_block.header().height.next());
    let tx: Transaction = alice
        .api()
        .tx_initiator_internal()
        .create_transaction(vec![tx_output].into(), fee, now, config, consensus_rule_set)
        .await
        .unwrap()
        .transaction
        .into();
    let block1 = mine_tx(&alice, tx.clone(), now).await;
    alice.set_new_tip(block1.clone()).await.unwrap();

    // Update transaction, stick it into block 2, and verify that block 2
    // is invalid.
    let later = now + Timestamp::months(1);
    let tx = Transaction::new_with_updated_mutator_set_records_given_proof(
        tx.kernel,
        &genesis_block.mutator_set_accumulator_after().unwrap(),
        &block1.mutator_set_update().unwrap(),
        tx.proof.into_single_proof(),
        TritonVmJobQueue::get_instance(),
        TritonVmJobPriority::default().into(),
        Some(later),
        consensus_rule_set,
    )
    .await
    .unwrap();

    let block2 = mine_tx(&alice, tx, later).await;
    assert_eq!(
        BlockValidationError::RemovalRecordsValidity,
        block2.validate(&block1, later, network,).await.unwrap_err(),
        "Block doing a double-spend must be invalid."
    );
}
