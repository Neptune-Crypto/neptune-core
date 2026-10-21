use std::sync::Arc;

use itertools::Itertools;
use neptune_consensus::block::block_appendix::BlockAppendix;
use neptune_consensus::block::block_validation_error::BlockValidationError;
use neptune_consensus::block::pow::LustrationStatus;
use neptune_consensus::block::test_helpers::invalid_block_with_tx_kernel;
use neptune_consensus::block::test_helpers::invalid_empty_block;
use neptune_consensus::block::validity::predecessor_is_valid::PredecessorIsValid;
use neptune_consensus::block::Block;
use neptune_consensus::block::BlockProof;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::consensus_rule_set::BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET;
use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use neptune_consensus::proof_abstractions::triton_vm_job_queue::vm_job_queue;
use neptune_consensus::proof_abstractions::tx_proving_capability::TxProvingCapability;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
use neptune_consensus::transaction::transaction_proof::TransactionProofType;
use neptune_consensus::transaction::validity::neptune_proof::NeptuneProof;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::address::generation_address::GenerationReceivingAddress;
use neptune_wallet::address::KeyType;
use neptune_wallet::address::ReceivingAddress;
use neptune_wallet::change_policy::ChangePolicy;
use neptune_wallet::expected_utxo::ExpectedUtxo;
use neptune_wallet::utxo_notification::UtxoNotificationMedium;
use neptune_wallet::wallet_entropy::WalletEntropy;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::RngExt;
use rand::SeedableRng;
use tasm_lib::prelude::Digest;
use tracing_test::traced_test;

use crate::api::export::GlobalStateLock;
use crate::api::export::InputCandidate;
use crate::api::export::InputSelectionPriority;
use crate::api::export::OutputFormat;
use crate::api::export::StateLock;
use crate::api::export::TxCreationArtifacts;
use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
use crate::api::tx_initiation::builder::input_selector::InputSelector;
use crate::api::tx_initiation::builder::input_selector::SortOrder;
use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
use crate::api::tx_initiation::error;
use crate::application::config::cli_args;
use crate::application::loops::mine_loop::compose_block_helper;
use crate::tests::shared::blocks::compose_and_guess_for_tests;
use crate::tests::shared::blocks::guess_for_tests;
use crate::tests::shared::globalstate::mock_genesis_global_state;
use crate::tests::shared::globalstate::mock_genesis_global_state_with_block;

/// Send n outputs to the same address.
///
/// If no address is provided, the next viewing address will be used.
pub(crate) async fn tx_with_n_outputs(
    mut state: GlobalStateLock,
    num_outputs: usize,
    timestamp: Timestamp,
    input_selection_policy: Option<InputSelectionPolicy>,
    address: Option<ReceivingAddress>,
    amt_per_output: Option<NativeCurrencyAmount>,
) -> Result<TxCreationArtifacts, error::CreateTxError> {
    let address = match address {
        Some(addr) => addr,
        None => state
            .api()
            .wallet_mut()
            .next_receiving_address(KeyType::ViewingAddress)
            .await
            .unwrap(),
    };

    let amt_per_output = amt_per_output.unwrap_or(NativeCurrencyAmount::from_nau(1));
    let mut addresses_and_amts = vec![];
    for _ in 0..num_outputs {
        let value = OutputFormat::AddressAndAmountAndMedium(
            address.clone(),
            amt_per_output,
            UtxoNotificationMedium::OnChain,
        );
        addresses_and_amts.push(value);
    }

    let lustration_threshold = state.lock_guard().await.chain.lustration_threshold();
    let initiator = state.api().tx_initiator();
    let tx_outputs = initiator.generate_tx_outputs(addresses_and_amts).await;
    drop(initiator);

    let fee = NativeCurrencyAmount::from_nau(14);

    let unlocked_inputs = {
        let state_lock = state.lock_guard().await;
        let validator = state_lock.utxo_validator();
        let wallet_status = state_lock.wallet_state.get_wallet_status(&validator).await;
        let spendable_inputs = wallet_status.spendable_inputs(timestamp);
        let current_height = state_lock.chain.tip().header().height;
        let input_candidates = spendable_inputs
            .into_iter()
            .map(|synced_utxo| InputCandidate::from_synced_utxo(synced_utxo, current_height))
            .collect();

        let policy = input_selection_policy.unwrap_or(
            InputSelectionPolicy::default()
                .prioritize(InputSelectionPriority::ByUtxoSize(SortOrder::Ascending)),
        );
        let selected_inputs = InputSelector::new(lustration_threshold)
            .input_candidates(input_candidates)
            .policy(policy)
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build()?;

        println!(
            "Selected inputs: [{}]",
            selected_inputs.iter().map(|x| x.aocl_leaf_index).join(", ")
        );

        state_lock.unlock_inputs(selected_inputs).await
    };

    let tx_details = TransactionDetailsBuilder::new()
        .inputs(unlocked_inputs)
        .outputs(tx_outputs)
        .fee(fee)
        .timestamp(timestamp)
        .build(&mut StateLock::write_guard(&mut state).await)
        .await
        .unwrap();

    // use cli options for building proof, but override proof-type
    let network = state.cli().network;
    let options = TritonVmProofJobOptionsBuilder::new()
        .network(network)
        .proof_type(TransactionProofType::SingleProof)
        .proving_capability(TxProvingCapability::SingleProof)
        .build();

    // generate proof
    let block_height = state.lock_guard().await.chain.tip().header().height;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height);
    let proof = TransactionProofBuilder::new()
        .consensus_rule_set(consensus_rule_set)
        .transaction_details(&tx_details)
        .job_queue(vm_job_queue())
        .proof_job_options(options)
        .build()
        .await
        .unwrap();

    let transaction = TransactionBuilder::new()
        .transaction_details(&tx_details)
        .transaction_proof(proof)
        .build()
        .unwrap();

    Ok(TxCreationArtifacts {
        transaction: Arc::new(transaction),
        details: Arc::new(tx_details),
    })
}

async fn mine_to_own_wallet(
    me: GlobalStateLock,
    timestamp: Timestamp,
) -> (Block, Vec<ExpectedUtxo>) {
    let current_tip = me.lock_guard().await.chain.archival_state().get_tip().await;
    let (mut block, expected_composer_utxos) = compose_block_helper(
        current_tip,
        me.clone(),
        timestamp,
        TritonVmProofJobOptions::default_with_network(me.cli().network),
    )
    .await
    .unwrap()
    .unwrap();
    // Guess for the node's own guesser address, as its guesser would.
    let (guesser_address, _) = me.lock_guard().await.mining_rewards_address();
    block.set_header_guesser_data(guesser_address.into());
    guess_for_tests(&mut block, &me).await;
    (block, expected_composer_utxos)
}

/// Build on a stand-in genesis block at height 99,999, named as the
/// network's genesis block, so that every block is built under the rule set
/// in force at a large height.
async fn new_blocks_at_block_height_100_000_on(network: Network) {
    let fake_genesis = Block::fake_genesis_at_height(network, BlockHeight::from(99_999u64));
    fake_genesis.name_as_genesis(network);
    let mut rng = StdRng::seed_from_u64(55512345);
    let bob_wallet = WalletEntropy::new_pseudorandom(rng.random());
    let cli = cli_args::Args {
        network,
        compose: true,
        guess: true,
        tx_proving_capability: Some(TxProvingCapability::SingleProof),
        number_of_mps_per_utxo: 3,
        ..Default::default()
    };
    let mut bob =
        mock_genesis_global_state_with_block(0, bob_wallet, cli, fake_genesis.clone()).await;
    let mut now = fake_genesis.header().timestamp;

    // 1. get a positive balance, by mining.
    let blocks_to_mine = 3;
    let mut predecessor = fake_genesis;
    for _ in 0..blocks_to_mine {
        now += Timestamp::hours(1);
        let (next_block, expected_composer_utxos) = mine_to_own_wallet(bob.clone(), now).await;
        assert!(next_block.is_valid(&predecessor, now, network).await);
        bob.set_new_self_composed_tip(next_block.clone(), expected_composer_utxos)
            .await
            .unwrap();
        predecessor = next_block;
    }

    let hopefully_plus_3 = bob.lock_guard().await.chain.tip().header().height;
    assert_eq!(BlockHeight::from(100_002u64), hopefully_plus_3);
    assert!(
        bob.api()
            .wallet()
            .balances(now)
            .await
            .confirmed_available
            .is_positive(),
        "Bob must have money"
    );
    let bob_spendable_inputs = bob
        .lock_guard()
        .await
        .wallet_spendable_inputs_at_time(now)
        .await;

    // Bob composes and guesses, so each block pays him a liquid reward of
    // each kind.
    assert_eq!(
        2 * blocks_to_mine,
        bob_spendable_inputs.len(),
        "Bob must have {} spendable inputs after mining {blocks_to_mine} blocks",
        2 * blocks_to_mine
    );

    // 2. create blocks with enough outputs to give some/all owned UTXOs
    //    non-empty chunk dictionaries. This serves to check that the
    //    membership proofs/removal records are updated correctly.
    let num_blocks_with_many_outputs = 3;
    for _ in 0..num_blocks_with_many_outputs {
        now += Timestamp::hours(1);
        // Inputs this early look like lustration candidates to the wallet.
        let lustrating = InputSelectionPolicy::default().set_lustration_acceptance(true);
        let tx = tx_with_n_outputs(bob.clone(), 24, now, Some(lustrating), None, None)
            .await
            .unwrap();
        let next_block = compose_and_guess_for_tests(&bob, vec![tx.transaction.into()], now).await;
        assert!(next_block.is_valid(&predecessor, now, network).await);
        bob.set_new_tip(next_block.clone()).await.unwrap();
        predecessor = next_block;
    }
}

#[traced_test]
#[tokio::test]
async fn new_blocks_at_block_height_100_000_on_main_net() {
    new_blocks_at_block_height_100_000_on(Network::Main).await;
}

#[traced_test]
#[tokio::test]
async fn new_blocks_at_block_height_100_000_on_testnet_42() {
    new_blocks_at_block_height_100_000_on(Network::Testnet(42)).await;
}

#[traced_test]
#[tokio::test]
async fn new_blocks_at_block_height_100_000_with_mock_proofs() {
    new_blocks_at_block_height_100_000_on(Network::TestnetMock).await;
}

/// A block on the stand-in genesis block passes every rule but the proof,
/// and the archival mutator set follows it.
#[tokio::test]
async fn fake_genesis_on_main_net_accepts_a_successor() {
    let network = Network::Main;
    let activation = BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET;
    let fake_genesis = Block::fake_genesis_at_height(network, activation.checked_sub(2).unwrap());
    let mut successor = invalid_empty_block(&fake_genesis, network);
    let claims = BlockAppendix::mock_consensus_claims(successor.body(), &fake_genesis, network);
    successor.set_appendix(BlockAppendix::new(claims));
    let now = successor.header().timestamp;
    assert_eq!(
        Err(BlockValidationError::ProofQuality),
        successor
            .validate_proposal(&fake_genesis, now, network)
            .await
    );

    let mut bob = mock_genesis_global_state_with_block(
        0,
        WalletEntropy::new_random(),
        cli_args::Args::default_with_network(network),
        fake_genesis,
    )
    .await;
    bob.set_new_tip(successor.clone()).await.unwrap();
    let archival_mutator_set = bob
        .lock_guard()
        .await
        .chain
        .archival_state()
        .archival_mutator_set
        .ams()
        .accumulator()
        .await;
    assert_eq!(
        successor.mutator_set_accumulator_after().unwrap().hash(),
        archival_mutator_set.hash()
    );
}

#[traced_test]
#[tokio::test]
async fn blocks_across_epsilon_activation_on_main_net() {
    let network = Network::Main;
    let activation = BLOCK_HEIGHT_SOFTFORK_EPSILON_MAIN_NET;
    let fake_genesis = Block::fake_genesis_at_height(network, activation.checked_sub(2).unwrap());
    let mut rng = StdRng::seed_from_u64(55512345);
    let cli = cli_args::Args {
        network,
        tx_proving_capability: Some(TxProvingCapability::SingleProof),
        ..Default::default()
    };
    let mut bob = mock_genesis_global_state_with_block(
        0,
        WalletEntropy::new_pseudorandom(rng.random()),
        cli,
        fake_genesis.clone(),
    )
    .await;

    // Mine the last block of delta, the first block of epsilon and one more.
    let mut now = fake_genesis.header().timestamp;
    let mut blocks = vec![];
    for _ in 0..3 {
        now += Timestamp::hours(1);
        let predecessor = bob.lock_guard().await.chain.tip().to_owned();
        let (block, expected_composer_utxos) = mine_to_own_wallet(bob.clone(), now).await;
        assert!(block.is_valid(&predecessor, now, network).await);
        bob.set_new_self_composed_tip(block.clone(), expected_composer_utxos)
            .await
            .unwrap();
        blocks.push(block);
    }
    assert_eq!(activation.previous().unwrap(), blocks[0].header().height);

    // The delta block contains the transaction's claim only; the epsilon
    // block also contains the claim about its predecessor.
    assert_eq!(1, blocks[0].appendix().len());
    let predecessor_claim =
        PredecessorIsValid::claim_about(&blocks[0], blocks[1].body().mast_hash(), network);
    assert!(blocks[1].appendix().find(&predecessor_claim).is_some());
    assert!(
        bob.api()
            .wallet()
            .balances(now)
            .await
            .confirmed_available
            .is_positive(),
        "Bob must have money"
    );

    // Confirm transactions with enough outputs to give Bob's UTXOs
    // non-empty chunk dictionaries.
    for _ in 0..3 {
        now += Timestamp::hours(1);
        let predecessor = bob.lock_guard().await.chain.tip().to_owned();
        // Inputs this early look like lustration candidates to the wallet.
        let lustrating = InputSelectionPolicy::default().set_lustration_acceptance(true);
        let tx = tx_with_n_outputs(bob.clone(), 24, now, Some(lustrating), None, None)
            .await
            .unwrap();
        let block = compose_and_guess_for_tests(&bob, vec![tx.transaction.into()], now).await;
        assert!(block.is_valid(&predecessor, now, network).await);
        bob.set_new_tip(block).await.unwrap();
    }
    assert_eq!(
        activation + 4,
        bob.lock_guard().await.chain.tip().header().height
    );
}

#[traced_test]
#[tokio::test]
async fn lustration_counter_errors() {
    async fn assert_error(mut block: Block, parent: &Block, expected_error: BlockValidationError) {
        let network = Network::RegTest;
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block.header().height);
        assert!(consensus_rule_set.requires_lustration_status_in_block_header());

        let appendix = BlockAppendix::mock_consensus_claims(block.body(), parent, network);
        block.set_appendix(BlockAppendix::new(appendix));
        block.set_proof(BlockProof::SingleProof(NeptuneProof::valid_mock()));
        block.set_lustration_status(parent.header().pow.lustration_status().unwrap());

        let now = block.header().timestamp;
        assert_eq!(
            expected_error,
            block.validate(parent, now, network).await.unwrap_err()
        );
    }

    let network = Network::RegTest;
    let genesis = Block::genesis(network);
    let cli = cli_args::Args::default_with_network(network);
    let mut premine_receiver =
        mock_genesis_global_state(2, WalletEntropy::devnet_wallet(), cli).await;
    let mut parent = genesis;
    for _ in 0..30 {
        let block = invalid_empty_block(&parent, network);
        premine_receiver.set_new_tip(block.clone()).await.unwrap();
        parent = block;
    }

    // Set lustration counter to zero to trigger a negative lustration
    // counter when validating the next block.
    parent.set_lustration_status(LustrationStatus {
        counter: NativeCurrencyAmount::zero(),
        max_lustrating_aocl_leaf_index: 0,
    });

    premine_receiver.set_new_tip(parent.clone()).await.unwrap();

    // Now make a non-lustrating transaction
    let outputs = vec![OutputFormat::AddressAndAmount(
        GenerationReceivingAddress::derive_from_seed(Digest::default()).into(),
        NativeCurrencyAmount::coins(3),
    )];
    let fee = NativeCurrencyAmount::coins(1);
    let timestamp = parent.header().timestamp + Timestamp::months(6);
    let accept_lustrations = true;
    let tx = premine_receiver
        .api_mut()
        .tx_sender_mut()
        .send(
            outputs,
            ChangePolicy::Burn,
            fee,
            timestamp,
            accept_lustrations,
        )
        .await
        .unwrap();
    let kernel_with_lustration = tx.transaction.kernel.clone();
    let kernel_without_lustration = TransactionKernelModifier::default()
        .announcements(vec![])
        .modify(tx.transaction.kernel.clone());
    assert!(kernel_without_lustration.announcements.is_empty());
    assert!(!kernel_with_lustration.announcements.is_empty());

    let missing_lustrations: Block =
        invalid_block_with_tx_kernel(&parent, kernel_without_lustration);
    assert_error(
        missing_lustrations,
        &parent,
        BlockValidationError::MissingLustrationAnnouncement,
    )
    .await;
    let makes_counter_negative: Block =
        invalid_block_with_tx_kernel(&parent, kernel_with_lustration);
    assert_error(
        makes_counter_negative,
        &parent,
        BlockValidationError::NegativeLustrationCounter {
            // Input to above tx is 20, since premine receiver has only
            // 1 UTXO in their wallet.
            got: -NativeCurrencyAmount::coins(20),
        },
    )
    .await;
}
