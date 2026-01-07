use strum_macros::EnumIter;

use crate::api::export::BlockHeight;
use crate::api::export::Network;
use crate::protocol::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::BFieldElement;

/// Height of 1st block that follows the alpha consensus ruleset, for main net.
pub const BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(15_000u64));

/// Height of 1st block that follows the alpha consensus ruleset, for main net.
pub const BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(25_000u64));

/// Height of 1st block that follows the alpha consensus ruleset, for test net.
pub const BLOCK_HEIGHT_HARDFORK_ALPHA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(12064));

/// Height of 1st block that follows the beta consensus ruleset, for test net.
pub const BLOCK_HEIGHT_HARDFORK_BETA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(3500u64));

/// Enumerates all possible sets of consensus rules.
///
/// Specifically, this enum captures *differences* between consensus rules,
/// across
///  - networks, and
///  - hard and soft forks triggered by blocks.
///
/// Consensus logic not captured by this encapsulation lives on
/// [`Transaction::is_valid`][super::transaction::Transaction::is_valid] and
/// ultimately [`Block::is_valid`][super::block::Block::is_valid].
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, Default, strum_macros::Display)]
pub enum ConsensusRuleSet {
    #[default]
    Reboot,
    HardforkAlpha,
    HardforkBeta,
}

impl ConsensusRuleSet {
    /// Maximum block size in number of BFieldElements
    pub(crate) const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::HardforkBeta => {
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space.
                1_000_000
            }
        }
    }

    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks can activate at different
    /// heights based on the network.
    pub(crate) fn infer_from(network: Network, block_height: BlockHeight) -> Self {
        match network {
            Network::Main => {
                if block_height < BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET {
                    ConsensusRuleSet::HardforkAlpha
                } else {
                    ConsensusRuleSet::HardforkBeta
                }
            }
            Network::TestnetMock => ConsensusRuleSet::HardforkBeta,
            Network::RegTest => ConsensusRuleSet::HardforkBeta,
            Network::Testnet(_) => {
                if block_height < BLOCK_HEIGHT_HARDFORK_ALPHA_TESTNET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_BETA_TESTNET {
                    ConsensusRuleSet::HardforkAlpha
                } else {
                    ConsensusRuleSet::HardforkBeta
                }
            }
        }
    }

    pub(crate) fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::HardforkBeta => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::HardforkBeta => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::HardforkBeta => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::sync::Arc;

    use futures::channel::oneshot;
    use itertools::Itertools;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::GlobalStateLock;
    use crate::api::export::InputSelectionPolicy;
    use crate::api::export::KeyType;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::OutputFormat;
    use crate::api::export::ReceivingAddress;
    use crate::api::export::StateLock;
    use crate::api::export::Timestamp;
    use crate::api::export::TransactionProofType;
    use crate::api::export::TxCreationArtifacts;
    use crate::api::export::TxProvingCapability;
    use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
    use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
    use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    use crate::api::tx_initiation::builder::tx_input_list_builder::SortOrder;
    use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
    use crate::application::config::cli_args;
    use crate::application::loops::channel::NewBlockFound;
    use crate::application::loops::mine_loop::compose_block_helper;
    use crate::application::loops::mine_loop::create_block_transaction_from;
    use crate::application::loops::mine_loop::guess_nonce;
    use crate::application::loops::mine_loop::GuessingConfiguration;
    use crate::application::loops::mine_loop::TxMergeOrigin;
    use crate::application::triton_vm_job_queue::vm_job_queue;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;
    use crate::protocol::consensus::block::validity::block_primitive_witness::BlockPrimitiveWitness;
    use crate::protocol::consensus::block::Block;
    use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::next_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state_with_block;
    use crate::tests::tokio_runtime;

    async fn tx_with_n_outputs(
        mut state: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
    ) -> TxCreationArtifacts {
        let mut addresses_and_amts = vec![];
        let same_address = state
            .api()
            .wallet_mut()
            .next_receiving_address(KeyType::Symmetric)
            .await
            .unwrap();
        for _ in 0..num_outputs {
            let value = OutputFormat::AddressAndAmount(
                same_address.clone(),
                NativeCurrencyAmount::from_nau(1),
            );
            addresses_and_amts.push(value);
        }

        let initiator = state.api().tx_initiator();
        let tx_outputs = initiator.generate_tx_outputs(addresses_and_amts).await;
        drop(initiator);

        let fee = NativeCurrencyAmount::from_nau(14);
        let tx_inputs = TxInputListBuilder::new()
            .spendable_inputs(
                state
                    .lock_guard()
                    .await
                    .wallet_spendable_inputs(timestamp)
                    .await
                    .into_iter()
                    .collect(),
            )
            .policy(InputSelectionPolicy::ByUtxoSize(SortOrder::Ascending))
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build();
        let tx_inputs = tx_inputs.into_iter().collect_vec();

        let tx_details = TransactionDetailsBuilder::new()
            .inputs(tx_inputs.into_iter().into())
            .outputs(tx_outputs)
            .fee(fee)
            .timestamp(timestamp)
            .build(&mut StateLock::write_guard(&mut state).await)
            .await
            .unwrap();

        // use cli options for building proof, but override proof-type
        let options = TritonVmProofJobOptionsBuilder::new()
            .proof_type(TransactionProofType::SingleProof)
            .proving_capability(TxProvingCapability::SingleProof)
            .build();

        // generate proof
        let block_height = state.lock_guard().await.chain.light_state().header().height;
        let network = state.cli().network;
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

        TxCreationArtifacts {
            transaction: Arc::new(transaction),
            details: Arc::new(tx_details),
        }
    }

    async fn block_with_n_outputs(
        me: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
    ) -> Block {
        let current_tip = me.lock_guard().await.chain.archival_state().get_tip().await;
        let tx_many_outputs = tx_with_n_outputs(me.clone(), num_outputs, timestamp).await;
        let (block_tx, _) = create_block_transaction_from(
            &current_tip,
            me,
            timestamp,
            TritonVmProofJobOptions::default(),
            TxMergeOrigin::ExplicitList(vec![tx_many_outputs.transaction.into()]),
        )
        .await
        .unwrap();
        Block::compose(
            &current_tip,
            block_tx,
            timestamp,
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    async fn mine_to_own_wallet(
        me: GlobalStateLock,
        timestamp: Timestamp,
    ) -> (Block, Vec<ExpectedUtxo>) {
        let current_tip = me.lock_guard().await.chain.archival_state().get_tip().await;
        compose_block_helper(
            current_tip,
            me,
            timestamp,
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    #[traced_test]
    #[test]
    fn new_blocks_at_block_height_10_000() {
        // We want to use the following block primitive witness generator (which
        // uses async code on the inside) in combination with async code. We
        // make this test function async because we would be entering into the
        // same runtime twice. Therefore, we generate the block primitive
        // witness once, in this synchronous wrapper, and continue
        // asynchronously with the helper function.

        let init_block_heigth = BlockHeight::from(10_000u64);
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height(init_block_heigth);

        tokio_runtime().block_on(new_blocks_at_block_height_10_000_async(bpw));
    }

    async fn new_blocks_at_block_height_10_000_async(
        block_primitive_witness: BlockPrimitiveWitness,
    ) {
        // 1. generate state synced to height
        let mut rng = StdRng::seed_from_u64(55512345);
        let network = Network::Main;
        let bob_wallet = WalletEntropy::new_pseudorandom(rng.random());
        let cli = cli_args::Args {
            network,
            compose: true,
            guess: true,
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            ..Default::default()
        };

        let (fake_genesis, block_10_000) =
            Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness).await;
        let mut now = block_10_000.header().timestamp;
        assert!(block_10_000.is_valid(&fake_genesis, now, network).await);

        let mut bob = mock_genesis_global_state_with_block(0, bob_wallet, cli, fake_genesis).await;
        bob.set_new_tip(block_10_000.clone()).await.unwrap();

        let observed_block_height = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(BlockHeight::from(10_000u64), observed_block_height,);

        // 2. get a positive balance, by mining.
        let blocks_to_mine = 5;
        let mut predecessor = block_10_000;
        for _ in 0..blocks_to_mine {
            now += Timestamp::hours(1);
            let (next_block, expected_composer_utxos) = mine_to_own_wallet(bob.clone(), now).await;
            assert!(next_block.is_valid(&predecessor, now, network).await);
            bob.set_new_self_composed_tip(next_block.clone(), expected_composer_utxos)
                .await
                .unwrap();
            predecessor = next_block;
        }

        let hopefully_plus_5 = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(BlockHeight::from(10_005u64), hopefully_plus_5);
        assert!(
            bob.api()
                .wallet()
                .balances(now)
                .await
                .confirmed_available
                .is_positive(),
            "Bob must have money"
        );
        assert_eq!(
            blocks_to_mine,
            bob.api().wallet().spendable_inputs(now).await.len(),
            "Bob must have {blocks_to_mine} spendable inputs after mining {blocks_to_mine} blocks"
        );

        // 3. create blocks with enough outputs to give some/all owned UTXOs
        //    non-empty chunk dictionaries. This serves to check that the
        //    membership proofs/removal records are updated correctly.
        let num_blocks_with_many_outputs = 4;
        for _ in 0..num_blocks_with_many_outputs {
            now += Timestamp::hours(1);
            let next_block = block_with_n_outputs(bob.clone(), 24, now).await;
            assert!(next_block.is_valid(&predecessor, now, network).await);
            bob.set_new_tip(next_block.clone()).await.unwrap();
            predecessor = next_block;
        }
    }

    #[traced_test]
    #[test]
    fn hard_fork_alpha() {
        // Start at hard fork block height minus 2
        // Then mine enough blocks to activate the hard fork. Verify that all
        // blocks are valid under the expected consensus rule set.
        let init_block_heigth = BlockHeight::from(14998u64);
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height_and_difficulty(
            init_block_heigth,
            Difficulty::MINIMUM,
        );

        tokio_runtime().block_on(new_blocks_hardfork_alpha(bpw));

        async fn new_blocks_hardfork_alpha(block_primitive_witness: BlockPrimitiveWitness) {
            // 1. generate state synced to height
            let mut rng = StdRng::seed_from_u64(55512345);
            let network = Network::Main;
            let bob_wallet = WalletEntropy::new_pseudorandom(rng.random());
            let cli = cli_args::Args {
                network,
                compose: true,
                guess: true,
                tx_proving_capability: Some(TxProvingCapability::SingleProof),
                ..Default::default()
            };

            let (block_a, block_b_no_pow) =
                Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness)
                    .await;

            assert!(
                block_b_no_pow
                    .is_valid(&block_a, block_b_no_pow.header().timestamp, network)
                    .await
            );
            let mut bob =
                mock_genesis_global_state_with_block(2, bob_wallet, cli.clone(), block_a.clone())
                    .await;

            // Solve PoW for block_b
            let guesser_address: ReceivingAddress = bob
                .lock_guard()
                .await
                .wallet_state
                .wallet_entropy
                .guesser_fee_key()
                .to_address()
                .into();
            let (guesser_tx_b, guesser_rx_b) = oneshot::channel::<NewBlockFound>();
            let guesser_timestamp_b = block_b_no_pow.header().timestamp;
            guess_nonce(
                network,
                block_b_no_pow,
                *block_a.header(),
                guesser_tx_b,
                GuessingConfiguration {
                    num_guesser_threads: cli.guesser_threads,
                    address: guesser_address.clone(),
                    // For deterministic pow-guessing, both RNG and timestamp
                    // must be deterministic.
                    override_rng: Some(rng),
                    override_timestamp: Some(guesser_timestamp_b),
                },
            )
            .await;
            let block_b = *guesser_rx_b.await.unwrap().block;
            assert!(
                block_b
                    .is_valid(&block_a, block_b.header().timestamp, network)
                    .await
            );
            assert!(block_b.has_proof_of_work(network, block_a.header()));
            assert!(block_b.pow_verify(
                block_a.header().difficulty.target(),
                ConsensusRuleSet::Reboot
            ));
            assert!(!block_b.pow_verify(
                block_a.header().difficulty.target(),
                ConsensusRuleSet::HardforkAlpha
            ));

            bob.set_new_tip(block_b.clone()).await.unwrap();
            assert_eq!(
                14998u64,
                bob.lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
                    .value()
            );

            // hard fork minus 1
            let block_c = next_block(bob.clone(), block_b.clone()).await;
            assert!(
                block_c
                    .is_valid(&block_b, block_c.header().timestamp, network)
                    .await
            );
            assert!(block_c.has_proof_of_work(network, block_b.header()));
            assert!(block_c.pow_verify(
                block_b.header().difficulty.target(),
                ConsensusRuleSet::Reboot
            ));
            assert!(!block_c.pow_verify(
                block_b.header().difficulty.target(),
                ConsensusRuleSet::HardforkAlpha
            ));
            bob.set_new_tip(block_c.clone()).await.unwrap();
            assert_eq!(
                14999u64,
                bob.lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
                    .value()
            );

            // 1st block after hard fork!
            let block_d = next_block(bob.clone(), block_c.clone()).await;
            assert!(
                block_d
                    .is_valid(&block_c, block_d.header().timestamp, network)
                    .await
            );
            assert!(block_d.has_proof_of_work(network, block_c.header()));
            assert!(!block_d.pow_verify(
                block_c.header().difficulty.target(),
                ConsensusRuleSet::Reboot
            ));
            assert!(block_d.pow_verify(
                block_c.header().difficulty.target(),
                ConsensusRuleSet::HardforkAlpha
            ));
            bob.set_new_tip(block_d.clone()).await.unwrap();
            assert_eq!(
                15000u64,
                bob.lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
                    .value()
            );

            // 2nd block after hard fork
            let block_e = next_block(bob.clone(), block_d.clone()).await;
            assert!(
                block_e
                    .is_valid(&block_d, block_e.header().timestamp, network)
                    .await
            );
            assert!(block_e.has_proof_of_work(network, block_d.header()));
            assert!(!block_e.pow_verify(
                block_d.header().difficulty.target(),
                ConsensusRuleSet::Reboot
            ));
            assert!(block_e.pow_verify(
                block_d.header().difficulty.target(),
                ConsensusRuleSet::HardforkAlpha
            ));
            bob.set_new_tip(block_e.clone()).await.unwrap();
            assert_eq!(
                15001u64,
                bob.lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
                    .value()
            );

            // 3rd block after hard fork
            let block_f = next_block(bob.clone(), block_e.clone()).await;
            assert!(
                block_f
                    .is_valid(&block_e, block_f.header().timestamp, network)
                    .await
            );
            assert!(block_f.has_proof_of_work(network, block_e.header()));
            assert!(!block_f.pow_verify(
                block_e.header().difficulty.target(),
                ConsensusRuleSet::Reboot
            ));
            assert!(block_f.pow_verify(
                block_e.header().difficulty.target(),
                ConsensusRuleSet::HardforkAlpha
            ));
            bob.set_new_tip(block_f.clone()).await.unwrap();
            assert_eq!(
                15002u64,
                bob.lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
                    .value()
            );

            // 4th block after hard fork, with a transaction.
            // Create transaction
            let tx_timestamp = block_f.header().timestamp + Timestamp::minutes(6);
            let tx_artifacts = tx_with_n_outputs(bob.clone(), 2, tx_timestamp).await;
            bob.api_mut()
                .tx_initiator_mut()
                .record_and_broadcast_transaction(&tx_artifacts)
                .await
                .unwrap();

            // Create block, with above transaction
            let block_g = next_block(bob.clone(), block_f.clone()).await;
            assert!(
                block_g
                    .is_valid(&block_f, block_g.header().timestamp, network)
                    .await
            );
            assert!(block_g.has_proof_of_work(network, block_f.header()));
            assert!(!block_g.pow_verify(
                block_f.header().difficulty.target(),
                ConsensusRuleSet::Reboot
            ));
            assert!(block_g.pow_verify(
                block_f.header().difficulty.target(),
                ConsensusRuleSet::HardforkAlpha
            ));
            bob.set_new_tip(block_g.clone()).await.unwrap();
            assert_eq!(
                15003u64,
                bob.lock_guard()
                    .await
                    .chain
                    .light_state()
                    .header()
                    .height
                    .value()
            );
        }
    }
}
