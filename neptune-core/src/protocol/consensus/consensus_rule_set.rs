use num_traits::Zero;

use crate::api::export::BlockHeight;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Network;
use crate::protocol::consensus::block::block_height::NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT;
use crate::protocol::consensus::block::pow::LustrationStatus;
use crate::protocol::consensus::block::INITIAL_BLOCK_SUBSIDY;
use crate::protocol::consensus::block::MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS;
use crate::protocol::consensus::block::PREMINE_MAX_SIZE;
use crate::BFieldElement;

/// Height of 1st block that follows the alpha consensus ruleset, for main net.
pub const BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(15_000u64));

/// Height of 1st block that follows the alpha consensus ruleset, for test net.
pub const BLOCK_HEIGHT_HARDFORK_ALPHA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(120u64));

/// Height of 1st block that follows the alpha consensus ruleset, for test net.
pub const BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(3571u64));

/// Height of 1st block that uses Triton VM with proof version 1.
pub const BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(23_401u64));

/// Height of 1st block changing PoW algorithm to drop memory hardness
pub const BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET: BlockHeight =
    BlockHeight::new(BFieldElement::new(40_000u64));

/// Height of 1st block changing PoW algorithm to drop memory hardness, for test
/// net.
pub const BLOCK_HEIGHT_HARDFORK_BETA_TESTNET: BlockHeight =
    BlockHeight::new(BFieldElement::new(3_700u64));

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter, Default, strum::Display)]
pub enum ConsensusRuleSet {
    /// First rule set after reboot
    Reboot,

    /// Allow reuse of preprocessing step for new block proposals
    HardforkAlpha,

    /// Upgrade from Triton VM proof version v0 to v1
    #[default]
    TvmProofVersion1,

    /// Remove memory hardness from PoW algorithm
    HardforkBeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
pub enum TritonProofVersion {
    V0,
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LustrationRule {
    Initial(LustrationStatus),
    Updated {
        // This data is actually redundant but allows for an security-in-depth
        // extra sanity check.
        initial_counter: NativeCurrencyAmount,
    },
}

impl ConsensusRuleSet {
    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks can activate at different
    /// heights based on the network.
    pub(crate) fn infer_from(network: Network, block_height: BlockHeight) -> Self {
        let first_lustration_block = Self::first_lustration_block(network);
        match network {
            Network::Main => {
                if block_height < BLOCK_HEIGHT_HARDFORK_ALPHA_MAIN_NET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_MAIN_NET {
                    ConsensusRuleSet::HardforkAlpha
                } else if block_height < first_lustration_block {
                    ConsensusRuleSet::TvmProofVersion1
                } else {
                    ConsensusRuleSet::HardforkBeta
                }
            }
            Network::Testnet(0) => {
                if block_height < BLOCK_HEIGHT_HARDFORK_ALPHA_TESTNET {
                    ConsensusRuleSet::Reboot
                } else if block_height < BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_TESTNET {
                    ConsensusRuleSet::HardforkAlpha
                } else if block_height < first_lustration_block {
                    ConsensusRuleSet::TvmProofVersion1
                } else {
                    ConsensusRuleSet::HardforkBeta
                }
            }
            _ => {
                if block_height < first_lustration_block {
                    ConsensusRuleSet::TvmProofVersion1
                } else {
                    ConsensusRuleSet::HardforkBeta
                }
            }
        }
    }

    pub(crate) fn memory_hard_pow(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot => true,
            ConsensusRuleSet::HardforkAlpha => true,
            ConsensusRuleSet::TvmProofVersion1 => true,
            ConsensusRuleSet::HardforkBeta => false,
        }
    }

    pub(crate) fn requires_lustration_status_in_block_header(&self) -> bool {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1 => false,
            ConsensusRuleSet::HardforkBeta => true,
        }
    }

    pub(crate) fn triton_proof_version(&self) -> TritonProofVersion {
        if cfg!(test) {
            // Only test with v1 since we would otherwise need to depend on two
            // different versions of Triton VM.
            TritonProofVersion::V1
        } else {
            match self {
                ConsensusRuleSet::Reboot => TritonProofVersion::V0,
                ConsensusRuleSet::HardforkAlpha => TritonProofVersion::V0,
                ConsensusRuleSet::TvmProofVersion1 => TritonProofVersion::V1,
                ConsensusRuleSet::HardforkBeta => TritonProofVersion::V1,
            }
        }
    }

    /// Maximum block size in number of BFieldElements
    pub(crate) const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta => {
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space.
                1_000_000
            }
        }
    }

    pub(crate) fn max_num_inputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_outputs(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }
    pub(crate) fn max_num_announcements(&self) -> usize {
        match self {
            ConsensusRuleSet::Reboot
            | ConsensusRuleSet::HardforkAlpha
            | ConsensusRuleSet::TvmProofVersion1
            | ConsensusRuleSet::HardforkBeta => MAX_NUM_INPUTS_OUTPUTS_ANNOUNCEMENTS,
        }
    }

    pub(crate) fn first_tvmv1_block(network: Network) -> BlockHeight {
        match network {
            Network::Main => BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_MAIN_NET,
            Network::Testnet(0) => BLOCK_HEIGHT_HARDFORK_TVMV_PROOF_V1_TESTNET,
            _ => BlockHeight::genesis(),
        }
    }

    pub(crate) fn first_lustration_block(network: Network) -> BlockHeight {
        match network {
            Network::Main => BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET,
            Network::Testnet(0) => BLOCK_HEIGHT_HARDFORK_BETA_TESTNET,
            _ => {
                // Activating the lustration rule at block 20 on these test
                // networks means that existing tests that generate blocks and
                // transactions without lustrations keep working. This value
                // isn't set in stone though, and can be changed if anyone has
                // a good reason for it.
                20u64.into()
            }
        }
    }

    pub(crate) fn lustration_rule(
        network: Network,
        block_height: BlockHeight,
        last_aocl_leaf_index: u64,
    ) -> Option<LustrationRule> {
        let premine = PREMINE_MAX_SIZE;
        let claims_pool = INITIAL_BLOCK_SUBSIDY
            .scalar_mul(u32::try_from(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT).unwrap());

        let first_hf_beta_block = Self::first_lustration_block(network);

        assert!(
            first_hf_beta_block.get_generation().is_zero(),
            "This calculation assumes transparency gateway starts at generation zero."
        );

        let mined_at_hardfork_activation =
            INITIAL_BLOCK_SUBSIDY.scalar_mul(u32::try_from(first_hf_beta_block.value()).unwrap());
        let initial_counter = premine + claims_pool + mined_at_hardfork_activation;

        if block_height < first_hf_beta_block {
            None
        } else if block_height == first_hf_beta_block {
            Some(LustrationRule::Initial(LustrationStatus {
                counter: initial_counter,
                max_lustrating_aocl_leaf_index: last_aocl_leaf_index,
            }))
        } else {
            Some(LustrationRule::Updated { initial_counter })
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use std::assert_matches;
    use std::sync::Arc;

    use futures::channel::oneshot;
    use itertools::Itertools;
    use num_traits::CheckedSub;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::Digest;
    use tasm_lib::twenty_first::prelude::Mmr;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::GlobalStateLock;
    use crate::api::export::InputCandidate;
    use crate::api::export::InputSelectionPriority;
    use crate::api::export::KeyType;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::OutputFormat;
    use crate::api::export::ReceivingAddress;
    use crate::api::export::StateLock;
    use crate::api::export::Timestamp;
    use crate::api::export::TransactionProofType;
    use crate::api::export::TxCreationArtifacts;
    use crate::api::export::TxProvingCapability;
    use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
    use crate::api::tx_initiation::builder::input_selector::InputSelector;
    use crate::api::tx_initiation::builder::input_selector::SortOrder;
    use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
    use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
    use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
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
    use crate::state::mempool::upgrade_priority::UpgradePriority;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::state::wallet::wallet_entropy::WalletEntropy;
    use crate::tests::shared::blocks::next_block;
    use crate::tests::shared::globalstate::mock_genesis_global_state_with_block;
    use crate::tests::tokio_runtime;

    async fn tx_with_n_outputs(
        mut state: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
        input_selection_policy: Option<InputSelectionPolicy>,
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
            let selected_inputs = InputSelector::new()
                .input_candidates(input_candidates)
                .policy(policy)
                .spend_amount(tx_outputs.total_native_coins() + fee)
                .build()
                .unwrap();

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
        let options = TritonVmProofJobOptionsBuilder::new()
            .proof_type(TransactionProofType::SingleProof)
            .proving_capability(TxProvingCapability::SingleProof)
            .build();

        // generate proof
        let block_height = state.lock_guard().await.chain.tip().header().height;
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
        let tx_many_outputs = tx_with_n_outputs(me.clone(), num_outputs, timestamp, None).await;
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
            current_tip,
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
            number_of_mps_per_utxo: 3,
            ..Default::default()
        };

        let (fake_genesis, block_10_000) =
            Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness).await;
        let mut now = block_10_000.header().timestamp;
        assert!(block_10_000.is_valid(&fake_genesis, now, network).await);

        let mut bob = mock_genesis_global_state_with_block(0, bob_wallet, cli, fake_genesis).await;
        bob.set_new_tip(block_10_000.clone()).await.unwrap();

        let observed_block_height = bob.lock_guard().await.chain.tip().header().height;
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

        let hopefully_plus_5 = bob.lock_guard().await.chain.tip().header().height;
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
        let bob_spendable_inputs = bob
            .lock_guard()
            .await
            .wallet_spendable_inputs_at_time(now)
            .await;
        assert_eq!(
            blocks_to_mine,
            bob_spendable_inputs.len(),
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

    #[test]
    fn lustration_counter_has_expected_initial_value() {
        let first_lustration_rule = ConsensusRuleSet::lustration_rule(
            Network::Main,
            BLOCK_HEIGHT_HARDFORK_BETA_MAIN_NET,
            100_000,
        )
        .unwrap();
        let LustrationRule::Initial(lustration_status) = first_lustration_rule else {
            panic!("First lustration rule must be of type 'initial'");
        };

        assert_eq!(
            NativeCurrencyAmount::coins(8679168),
            lustration_status.counter
        );
        assert_eq!(100_000, lustration_status.max_lustrating_aocl_leaf_index);
    }

    #[test]
    fn future_and_past_memory_hardness() {
        assert!(ConsensusRuleSet::infer_from(Network::Main, 1_000u64.into()).memory_hard_pow());
        assert!(!ConsensusRuleSet::infer_from(Network::Main, 100_000u64.into()).memory_hard_pow());
    }

    #[test]
    fn tvm_v1_preceeds_hf_beta() {
        let network = Network::Main;
        let first_lustration_block = ConsensusRuleSet::first_lustration_block(network);
        assert_eq!(
            ConsensusRuleSet::TvmProofVersion1,
            ConsensusRuleSet::infer_from(network, first_lustration_block.previous().unwrap())
        );
        assert_eq!(
            ConsensusRuleSet::HardforkBeta,
            ConsensusRuleSet::infer_from(network, first_lustration_block)
        );

        let dummy_count = 55647;
        assert!(ConsensusRuleSet::lustration_rule(
            network,
            first_lustration_block.previous().unwrap(),
            dummy_count
        )
        .is_none(),);
        assert_matches!(
            ConsensusRuleSet::lustration_rule(network, first_lustration_block, dummy_count),
            Some(LustrationRule::Initial(_)),
        );
        assert_matches!(
            ConsensusRuleSet::lustration_rule(network, first_lustration_block.next(), dummy_count),
            Some(LustrationRule::Updated { .. }),
        );
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

                // Must be non-zero since no archival mutator set is known
                number_of_mps_per_utxo: 3,
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
                bob.lock_guard().await.chain.tip().header().height.value()
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
                bob.lock_guard().await.chain.tip().header().height.value()
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
                bob.lock_guard().await.chain.tip().header().height.value()
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
                bob.lock_guard().await.chain.tip().header().height.value()
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
                bob.lock_guard().await.chain.tip().header().height.value()
            );

            // 4th block after hard fork, with a transaction.
            let tx_timestamp = block_f.header().timestamp + Timestamp::minutes(6);
            let tx_artifacts = tx_with_n_outputs(bob.clone(), 2, tx_timestamp, None).await;
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
                bob.lock_guard().await.chain.tip().header().height.value()
            );
        }
    }

    #[traced_test]
    #[test]
    fn hard_fork_beta() {
        // Start at hard fork block height minus 2
        let init_block_heigth = BlockHeight::from(39998u64);
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height_and_difficulty(
            init_block_heigth,
            Difficulty::MINIMUM,
        );

        tokio_runtime().block_on(new_blocks_hardfork_beta(bpw));

        async fn new_blocks_hardfork_beta(block_primitive_witness: BlockPrimitiveWitness) {
            // 1. generate state synced to height
            let mut rng = StdRng::seed_from_u64(5551234665);
            let network = Network::Main;
            let bob_wallet = WalletEntropy::new_pseudorandom(rng.random());
            let cli = cli_args::Args {
                network,
                tx_proving_capability: Some(TxProvingCapability::SingleProof),

                // Must be non-zero since no archival mutator set is known
                number_of_mps_per_utxo: 3,
                ..Default::default()
            };

            let (minus3, minus2_no_pow) =
                Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness)
                    .await;

            assert!(
                minus2_no_pow
                    .is_valid(&minus3, minus2_no_pow.header().timestamp, network)
                    .await
            );
            let mut bob =
                mock_genesis_global_state_with_block(2, bob_wallet, cli.clone(), minus3.clone())
                    .await;

            let (guesser_tx_b, guesser_rx_b) = oneshot::channel::<NewBlockFound>();
            let guesser_timestamp_b = minus2_no_pow.header().timestamp;
            guess_nonce(
                network,
                minus2_no_pow,
                *minus3.header(),
                guesser_tx_b,
                GuessingConfiguration {
                    num_guesser_threads: cli.guesser_threads,
                    address: GenerationReceivingAddress::derive_from_seed(Digest::default()).into(),
                    // For deterministic pow-guessing, both RNG and timestamp
                    // must be deterministic.
                    override_rng: Some(rng),
                    override_timestamp: Some(guesser_timestamp_b),
                },
            )
            .await;
            let minus2 = *guesser_rx_b.await.unwrap().block;
            assert!(
                minus2
                    .is_valid(&minus3, minus2.header().timestamp, network)
                    .await
            );
            assert!(minus2.has_proof_of_work(network, minus3.header()));
            assert!(minus2.pow_verify(
                minus3.header().difficulty.target(),
                ConsensusRuleSet::TvmProofVersion1
            ));
            assert!(minus2.pow_verify(
                minus3.header().difficulty.target(),
                ConsensusRuleSet::HardforkBeta
            ));

            bob.set_new_tip(minus2.clone()).await.unwrap();
            assert_eq!(
                39998u64,
                bob.lock_guard().await.chain.tip().header().height.value()
            );

            // hard fork minus 1
            let minus1 = next_block(bob.clone(), minus2.clone()).await;
            assert!(
                minus1
                    .is_valid(&minus2, minus1.header().timestamp, network)
                    .await
            );
            assert!(minus1.has_proof_of_work(network, minus2.header()));
            assert!(minus1.pow_verify(
                minus2.header().difficulty.target(),
                ConsensusRuleSet::TvmProofVersion1
            ));
            assert!(minus1.pow_verify(
                minus2.header().difficulty.target(),
                ConsensusRuleSet::HardforkBeta
            ));
            bob.set_new_tip(minus1.clone()).await.unwrap();
            assert_eq!(
                39999u64,
                bob.lock_guard().await.chain.tip().header().height.value()
            );

            // Verify non-zero balance, since we must make a transaction later.
            let bob_balance_minus1 = bob
                .lock_guard()
                .await
                .get_wallet_status_for_tip()
                .await
                .confirmed_total_balance(bob.lock_guard().await.chain.tip_height());
            println!("bob_balance_minus1: {bob_balance_minus1}");
            assert!(!bob_balance_minus1.is_zero());

            assert!(bob.lock_guard().await.chain.lustration_status().is_none());

            // Next: Mine a block that activates hardfork beta
            let hf = next_block(bob.clone(), minus1.clone()).await;
            assert!(hf.is_valid(&minus1, hf.header().timestamp, network).await);
            assert!(hf.has_proof_of_work(network, minus1.header()));
            assert!(!hf.pow_verify(
                minus1.header().difficulty.target(),
                ConsensusRuleSet::TvmProofVersion1
            ));
            assert!(hf.pow_verify(
                minus1.header().difficulty.target(),
                ConsensusRuleSet::HardforkBeta
            ));
            let hf_lustration_status = hf.header().pow.lustration_status().unwrap();
            assert_eq!(
                hf_lustration_status.max_lustrating_aocl_leaf_index + 1,
                hf.mutator_set_accumulator_after().unwrap().aocl.num_leafs()
            );
            assert_eq!(
                hf_lustration_status.counter,
                NativeCurrencyAmount::coins(8679168),
                "Lustration status must have expected value"
            );

            assert!(bob.lock_guard().await.chain.lustration_status().is_none());
            bob.set_new_tip(hf.clone()).await.unwrap();
            assert!(bob.lock_guard().await.chain.lustration_status().is_some());

            // Now build a transaction that *must* lustrate.
            let prefer_old_inputs = InputSelectionPolicy::default()
                .prioritize(InputSelectionPriority::ByAge(SortOrder::Descending));
            let tx0 = tx_with_n_outputs(
                bob.clone(),
                3,
                hf.header().timestamp,
                Some(prefer_old_inputs),
            )
            .await;
            assert!(tx0.is_valid(network, ConsensusRuleSet::HardforkBeta).await);
            assert!(tx0.details.contains_lustrations());
            let input_amt0 = tx0.details.tx_inputs.total_native_coins();
            assert!(
                input_amt0 < bob_balance_minus1,
                "Not all UTXOs may be carried over lustration barrier by this transaction, because
                 of later asserts in this test"
            );
            assert_eq!(
                input_amt0,
                tx0.transaction()
                    .kernel
                    .verified_lustration_amount(hf_lustration_status.max_lustrating_aocl_leaf_index)
                    .unwrap()
            );

            // Mine the above trasaction to produce block one after activation
            // the hardfork.
            bob.lock_guard_mut()
                .await
                .mempool_insert(tx0.transaction().to_owned(), UpgradePriority::Critical)
                .await;
            let plus1 = next_block(bob.clone(), hf.clone()).await;
            assert!(plus1.is_valid(&hf, plus1.header().timestamp, network).await);
            assert!(plus1.has_proof_of_work(network, hf.header()));
            assert!(!plus1.pow_verify(
                hf.header().difficulty.target(),
                ConsensusRuleSet::TvmProofVersion1
            ));
            assert!(plus1.pow_verify(
                hf.header().difficulty.target(),
                ConsensusRuleSet::HardforkBeta
            ));
            let plus1_lustration_status = plus1.header().pow.lustration_status().unwrap();
            assert_eq!(
                hf_lustration_status.max_lustrating_aocl_leaf_index,
                plus1_lustration_status.max_lustrating_aocl_leaf_index,
                "AOCL threshold must be unchanged after first HF-beta block"
            );
            assert_eq!(
                hf_lustration_status
                    .counter
                    .checked_sub(&input_amt0)
                    .unwrap(),
                plus1_lustration_status.counter,
                "Lustration counter must be less since plus1 mined lustrating inputs"
            );
            bob.set_new_tip(plus1.clone()).await.unwrap();

            // Build a 2nd transaction that must also lustrate since not all
            // old inputs were mined yet.
            // Give it many outputs to move the AOCL index so far that later
            // transactions don't have to lustrate.
            let tx1 = tx_with_n_outputs(
                bob.clone(),
                65,
                plus1.header().timestamp,
                Some(prefer_old_inputs),
            )
            .await;
            assert!(tx1.is_valid(network, ConsensusRuleSet::HardforkBeta).await);
            assert!(tx1.details.contains_lustrations());
            let input_amt1 = tx1.details.tx_inputs.total_native_coins();
            assert_eq!(
                input_amt1,
                tx1.transaction()
                    .kernel
                    .verified_lustration_amount(hf_lustration_status.max_lustrating_aocl_leaf_index)
                    .unwrap()
            );
            bob.lock_guard_mut()
                .await
                .mempool_insert(tx1.transaction().to_owned(), UpgradePriority::Critical)
                .await;
            let plus2 = next_block(bob.clone(), plus1.clone()).await;
            assert!(
                plus2
                    .is_valid(&plus1, plus2.header().timestamp, network)
                    .await
            );
            assert!(plus2.has_proof_of_work(network, plus1.header()));
            assert!(!plus2.pow_verify(
                plus1.header().difficulty.target(),
                ConsensusRuleSet::TvmProofVersion1
            ));
            assert!(plus2.pow_verify(
                plus1.header().difficulty.target(),
                ConsensusRuleSet::HardforkBeta
            ));
            let plus2_lustration_status = plus2.header().pow.lustration_status().unwrap();
            assert_eq!(
                hf_lustration_status.max_lustrating_aocl_leaf_index,
                plus2_lustration_status.max_lustrating_aocl_leaf_index,
                "AOCL threshold must be unchanged once HF-beta is activated"
            );
            assert_eq!(
                plus1_lustration_status
                    .counter
                    .checked_sub(&input_amt1)
                    .unwrap(),
                plus2_lustration_status.counter,
                "Lustration counter must be less since plus2 mined lustrating inputs"
            );
            bob.set_new_tip(plus2.clone()).await.unwrap();

            // Build a new transaction that doesn't have to lustrate, since
            // it's being built from new inputs. Verify no lustration.
            println!(
                "Lustration threshold: {}",
                hf_lustration_status.max_lustrating_aocl_leaf_index
            );
            let prefer_new_inputs = InputSelectionPolicy::default()
                .prioritize(InputSelectionPriority::ByAge(SortOrder::Ascending));
            let tx2 = tx_with_n_outputs(
                bob.clone(),
                1,
                plus2.header().timestamp,
                Some(prefer_new_inputs),
            )
            .await;
            assert!(tx2.is_valid(network, ConsensusRuleSet::HardforkBeta).await);
            assert!(!tx2.details.contains_lustrations());
            assert_eq!(
                Ok(NativeCurrencyAmount::zero()),
                tx2.transaction().kernel.verified_lustration_amount(
                    hf_lustration_status.max_lustrating_aocl_leaf_index
                )
            );

            // When a transaction without lustrations is mined, the lustration
            // status must remain unchanged.
            bob.lock_guard_mut()
                .await
                .mempool_insert(tx2.transaction().to_owned(), UpgradePriority::Critical)
                .await;
            let plus3 = next_block(bob.clone(), plus2.clone()).await;
            assert!(
                plus3
                    .is_valid(&plus2, plus3.header().timestamp, network)
                    .await
            );
            assert!(plus3.has_proof_of_work(network, plus2.header()));
            assert!(!plus3.pow_verify(
                plus2.header().difficulty.target(),
                ConsensusRuleSet::TvmProofVersion1
            ));
            assert!(plus3.pow_verify(
                plus2.header().difficulty.target(),
                ConsensusRuleSet::HardforkBeta
            ));
            let plus3_lustration_status = plus3.header().pow.lustration_status().unwrap();
            assert_eq!(
                plus2_lustration_status, plus3_lustration_status,
                "Lustration status must be unchanged when no lustrating inputs were mined"
            );
        }
    }
}
