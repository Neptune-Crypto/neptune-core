use strum_macros::EnumIter;

use super::block::BLOCK_HEIGHT_HF_1;
use super::block::BLOCK_HEIGHT_HF_2_MAINNET;
use super::block::BLOCK_HEIGHT_HF_2_NOT_MAINNET;
use super::block::MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1;
use super::transaction::merge_version::MergeVersion;
use crate::api::export::BlockHeight;
use crate::api::export::Network;

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
    Genesis,
    HardFork1,
    HardFork2,
}

impl ConsensusRuleSet {
    /// Maximum block size in number of BFieldElements
    pub(crate) const fn max_block_size(&self) -> usize {
        match self {
            ConsensusRuleSet::Genesis => {
                // Old maximum block size in number of `BFieldElement`s.
                250_000
            }
            ConsensusRuleSet::HardFork1 | ConsensusRuleSet::HardFork2 => {
                // New maximum block size in number of `BFieldElement`s.
                //
                // This size is 8MB which should keep it feasible to run archival nodes for
                // many years without requiring excessive disk space. With an SWBF MMR of
                // height 20, this limit allows for 150-200 inputs per block.
                1_000_000
            }
        }
    }

    /// Infer the [`ConsensusRuleSet`] from the [`Network`] and the
    /// [`BlockHeight`]. The second argument is necessary to take into account
    /// planned hard or soft forks that activate at a given height. The first
    /// argument is necessary because the forks activate at different heights
    /// based on the network.
    pub(crate) fn infer_from(network: Network, block_height: BlockHeight) -> Self {
        match network {
            Network::Main => {
                if block_height < BLOCK_HEIGHT_HF_1 {
                    Self::Genesis
                } else if block_height < BLOCK_HEIGHT_HF_2_MAINNET {
                    Self::HardFork1
                } else {
                    Self::HardFork2
                }
            }
            Network::TestnetMock | Network::Beta | Network::Testnet | Network::RegTest => {
                match block_height {
                    h if h < BLOCK_HEIGHT_HF_2_NOT_MAINNET => Self::HardFork1,
                    _ => Self::HardFork2,
                }
            }
        }
    }

    /// Stipulates which version of the merge-branch in [`SingleProof`] is
    /// active.
    ///
    /// [`SingleProof`]: crate::models::blockchain::transaction::validity::single_proof::SingleProof
    pub(crate) const fn merge_version(&self) -> MergeVersion {
        match self {
            ConsensusRuleSet::Genesis | ConsensusRuleSet::HardFork1 => MergeVersion::Genesis,
            ConsensusRuleSet::HardFork2 => MergeVersion::HardFork2,
        }
    }

    pub(crate) fn max_num_inputs(&self) -> Option<usize> {
        match self {
            ConsensusRuleSet::Genesis => None,
            _ => Some(MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1),
        }
    }
    pub(crate) fn max_num_outputs(&self) -> Option<usize> {
        match self {
            ConsensusRuleSet::Genesis => None,
            _ => Some(MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1),
        }
    }
    pub(crate) fn max_num_public_announcements(&self) -> Option<usize> {
        match self {
            ConsensusRuleSet::Genesis => None,
            _ => Some(MAX_NUM_INPUTS_OUTPUTS_PUB_ANNOUNCEMENTS_AFTER_HF_1),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::hash::Hash;

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::prelude::Tip5;
    use tracing_test::traced_test;

    use crate::api::export::GlobalStateLock;
    use crate::api::export::InputSelectionPolicy;
    use crate::api::export::KeyType;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::OutputFormat;
    use crate::api::export::StateLock;
    use crate::api::export::Timestamp;
    use crate::api::export::Transaction;
    use crate::api::export::TransactionProofType;
    use crate::api::export::TxProvingCapability;
    use crate::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
    use crate::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
    use crate::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    use crate::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    use crate::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
    use crate::mine_loop::compose_block_helper;
    use crate::mine_loop::create_block_transaction;
    use crate::mine_loop::create_block_transaction_from;
    use crate::mine_loop::TxMergeOrigin;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::consensus_rule_set;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
    use crate::tests::tokio_runtime;
    use crate::triton_vm_job_queue::vm_job_queue;
    use crate::{
        config_models::cli_args,
        models::{
            blockchain::block::validity::block_primitive_witness::BlockPrimitiveWitness,
            state::wallet::wallet_entropy::WalletEntropy,
        },
        tests::shared::globalstate::mock_genesis_global_state_with_block,
    };

    use super::*;

    impl ConsensusRuleSet {
        pub(crate) fn iter_merge_versions() -> std::vec::IntoIter<Self> {
            vec![Self::Genesis, Self::HardFork2].into_iter()
        }
    }

    async fn tx_with_n_outputs(
        mut state: GlobalStateLock,
        num_outputs: usize,
        timestamp: Timestamp,
    ) -> Transaction {
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
            .policy(InputSelectionPolicy::ByProvidedOrder)
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
        let consensus_rule_set = state.lock_guard().await.consensus_rule_set();
        let proof = TransactionProofBuilder::new()
            .consensus_rule_set(consensus_rule_set)
            .transaction_details(&tx_details)
            .job_queue(vm_job_queue())
            .proof_job_options(options)
            .build()
            .await
            .unwrap();

        TransactionBuilder::new()
            .transaction_details(&tx_details)
            .transaction_proof(proof)
            .build()
            .unwrap()
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
            &me,
            timestamp,
            TritonVmProofJobOptions::default(),
            TxMergeOrigin::ExplicitList(vec![tx_many_outputs]),
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
    fn test_activation_of_hard_fork_2() {
        // We want to use the following block primitive witness generator (which
        // uses async code on the inside) in combination with async code. We
        // make this test function async because we would be entering into the
        // same runtime twice. Therefore, we generate the block primitive
        // witness once, in this synchronous wrapper, and continue
        // asynchronously with the helper function.

        let init_block_heigth = BLOCK_HEIGHT_HF_2_MAINNET.checked_sub(8).unwrap();
        let bpw = BlockPrimitiveWitness::deterministic_with_block_height(init_block_heigth);

        tokio_runtime().block_on(test_activation_of_hard_fork_2_continue_async(bpw));
    }

    async fn test_activation_of_hard_fork_2_continue_async(
        block_primitive_witness: BlockPrimitiveWitness,
    ) {
        // 1. generate state synced to height HF2-8.
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

        let (fake_genesis, block_minus8) =
            Block::fake_block_pair_genesis_and_child_from_witness(block_primitive_witness).await;
        let mut now = block_minus8.header().timestamp;
        assert!(block_minus8.is_valid(&fake_genesis, now, network).await);

        let mut bob = mock_genesis_global_state_with_block(0, bob_wallet, cli, fake_genesis).await;
        bob.set_new_tip(block_minus8.clone()).await.unwrap();

        let expected_block_height = BLOCK_HEIGHT_HF_2_MAINNET.checked_sub(8).unwrap();
        let observed_block_height = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(
            expected_block_height,
            observed_block_height,
            "Expected block height {expected_block_height} must match observed {observed_block_height}");
        assert_eq!(expected_block_height, block_minus8.header().height);

        // 2. get a positive balance, by mining. (HF2-3)
        let blocks_to_mine = 5;
        let mut predecessor = block_minus8;
        for _ in 0..blocks_to_mine {
            now = now + Timestamp::hours(1);
            let (next_block, expected_composer_utxos) = mine_to_own_wallet(bob.clone(), now).await;
            println!("block height: {}", next_block.header().height);

            assert!(next_block.is_valid(&predecessor, now, network).await);

            // TODO: Assert that HardFork1 consensus rules are followed for mined block.
            bob.set_new_self_composed_tip(next_block.clone(), expected_composer_utxos)
                .await
                .unwrap();
            predecessor = next_block;
        }

        let hopefully_minus_3 = bob.lock_guard().await.chain.light_state().header().height;
        assert_eq!(
            BLOCK_HEIGHT_HF_2_MAINNET.checked_sub(3).unwrap(),
            hopefully_minus_3
        );
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
        //    non-empty chunk dictionaries. (HF-1)
        let num_blocks_with_many_outputs = 2;
        for _ in 0..num_blocks_with_many_outputs {
            let now = now + Timestamp::hours(1);
            let next_block = block_with_n_outputs(bob.clone(), 24, now).await;
            println!("block height: {}", next_block.header().height);

            assert!(next_block.is_valid(&predecessor, now, network).await);
            // TODO: Assert that HardFork1 consensus rules are followed for
            // this block.

            bob.set_new_tip(next_block.clone()).await.unwrap();
            predecessor = next_block;
        }
    }
}
