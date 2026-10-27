mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_consensus::block::proof_of_work_puzzle::ProofOfWorkPuzzle;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// test: Generate a local block proposal and find a valid PoW solution for it.
#[tokio::test(flavor = "multi_thread")]
pub async fn can_find_valid_pow_solution() {
    logging::tracing_logger();

    let network = Network::RegTest;
    let mut alice = GenesisNode::start_node(
        GenesisNode::default_args_with_network_and_devnet_wallet(network).await,
    )
    .await
    .unwrap();
    let timestamp = Timestamp(BFieldElement::new(1861920000000u64));
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .set_self_composed_proposal(timestamp, Default::default())
        .await;
    let mut proposal = alice
        .gsl
        .lock_guard()
        .await
        .mining_state
        .block_proposal
        .expect("Just set block proposal")
        .clone();
    let (guesser_address, _) = alice.gsl.lock_guard().await.mining_rewards_address();
    proposal.set_header_guesser_data(guesser_address.into());

    let latest_block_header = *alice.gsl.lock_guard().await.chain.tip().header();
    let puzzle = ProofOfWorkPuzzle::new(proposal.clone(), latest_block_header.difficulty);
    println!("puzzle:\n\n{}", serde_json::to_string(&puzzle).unwrap());

    let solution = puzzle.solve(ConsensusRuleSet::HardforkGamma);
    println!("solution:\n\n{}", serde_json::to_string(&solution).unwrap());
    proposal.set_header_pow(solution);

    assert!(proposal.has_proof_of_work(network, &latest_block_header))
}
