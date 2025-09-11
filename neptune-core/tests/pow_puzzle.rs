mod common;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::Network;
use neptune_cash::application::rpc::server::proof_of_work_puzzle::ProofOfWorkPuzzle;
use neptune_cash::protocol::consensus::block::block_header::BlockPow;
use neptune_cash::protocol::proof_abstractions::timestamp::Timestamp;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::common::fetch_files::test_helper_data_dir;
use crate::common::fetch_files::try_fetch_file_from_server;

/// test: Generate a local block proposal and find a valid PoW solution for it.
#[tokio::test(flavor = "multi_thread")]
pub async fn can_find_valid_pow_solution() {
    const POW_SOLUTION_FILE_NAME: &str = "precalculated_pow_solution.json";

    fn file_path() -> PathBuf {
        let mut path = test_helper_data_dir();
        path.push(POW_SOLUTION_FILE_NAME);

        path
    }

    /// Access precalculated solution since it takes a long time to find.
    fn precalculated_solution() -> Option<BlockPow> {
        let path = file_path();
        if File::open(file_path()).is_err() {
            let Some((file, _server)) =
                try_fetch_file_from_server(POW_SOLUTION_FILE_NAME.to_owned())
            else {
                println!(
                    "Could not find precalculated PoW solution. Solving \
                 locally. This may take multiple minutes."
                );
                return None;
            };
            let mut f = File::create_new(&path).unwrap();
            f.write_all(&file).unwrap();
        }

        let file = File::open(&path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

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
    let guesser_address = alice
        .gsl
        .lock_guard()
        .await
        .wallet_state
        .wallet_entropy
        .guesser_fee_key()
        .to_address();
    proposal.set_header_guesser_address(guesser_address.into());

    let latest_block_header = *alice.gsl.lock_guard().await.chain.light_state().header();
    let puzzle = ProofOfWorkPuzzle::new(proposal.clone(), latest_block_header);
    println!("puzzle:\n\n{}", serde_json::to_string(&puzzle).unwrap());

    let solution = match precalculated_solution() {
        Some(solution) => solution,
        None => {
            let solution = puzzle.solve();
            let file = File::create(file_path()).unwrap();
            serde_json::to_writer_pretty(file, &solution).unwrap();

            solution
        }
    };
    println!("solution:\n\n{}", serde_json::to_string(&solution).unwrap());
    proposal.set_header_pow(solution);

    assert!(proposal.has_proof_of_work(network, &latest_block_header))
}
