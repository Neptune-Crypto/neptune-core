//! neptune-block-claims
//!
//! Utility for printing `Claim`s related to validity of canonical, stored
//! blocks. Useful for producing a checkpoint: by adding these claims to the
//! true claims cache, incoming blocks are automatically validated as true
//! without going through the effort of verifying their proofs.

use clap::Parser;
use itertools::Itertools;
use neptune_cash::api::export::Network;
use neptune_cash::application::config::cli_args;
use neptune_cash::application::config::data_directory::DataDirectory;
use neptune_cash::protocol::consensus::block::validity::block_program::BlockProgram;
use neptune_cash::protocol::consensus::block::Block;
use neptune_cash::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_cash::state::archival_state::ArchivalState;

#[derive(Parser, Debug, Clone)]
#[clap()]
struct CliArg {
    min_height: u64,
    max_height: u64,
    network: Option<Network>,
}

fn main() {
    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not create tokio runtime");

    let CliArg {
        min_height,
        max_height,
        network,
    } = CliArg::parse();

    tokio_runtime.block_on(print_block_claims(min_height, max_height, network));
}

async fn print_block_claims(min_height: u64, max_height: u64, network: Option<Network>) {
    // Initialize archival state.

    // Runtime information is printed to stderr to allow the user to pipe stdout
    // into a file containing all claims.
    eprintln!("Writing claims in range ({min_height}..={max_height}) to std out");
    let network = network.unwrap_or_default();
    let cli_args = cli_args::Args::default_with_network(network);
    let genesis = Block::genesis(cli_args.network);
    let data_directory = DataDirectory::get(cli_args.data_dir.clone(), cli_args.network)
        .expect("data directory exists");
    let archival_state =
        ArchivalState::new(data_directory.clone(), genesis.clone(), &cli_args).await;

    // For all canonical blocks:
    let tip = archival_state.get_tip().await;
    let tip_height = tip.header().height.value();
    for block_height in min_height..=max_height {
        let block = match block_height {
            0 => genesis.clone(),
            bh if (1..tip_height).contains(&bh) => {
                let block_digest = archival_state
                    .archival_block_mmr
                    .ammr()
                    .get_leaf_async(bh)
                    .await;
                archival_state
                    .get_block(block_digest)
                    .await
                    .expect("good archive")
                    .expect("block is known")
            }
            bh if bh == tip_height => tip.clone(),
            _ => break,
        };

        if block_height.is_multiple_of(100) {
            eprintln!("Handling {block_height}");
        }

        let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height.into());
        let claim = BlockProgram::claim(block.body(), block.appendix(), consensus_rule_set);
        let claim_bytes = bincode::serialize(&claim).expect("can serialize claim");
        let claim_hex = claim_bytes.into_iter().map(|b| format!("{b:02x}")).join("");
        println!("{block_height} {claim_hex}",);
    }
}
