mod common;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use common::logging;
use itertools::Itertools;
use neptune_archive::archival_state::ArchivalState;
use neptune_consensus::block::validity::block_program::BlockProgram;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::data_directory::DataDirectory;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tracing::info;

use crate::common::fetch_files::test_helper_data_dir;
use crate::common::fetch_files::try_fetch_file_from_server;
use crate::common::genesis_node::GenesisNode;

const MAIN_NET_GENESIS_HASH: &str =
    "7962e48729acd97e08efa77b5b28d49f2dc0e5609a4f1f1affca5b4549c78e520462a7f955371386";

#[tokio::test(flavor = "multi_thread")]
pub async fn first_few_block_hashes_are_unchanged_main_net() {
    const BLOCK1_HASH: &str =
        "2a9b685b2f9cde0d6f258dcd3ab575ddabddd16d70f56e9b3ea7072e77a50aff95ad22c128000000";
    const BLOCK2A_HASH: &str =
        "50ed8d790911380c70dcf8e899e5bd92155ad6518ed5e69175f5072fbce5a9d92c61cbed00000000";
    const BLOCK2B_HASH: &str =
        "12e6e69d7447691dba85c462c9b214274064ea1dd8835c2dd731618add0320588706d4cc0b000000";

    let network = Network::Main;
    let expected_blk_files = ["blk0.dat"];
    let test_data_dir =
        ensure_blocks_in_test_data_dir(expected_blk_files.to_vec(), network, None).await;
    let block_file_paths =
        ArchivalState::read_block_file_names_from_directory(&test_data_dir).unwrap();
    let blocks = ArchivalState::blocks_from_file_without_record(&block_file_paths[0])
        .await
        .unwrap();

    let block1 = &blocks[0];
    assert_eq!(BLOCK1_HASH, block1.hash().to_hex());
    assert_eq!(
        MAIN_NET_GENESIS_HASH,
        block1.header().prev_block_digest.to_hex()
    );

    // block data contains shallow forks. So we have two blocks of height 2.
    let block2a = &blocks[1];
    assert_eq!(BLOCK2A_HASH, block2a.hash().to_hex());
    assert_eq!(BLOCK1_HASH, block2a.header().prev_block_digest.to_hex());

    let block2b = &blocks[2];
    assert_eq!(BLOCK2B_HASH, block2b.hash().to_hex());
    assert_eq!(BLOCK1_HASH, block2b.header().prev_block_digest.to_hex());
}

#[tokio::test(flavor = "multi_thread")]
async fn gamma_hardfork_on_tesnet0() {
    // Verify that blocks spanning consensus rule change on testnet are
    // considered valid.
    logging::tracing_logger();

    // Add checkpoint. Otherwise pre-hf blocks blocks fail
    let network = Network::Testnet(0);
    ArchivalState::accept_checkpoint(network).await;

    let blk_file = ["blk36.dat"];
    let test_data_dir = ensure_blocks_in_test_data_dir(blk_file.to_vec(), network, None).await;
    let block_file_paths =
        ArchivalState::read_block_file_names_from_directory(&test_data_dir).unwrap();
    let block_file_paths: Vec<_> = block_file_paths
        .into_iter()
        .filter(|x| x.to_string_lossy().contains("blk36"))
        .collect();
    let blocks = ArchivalState::blocks_from_file_without_record(&block_file_paths[0])
        .await
        .unwrap();

    let now = Timestamp::now();
    let mut latest = blocks[0].clone();
    for block in blocks.into_iter().skip(1) {
        let height = block.header().height;
        let hash = block.hash();
        info!("Checking validity of testnet block of height {height}; hash: {hash:x}",);
        assert!(
            block.is_valid(&latest, now, network).await,
            "height {height}; hash: {hash:x} must be valid"
        );
        assert!(block.has_proof_of_work(network, latest.header()));
        latest = block;
    }
}

/// Assert that a single main-net `blk` file whose blocks span a consensus-rule-set
/// change (hard fork) validates end to end: every block is valid relative to its
/// predecessor and carries valid proof-of-work, across the fork boundary.
async fn assert_hardfork_boundary_blocks_are_valid(
    sub_dir: &str,
    blk_file: &str,
    end_consensus_rules: ConsensusRuleSet,
) {
    logging::tracing_logger();

    let network = Network::Main;

    // Pre-gamma main-net proofs were retroactively found unsound, so their
    // validity is asserted via the checkpoint rather than re-verification.
    // Without it, pre-hardfork blocks fail.
    ArchivalState::accept_checkpoint(network).await;

    // Keep the file in its own subdirectory so it does not interfere with other
    // tests that import the entire main-net data directory.
    let test_data_dir =
        ensure_blocks_in_test_data_dir(vec![blk_file], network, Some(sub_dir)).await;
    let block_file_paths =
        ArchivalState::read_block_file_names_from_directory(&test_data_dir).unwrap();
    let block_file_paths: Vec<_> = block_file_paths
        .into_iter()
        .filter(|x| x.to_string_lossy().contains(blk_file))
        .collect();
    let blocks = ArchivalState::blocks_from_file_without_record(&block_file_paths[0])
        .await
        .unwrap();

    // The file must actually straddle the hard fork, otherwise this test would
    // silently stop exercising the rule-set transition.
    let first_rule_set = ConsensusRuleSet::infer_from(network, blocks[0].header().height);
    let last_rule_set =
        ConsensusRuleSet::infer_from(network, blocks.last().unwrap().header().height);
    assert_ne!(
        first_rule_set, last_rule_set,
        "{blk_file} must span a consensus-rule-set change"
    );
    assert_eq!(
        end_consensus_rules, last_rule_set,
        "last block in {blk_file} must follow {end_consensus_rules}"
    );

    let now = Timestamp::now();
    let mut latest = blocks[0].clone();
    for block in blocks.into_iter().skip(1) {
        let height = block.header().height;
        let hash = block.hash();
        println!("Checking validity of main-net block of height {height}; hash: {hash:x}");
        block.validate(&latest, now, network).await.unwrap();
        assert!(block.has_proof_of_work(network, latest.header()));
        latest = block;
    }
}

/// Verify that the sequence of main-net blocks spanning the hardfork-alpha
/// boundary (height 15,000) is valid.
#[tokio::test(flavor = "multi_thread")]
async fn alpha_hardfork_on_main_net() {
    assert_hardfork_boundary_blocks_are_valid(
        "hf-alpha-validity",
        "blk121.dat",
        ConsensusRuleSet::HardforkAlpha,
    )
    .await;
}

/// Verify that the sequence of main-net blocks spanning the hardfork-beta
/// boundary (height 38,000) is valid.
#[tokio::test(flavor = "multi_thread")]
async fn beta_hardfork_on_main_net() {
    assert_hardfork_boundary_blocks_are_valid(
        "hf-beta-validity",
        "blk325.dat",
        ConsensusRuleSet::HardforkBeta,
    )
    .await;
}

/// Verify that the sequence of main-net blocks spanning the hardfork-gamma
/// boundary (height 40,300) is valid.
#[tokio::test(flavor = "multi_thread")]
async fn gamma_hardfork_on_main_net() {
    assert_hardfork_boundary_blocks_are_valid(
        "hf-gamma-validity",
        "blk344.dat",
        ConsensusRuleSet::HardforkGamma,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blockprogram_claim_has_not_changed_40068_hf_beta() {
    logging::tracing_logger();

    let network = Network::Main;

    let blk_file = ["blk343.dat"];
    let test_data_dir =
        ensure_blocks_in_test_data_dir(blk_file.to_vec(), network, Some("hf-beta-claims-check"))
            .await;
    let block_file_paths =
        ArchivalState::read_block_file_names_from_directory(&test_data_dir).unwrap();
    let block_file_paths: Vec<_> = block_file_paths
        .into_iter()
        .filter(|x| x.to_string_lossy().contains("blk343"))
        .collect();
    let blocks = ArchivalState::blocks_from_file_without_record(&block_file_paths[0])
        .await
        .unwrap();
    let block = &blocks[0];
    let claim = BlockProgram::claim(
        block.body(),
        block.appendix(),
        ConsensusRuleSet::HardforkBeta,
    );

    let claim_bytes = bincode::serialize(&claim).expect("can serialize claim");
    let claim_hex = claim_bytes.into_iter().map(|b| format!("{b:02x}")).join("");

    // Expected value read from a v0.11.0 node -- using HF-beta rule set.
    assert_eq!(
        "72d46afed8a1bf162814a432cf1ebe0f16a1cdb84bd339badc6fbd499172c3474c285dd0d5ba4e0c0100000005000000000000006180a65eecef10ca257f9b1f92e6c521578eadc3d897cd76dcf30de61f6cc640369f3a5ad21eb19d05000000000000007563640e9b1cf5d28f3885c5235146974738b6ae88d72d485caf07ca076220a03a0f276f41b6d772",
        claim_hex);
}

/// test: Verify that first ~250 blocks on main net are still considered valid,
/// and that a global state can be restored from it.
#[tokio::test(flavor = "multi_thread")]
async fn can_restore_from_real_mainnet_data_with_reorganizations() {
    logging::tracing_logger();

    let network = Network::Main;
    let expected_blk_files = ["blk0.dat", "blk1.dat"];
    let test_data_dir =
        ensure_blocks_in_test_data_dir(expected_blk_files.to_vec(), network, None).await;

    let cli = GenesisNode::default_args_with_network_and_devnet_wallet(network).await;
    let mut alice = GenesisNode::start_node(cli).await.unwrap();

    let mut state = alice.gsl.lock_guard_mut().await;

    let validate_blocks = true;
    state
        .import_blocks_from_directory(&test_data_dir, 0, validate_blocks)
        .await
        .unwrap();
    let restored_block_height = state.chain.tip().header().height;
    println!("restored_block_height: {restored_block_height}");
    assert_eq!(
        BlockHeight::new(bfe!(250)),
        restored_block_height,
        "Expected block height not reached in state-recovery. Reached: {restored_block_height}"
    );

    // Verify that wallet state was handled correctly, that balance is still
    // premine reward, since the devnet reward was not spent during first
    // blocks.
    let final_height = state.chain.tip().header().height;
    let wallet_status = state.get_wallet_status_for_tip().await;
    let balance = wallet_status
        .confirmed_available_balance(final_height, network.launch_date() + Timestamp::months(7));
    assert_eq!(
        NativeCurrencyAmount::coins(20),
        balance,
        "Expected balance must be available after state-recovery"
    );

    drop(state);

    assert!(alice
        .gsl
        .revalidate_canonical_chain(BlockHeight::genesis(), final_height)
        .await
        .is_ok());
}

/// Fetch required files for testing, and return the directory.
async fn ensure_blocks_in_test_data_dir(
    blk_file_names: Vec<&str>,
    network: Network,
    sub_directory: Option<&str>,
) -> PathBuf {
    // Are the required blk files present on disk? If not, fetch them
    // from a server.
    let mut test_data_dir = test_helper_data_dir().join(format!("{network}"));
    if let Some(sub_dir) = sub_directory {
        test_data_dir = test_data_dir.join(sub_dir);
    }

    DataDirectory::create_dir_if_not_exists(test_data_dir.as_path())
        .await
        .unwrap();
    for file_name in blk_file_names {
        let mut path = test_data_dir.clone();
        path.push(file_name);
        if File::open(&path).is_err() {
            // Try fetching file from server and write it to disk.
            let (file, _server) = try_fetch_file_from_server(file_name.to_owned())
                .unwrap_or_else(|| panic!("File {file_name} must be available from a server"));
            let mut f = File::create_new(&path).unwrap();
            f.write_all(&file).unwrap();
        }
    }

    test_data_dir
}
