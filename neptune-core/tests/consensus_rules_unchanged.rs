mod common;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use common::logging;
use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::protocol::consensus::block::Block;
use neptune_cash::state::archival_state::ArchivalState;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::common::fetch_files::test_helper_data_dir;
use crate::common::fetch_files::try_fetch_file_from_server;
use crate::common::genesis_node::GenesisNode;

const MAIN_NET_GENESIS_HASH: &str =
    "7962e48729acd97e08efa77b5b28d49f2dc0e5609a4f1f1affca5b4549c78e520462a7f955371386";

/// test: Verify that the genesis block on main net has not changed.
#[test]
pub fn genesis_block_hasnt_changed_main_net() {
    assert_eq!(
        MAIN_NET_GENESIS_HASH,
        Block::genesis(Network::Main).hash().to_hex()
    );
}

/// test: Verify that the genesis block on testnet-0 has not changed.
#[test]
pub fn genesis_block_hasnt_changed_testnet_0() {
    assert_eq!(
        "bb1fa49a35a294dd2c09811c648c4d76f6ea17acc61fe7a6f1c3c8d81c967bc68e7cdb41f472544e",
        Block::genesis(Network::Testnet(0)).hash().to_hex()
    );
}

#[tokio::test(flavor = "multi_thread")]
pub async fn first_few_block_hashes_are_unchanged_main_net() {
    const BLOCK1_HASH: &str =
        "2a9b685b2f9cde0d6f258dcd3ab575ddabddd16d70f56e9b3ea7072e77a50aff95ad22c128000000";
    const BLOCK2A_HASH: &str =
        "50ed8d790911380c70dcf8e899e5bd92155ad6518ed5e69175f5072fbce5a9d92c61cbed00000000";
    const BLOCK2B_HASH: &str =
        "12e6e69d7447691dba85c462c9b214274064ea1dd8835c2dd731618add0320588706d4cc0b000000";

    let expected_blk_files = ["blk0.dat"];
    let test_data_dir = ensure_blocks_in_test_data_dir(expected_blk_files.to_vec()).await;
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

/// test: Verify that first ~250 blocks on main net are still considered valid,
/// and that a global state can be restored from it.
#[tokio::test(flavor = "multi_thread")]
async fn can_restore_from_real_mainnet_data_with_reorganizations() {
    logging::tracing_logger();

    let expected_blk_files = ["blk0.dat", "blk1.dat"];
    let test_data_dir = ensure_blocks_in_test_data_dir(expected_blk_files.to_vec()).await;

    let network = Network::Main;
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

async fn ensure_blocks_in_test_data_dir(blk_file_names: Vec<&str>) -> PathBuf {
    // Are the required blk files present on disk? If not, fetch them
    // from a server.
    let test_data_dir = test_helper_data_dir();
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
