mod common;

use std::fs::File;
use std::io::Write;

use common::logging;
use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::protocol::consensus::block::Block;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use crate::common::fetch_files::test_helper_data_dir;
use crate::common::fetch_files::try_fetch_file_from_server;
use crate::common::genesis_node::GenesisNode;

/// test: Verify that the genesis block on main net has not changed.
#[test]
pub fn genesis_block_hasnt_changed_main_net() {
    assert_eq!(
        "7962e48729acd97e08efa77b5b28d49f2dc0e5609a4f1f1affca5b4549c78e520462a7f955371386",
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

/// test: Verify that first ~250 blocks on main net are still considered valid,
/// and that a global state can be restored from it.
#[tokio::test(flavor = "multi_thread")]
async fn can_restore_from_real_mainnet_data_with_reorganizations() {
    logging::tracing_logger();

    let expected_blk_files = ["blk0.dat", "blk1.dat"];

    let network = Network::Main;
    let cli = GenesisNode::default_args_with_network_and_devnet_wallet(network).await;
    let mut alice = GenesisNode::start_node(cli).await.unwrap();

    let mut state = alice.gsl.lock_guard_mut().await;

    // Are the required blk files present on disk? If not, fetch them
    // from a server.
    let test_data_dir = test_helper_data_dir();
    for blk_file_name in expected_blk_files {
        let mut path = test_data_dir.clone();
        path.push(blk_file_name);
        if File::open(&path).is_err() {
            // Try fetching file from server and write it to disk.
            let (file, _server) = try_fetch_file_from_server(blk_file_name.to_owned())
                .unwrap_or_else(|| panic!("File {blk_file_name} must be available from a server"));
            let mut f = File::create_new(&path).unwrap();
            f.write_all(&file).unwrap();
        }
    }

    let validate_blocks = true;
    state
        .import_blocks_from_directory(&test_data_dir, 0, validate_blocks)
        .await
        .unwrap();
    let restored_block_height = state.chain.light_state().header().height;
    println!("restored_block_height: {restored_block_height}");
    assert_eq!(
        BlockHeight::new(bfe!(250)),
        restored_block_height,
        "Expected block height not reached in state-recovery. Reached: {restored_block_height}"
    );

    // Verify that wallet state was handled correctly, that balance is still
    // premine reward, since the devnet reward was not spent during first
    // blocks.
    let wallet_status = state.get_wallet_status_for_tip().await;
    let balance = wallet_status.available_confirmed(network.launch_date() + Timestamp::months(7));
    assert_eq!(
        NativeCurrencyAmount::coins(20),
        balance,
        "Expected balance must be available after state-recovery"
    );
}
