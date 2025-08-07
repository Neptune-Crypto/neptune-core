mod common;

use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::models::blockchain::block::Block;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

use common::logging;
use rand::seq::SliceRandom;
use tasm_lib::twenty_first::bfe;
use tracing::debug;
use tracing::Span;

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
    // Local function copied from elsewhere because it's under the test flag
    // the other place.
    fn test_helper_data_dir() -> PathBuf {
        const TEST_DATA_DIR_NAME: &str = "test_data/";
        let mut path = PathBuf::new();
        path.push(TEST_DATA_DIR_NAME);
        path
    }

    // Local function copied from elsewhere because it's under the test flag
    // the other place.
    fn try_fetch_file_from_server(filename: String) -> Option<(Vec<u8>, String)> {
        const TEST_NAME_HTTP_HEADER_KEY: &str = "Test-Name";

        fn get_test_name_from_tracing() -> String {
            match Span::current().metadata().map(|x| x.name()) {
                Some(test_name) => test_name.to_owned(),
                None => "unknown".to_owned(),
            }
        }

        fn attempt_to_get_test_name() -> String {
            let thread = std::thread::current();
            match thread.name() {
                Some(test_name) => {
                    if test_name.eq("tokio-runtime-worker") {
                        get_test_name_from_tracing()
                    } else {
                        test_name.to_owned()
                    }
                }
                None => get_test_name_from_tracing(),
            }
        }

        fn load_servers() -> Vec<String> {
            let mut server_list_path = test_helper_data_dir();
            server_list_path.push(Path::new("proof_servers").with_extension("txt"));
            let Ok(mut input_file) = File::open(server_list_path.clone()) else {
                debug!(
                    "cannot proof-server list '{}' -- file might not exist",
                    server_list_path.display()
                );
                return vec![];
            };
            let mut file_contents = vec![];
            if input_file.read_to_end(&mut file_contents).is_err() {
                debug!("cannot read file '{}'", server_list_path.display());
                return vec![];
            }
            let Ok(file_as_string) = String::from_utf8(file_contents) else {
                debug!(
                    "cannot parse file '{}' -- is it valid utf8?",
                    server_list_path.display()
                );
                return vec![];
            };
            file_as_string.lines().map(|s| s.to_string()).collect()
        }

        let mut servers = load_servers();
        servers.shuffle(&mut rand::rng());

        // Add test name to request allow server to see which test requires this
        // file.
        let mut headers = clienter::HttpHeaders::default();
        headers.insert(
            TEST_NAME_HTTP_HEADER_KEY.to_string(),
            attempt_to_get_test_name(),
        );

        for server in servers {
            let server_ = server.clone();
            let filename_ = filename.clone();
            let headers_ = headers.clone();
            let handle = std::thread::spawn(move || {
                let url = format!("{}{}", server_, filename_);

                debug!("requesting: <{url}>");

                let uri: clienter::Uri = url.into();

                let mut http_client = clienter::HttpClient::new();
                http_client.timeout = Some(Duration::from_secs(10));
                http_client.headers = headers_;
                let request = http_client.request(clienter::HttpMethod::GET, uri);

                // note: send() blocks
                let Ok(mut response) = http_client.send(&request) else {
                    println!(
                        "server '{}' failed for file '{}'; trying next ...",
                        server_.clone(),
                        filename_
                    );

                    return None;
                };

                // only retrieve body if we got a 2xx code.
                // addresses #477
                // https://github.com/Neptune-Crypto/neptune-core/issues/477
                let body = if response.status.is_success() {
                    response.body()
                } else {
                    Ok(vec![])
                };

                Some((response.status, body))
            });

            let Some((status_code, body)) = handle.join().unwrap() else {
                eprintln!("Could not connect to server {server}.");
                continue;
            };

            if !status_code.is_success() {
                eprintln!("{server} responded with {status_code}");
                continue;
            }

            let Ok(file_contents) = body else {
                eprintln!(
                    "error reading file '{}' from server '{}'; trying next ...",
                    filename, server
                );

                continue;
            };

            return Some((file_contents, server));
        }

        println!("No known servers serve file `{}`", filename);

        None
    }

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
    let balance = state
        .wallet_state
        .confirmed_available_balance(&wallet_status, network.launch_date() + Timestamp::months(7));
    assert_eq!(
        NativeCurrencyAmount::coins(20),
        balance,
        "Expected balance must be available after state-recovery"
    );
}
