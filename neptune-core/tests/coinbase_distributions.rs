mod common;

use common::genesis_node::GenesisNode;
use common::logging;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::ReceivingAddress;
use neptune_cash::api::export::Timestamp;
use neptune_cash::application::loops::mine_loop::coinbase_distribution::CoinbaseDistribution;
use neptune_cash::application::loops::mine_loop::coinbase_distribution::CoinbaseOutput;
use rand::Rng;

// #[traced_test]
#[tokio::test(flavor = "multi_thread")]
pub async fn custom_coinbase_distribution() {
    logging::tracing_logger();

    let mut rng = rand::rng();
    let mut cli_args = GenesisNode::default_args().await;

    // random ports to prevent multiple test runs from using same
    // socket.
    cli_args.peer_port = rng.random_range((1 << 10)..=u16::MAX);
    cli_args.rpc_port = rng.random_range((1 << 10)..=u16::MAX);

    // Ensure entire block subsidy goes to composer
    cli_args.guesser_fraction = 0f64;

    let mut alice = GenesisNode::start_node(cli_args).await.unwrap();
    let address: ReceivingAddress = alice
        .gsl
        .lock_guard()
        .await
        .wallet_state
        .wallet_entropy
        .composer_fee_key()
        .to_address()
        .into();

    // 75 % timelocked, 25 % liquid
    let coinbase_distribution = vec![
        CoinbaseOutput::timelocked(address.clone(), 500),
        CoinbaseOutput::liquid(address.clone(), 1),
        CoinbaseOutput::liquid(address.clone(), 249),
        CoinbaseOutput::timelocked(address.clone(), 125),
        CoinbaseOutput::timelocked(address.clone(), 125),
    ];
    let coinbase_distribution = CoinbaseDistribution::try_new(coinbase_distribution).unwrap();
    alice
        .gsl
        .lock_guard_mut()
        .await
        .mining_state
        .set_coinbase_distribution(coinbase_distribution);

    // Mine one block and verify what was received
    alice
        .gsl
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await
        .unwrap();

    let wallet_status = alice
        .gsl
        .lock_guard()
        .await
        .get_wallet_status_for_tip()
        .await;
    assert_eq!(
        NativeCurrencyAmount::coins(128),
        wallet_status.total_confirmed(),
        "Must have expected block reward"
    );
    assert_eq!(
        NativeCurrencyAmount::coins(32),
        wallet_status.available_confirmed(Timestamp::now()),
        "Must have 1/4 of block reward liquid"
    );
}
