use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::SystemTime;

use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::api::export::Network;
use crate::application::config::cli_args;
use crate::application::loops::channel::MainToPeerTask;
use crate::application::loops::channel::PeerTaskToMain;
use crate::protocol::consensus::block::Block;
use crate::protocol::peer::handshake_data::VersionString;
use crate::protocol::peer::peer_info::PeerConnectionInfo;
use crate::protocol::peer::peer_info::PeerInfo;
use crate::state::blockchain_state::BlockchainState;
use crate::state::light_state::LightState;
use crate::state::mempool::Mempool;
use crate::state::networking_state::NetworkingState;
use crate::state::wallet::wallet_configuration::WalletConfiguration;
use crate::state::wallet::wallet_entropy::WalletEntropy;
use crate::state::GlobalState;
use crate::state::GlobalStateLock;
use crate::HandshakeData;
use crate::RPCServerToMain;
use crate::PEER_CHANNEL_CAPACITY;
use crate::VERSION;

/// Get a global state object for unit test purposes. This global state is
/// populated with state from a caller-defined genesis block.
/// All contained peers represent outgoing connections.
pub(crate) async fn mock_genesis_global_state_with_block(
    peer_count: u8,
    wallet: WalletEntropy,
    cli: cli_args::Args,
    genesis_block: Block,
) -> GlobalStateLock {
    let data_dir = crate::tests::shared::files::unit_test_data_directory(cli.network).unwrap();
    let archival_state = crate::state::archival_state::ArchivalState::new(
        data_dir.clone(),
        genesis_block.clone(),
        cli.network,
    )
    .await;

    let peer_db = NetworkingState::initialize_peer_databases(&data_dir)
        .await
        .unwrap();
    let mut peer_map = get_peer_map();
    for i in 0..peer_count {
        let peer_address =
            std::net::SocketAddr::from_str(&format!("123.123.123.{}:8080", i)).unwrap();
        peer_map.insert(peer_address, get_dummy_peer_outgoing(peer_address));
    }
    let net = NetworkingState::new(peer_map, peer_db);

    // Sanity check
    assert_eq!(archival_state.genesis_block().hash(), genesis_block.hash());
    assert_eq!(archival_state.get_tip().await.hash(), genesis_block.hash());

    let light_state: LightState = LightState::from(genesis_block.to_owned());
    let chain = BlockchainState::Archival(Box::new(
        crate::state::blockchain_state::BlockchainArchivalState {
            light_state,
            archival_state,
        },
    ));
    let mempool = Mempool::new(
        cli.max_mempool_size,
        cli.proving_capability(),
        &genesis_block,
    );

    let configuration = WalletConfiguration::new(&data_dir).absorb_options(&cli);
    let wallet_state = crate::state::wallet::wallet_state::WalletState::try_new(
        configuration,
        wallet,
        &genesis_block,
    )
    .await
    .unwrap();

    // dummy channel
    let (rpc_to_main_tx, mut rpc_to_main_rx) = tokio::sync::mpsc::channel::<RPCServerToMain>(5);
    tokio::spawn(async move {
        while let Some(i) = rpc_to_main_rx.recv().await {
            tracing::trace!("mock Main got message = {:?}", i);
        }
    });

    let global_state = GlobalState::new(wallet_state, chain, net, cli, mempool);

    GlobalStateLock::from_global_state(global_state, rpc_to_main_tx)
}

/// Get a global state object for unit test purposes. This global state is
/// populated with state from the genesis block, e.g. in the archival mutator
/// set and the wallet.
///
/// All contained peers represent outgoing connections.
pub(crate) async fn mock_genesis_global_state(
    peer_count: u8,
    wallet: WalletEntropy,
    cli: cli_args::Args,
) -> GlobalStateLock {
    let genesis_block = Block::genesis(cli.network);
    mock_genesis_global_state_with_block(peer_count, wallet, cli, genesis_block).await
}

/// A state with a premine UTXO and self-mined blocks. Both composing and
/// guessing was done by the returned entity. Tip has height of
/// `num_blocks_mined`.
pub(crate) async fn state_with_premine_and_self_mined_blocks<const NUM_BLOCKS_MINED: usize>(
    cli_args: cli_args::Args,
    coinbase_sender_randomness_coll: [tasm_lib::prelude::Digest; NUM_BLOCKS_MINED],
) -> GlobalStateLock {
    let network = cli_args.network;
    let wallet = WalletEntropy::devnet_wallet();
    let composer_key = wallet.composer_fee_key();
    let mut global_state_lock =
        mock_genesis_global_state(2, wallet.clone(), cli_args.clone()).await;
    let mut previous_block = Block::genesis(network);

    let guesser_key = wallet.guesser_fee_key();
    let guesser_address = guesser_key.to_address();
    for coinbase_sender_randomness in coinbase_sender_randomness_coll {
        let (next_block, composer_utxos) =
            super::blocks::make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
                &previous_block,
                vec![],
                vec![],
                None,
                composer_key,
                coinbase_sender_randomness,
                (0.5, guesser_address.into()),
                network,
            )
            .await;

        global_state_lock
            .set_new_self_composed_tip(next_block.clone(), composer_utxos)
            .await
            .unwrap();

        previous_block = next_block;
    }

    global_state_lock
}

/// Return a setup with empty databases, and with the genesis block set as tip.
///
/// Returns:
/// (peer_broadcast_channel, from_main_receiver, to_main_transmitter, to_main_receiver, global state, peer's handshake data)
pub(crate) async fn get_test_genesis_setup(
    network: Network,
    peer_count: u8,
    cli: cli_args::Args,
) -> anyhow::Result<(
    broadcast::Sender<MainToPeerTask>,
    broadcast::Receiver<MainToPeerTask>,
    mpsc::Sender<PeerTaskToMain>,
    mpsc::Receiver<PeerTaskToMain>,
    GlobalStateLock,
    HandshakeData,
)> {
    let genesis = Block::genesis(network);
    test_setup_custom_genesis_block(network, peer_count, cli, genesis).await
}

pub(crate) async fn test_setup_custom_genesis_block(
    network: Network,
    peer_count: u8,
    cli: cli_args::Args,
    custom_genesis: Block,
) -> anyhow::Result<(
    broadcast::Sender<MainToPeerTask>,
    broadcast::Receiver<MainToPeerTask>,
    mpsc::Sender<PeerTaskToMain>,
    mpsc::Receiver<PeerTaskToMain>,
    GlobalStateLock,
    HandshakeData,
)> {
    let (peer_broadcast_tx, from_main_rx) =
        broadcast::channel::<MainToPeerTask>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, to_main_rx) = mpsc::channel::<PeerTaskToMain>(PEER_CHANNEL_CAPACITY);

    let wallet = WalletEntropy::devnet_wallet();
    let state = mock_genesis_global_state_with_block(peer_count, wallet, cli, custom_genesis).await;
    Ok((
        peer_broadcast_tx,
        from_main_rx,
        to_main_tx,
        to_main_rx,
        state,
        get_dummy_handshake_data_for_genesis(network),
    ))
}

/// Return an empty peer map
pub fn get_peer_map() -> HashMap<SocketAddr, PeerInfo> {
    HashMap::new()
}

pub fn get_dummy_socket_address(count: u8) -> SocketAddr {
    std::net::SocketAddr::from_str(&format!("113.151.22.{}:8080", count)).unwrap()
}

/// Get a dummy-peer representing an incoming connection.
pub(crate) fn get_dummy_peer_incoming(address: SocketAddr) -> PeerInfo {
    let peer_connection_info = PeerConnectionInfo::new(Some(8080), address, true);
    let peer_handshake = get_dummy_handshake_data_for_genesis(Network::Main);
    PeerInfo::new(
        peer_connection_info,
        &peer_handshake,
        SystemTime::now(),
        cli_args::Args::default().peer_tolerance,
    )
}

/// Get a dummy-peer representing an outgoing connection.
pub(crate) fn get_dummy_peer_outgoing(address: SocketAddr) -> PeerInfo {
    let peer_connection_info = PeerConnectionInfo::new(Some(8080), address, false);
    let peer_handshake = get_dummy_handshake_data_for_genesis(Network::Main);
    PeerInfo::new(
        peer_connection_info,
        &peer_handshake,
        SystemTime::now(),
        cli_args::Args::default().peer_tolerance,
    )
}

pub fn get_dummy_version() -> VersionString {
    VersionString::try_from_str(VERSION).unwrap()
}

/// Return a handshake object with a randomly set instance ID
pub(crate) fn get_dummy_handshake_data_for_genesis(network: Network) -> HandshakeData {
    HandshakeData {
        instance_id: rand::random(),
        tip_header: Block::genesis(network).header().to_owned(),
        listen_port: Some(8080),
        network,
        version: get_dummy_version(),
        is_archival_node: true,
        is_bootstrapper_node: false,
        timestamp: SystemTime::now(),
        extra_data: Default::default(),
    }
}

pub(crate) fn get_dummy_peer_connection_data_genesis(
    network: Network,
    id: u8,
) -> (HandshakeData, SocketAddr) {
    let handshake = get_dummy_handshake_data_for_genesis(network);
    let socket_address = get_dummy_socket_address(id);

    (handshake, socket_address)
}
