use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::Result;
use bytes::Bytes;
use bytes::BytesMut;
use futures::sink;
use futures::stream;
use futures::task::Context;
use futures::task::Poll;
use itertools::Itertools;
use num_traits::Zero;
use pin_project_lite::pin_project;
use proptest::collection::vec;
use proptest::prelude::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest_arbitrary_interop::arb;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use rand::random;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_serde::formats::SymmetricalBincode;
use tokio_serde::Serializer;
use tokio_util::codec::Encoder;
use tokio_util::codec::LengthDelimitedCodec;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::digest::Digest;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use crate::config_models::cli_args;
use crate::config_models::data_directory::DataDirectory;
use crate::config_models::network::Network;
use crate::database::storage::storage_vec::traits::StorageVecBase;
use crate::database::NeptuneLevelDb;
use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::job_queue::JobQueue;
use crate::mine_loop::composer_parameters::ComposerParameters;
use crate::mine_loop::create_block_transaction_stateless;
use crate::mine_loop::make_coinbase_transaction_stateless;
use crate::mine_loop::mine_loop_tests::mine_iteration_for_tests;
use crate::models::blockchain::block::block_appendix::BlockAppendix;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_header::TARGET_BLOCK_INTERVAL;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockProof;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::transaction_kernel::transaction_kernel_tests::pseudorandom_transaction_kernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelProxy;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::blockchain::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
use crate::models::channel::MainToPeerTask;
use crate::models::channel::PeerTaskToMain;
use crate::models::database::BlockIndexKey;
use crate::models::database::BlockIndexValue;
use crate::models::database::PeerDatabases;
use crate::models::peer::HandshakeData;
use crate::models::peer::PeerConnectionInfo;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerMessage;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::blockchain_state::BlockchainArchivalState;
use crate::models::state::blockchain_state::BlockchainState;
use crate::models::state::light_state::LightState;
use crate::models::state::mempool::Mempool;
use crate::models::state::networking_state::NetworkingState;
use crate::models::state::tx_proving_capability::TxProvingCapability;
use crate::models::state::wallet::address::generation_address;
use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::models::state::wallet::WalletSecret;
use crate::models::state::GlobalStateLock;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::PEER_CHANNEL_CAPACITY;

/// Return an empty peer map
pub fn get_peer_map() -> HashMap<SocketAddr, PeerInfo> {
    HashMap::new()
}

// Return empty database objects, and root directory for this unit test instantiation's
/// data directory.
#[allow(clippy::type_complexity)]
pub async fn unit_test_databases(
    network: Network,
) -> Result<(
    NeptuneLevelDb<BlockIndexKey, BlockIndexValue>,
    PeerDatabases,
    DataDirectory,
)> {
    let data_dir: DataDirectory = unit_test_data_directory(network)?;

    let block_db = ArchivalState::initialize_block_index_database(&data_dir).await?;
    let peer_db = NetworkingState::initialize_peer_databases(&data_dir).await?;

    Ok((block_db, peer_db, data_dir))
}

pub fn get_dummy_socket_address(count: u8) -> SocketAddr {
    std::net::SocketAddr::from_str(&format!("127.0.0.{}:8080", count)).unwrap()
}

/// Get a dummy-peer representing an outgoing connection.
pub(crate) fn get_dummy_peer(address: SocketAddr) -> PeerInfo {
    let peer_connection_info = PeerConnectionInfo::new(Some(8080), address, false);
    PeerInfo::new(
        peer_connection_info,
        rand::random(),
        SystemTime::now(),
        get_dummy_version(),
        true,
        cli_args::Args::default().peer_tolerance,
    )
}

pub fn get_dummy_version() -> String {
    "0.0.10".to_string()
}

/// Return a handshake object with a randomly set instance ID
pub async fn get_dummy_handshake_data_for_genesis(network: Network) -> HandshakeData {
    HandshakeData {
        instance_id: rand::random(),
        tip_header: Block::genesis_block(network).header().to_owned(),
        listen_port: Some(8080),
        network,
        version: get_dummy_version(),
        is_archival_node: true,
    }
}

pub(crate) fn to_bytes(message: &PeerMessage) -> Result<Bytes> {
    let mut transport = LengthDelimitedCodec::new();
    let mut formating = SymmetricalBincode::<PeerMessage>::default();
    let mut buf = BytesMut::new();
    transport.encode(Pin::new(&mut formating).serialize(message)?, &mut buf)?;
    Ok(buf.freeze())
}

pub async fn get_dummy_peer_connection_data_genesis(
    network: Network,
    id: u8,
) -> (HandshakeData, SocketAddr) {
    let handshake = get_dummy_handshake_data_for_genesis(network).await;
    let socket_address = get_dummy_socket_address(id);

    (handshake, socket_address)
}

/// Get a global state object for unit test purposes. This global state
/// populated with state from the genesis block, e.g. in the archival mutator
/// set and the wallet.
///
/// All contained peers represent outgoing connections.
pub(crate) async fn mock_genesis_global_state(
    // TODO: Remove network and read it from CLI arguments instead
    network: Network,
    peer_count: u8,
    wallet: WalletSecret,
    cli: cli_args::Args,
) -> GlobalStateLock {
    let (archival_state, peer_db, _data_dir) = mock_genesis_archival_state(network).await;

    let syncing = false;
    let mut peer_map: HashMap<SocketAddr, PeerInfo> = get_peer_map();
    for i in 0..peer_count {
        let peer_address =
            std::net::SocketAddr::from_str(&format!("123.123.123.{}:8080", i)).unwrap();
        peer_map.insert(peer_address, get_dummy_peer(peer_address));
    }
    let networking_state = NetworkingState::new(peer_map, peer_db, syncing);
    let genesis_block = archival_state.get_tip().await;

    // Sanity check
    assert_eq!(archival_state.genesis_block().hash(), genesis_block.hash());

    let light_state: LightState = LightState::from(genesis_block.to_owned());
    println!(
        "Genesis light state MSA hash: {}",
        light_state.mutator_set_accumulator_after().hash()
    );
    let blockchain_state = BlockchainState::Archival(BlockchainArchivalState {
        light_state,
        archival_state,
    });
    let mempool = Mempool::new(
        cli.max_mempool_size,
        cli.max_mempool_num_tx,
        genesis_block.hash(),
    );

    let wallet_state = mock_genesis_wallet_state(wallet, network).await;

    GlobalStateLock::new(
        wallet_state,
        blockchain_state,
        networking_state,
        cli.clone(),
        mempool,
    )
}

/// Return a setup with empty databases, and with the genesis block set as tip.
///
/// Returns:
/// (peer_broadcast_channel, from_main_receiver, to_main_transmitter, to_main_receiver, global state, peer's handshake data)
#[allow(clippy::type_complexity)]
pub(crate) async fn get_test_genesis_setup(
    network: Network,
    peer_count: u8,
) -> Result<(
    broadcast::Sender<MainToPeerTask>,
    broadcast::Receiver<MainToPeerTask>,
    mpsc::Sender<PeerTaskToMain>,
    mpsc::Receiver<PeerTaskToMain>,
    GlobalStateLock,
    HandshakeData,
)> {
    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerTask>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerTaskToMain>(PEER_CHANNEL_CAPACITY);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let devnet_wallet = WalletSecret::devnet_wallet();
    let state = mock_genesis_global_state(
        network,
        peer_count,
        devnet_wallet,
        cli_args::Args::default(),
    )
    .await;
    Ok((
        peer_broadcast_tx,
        from_main_rx_clone,
        to_main_tx,
        _to_main_rx1,
        state,
        get_dummy_handshake_data_for_genesis(network).await,
    ))
}

/// Set a new block as tip
pub(crate) async fn add_block_to_archival_state(
    archival_state: &mut ArchivalState,
    new_block: Block,
) -> Result<()> {
    archival_state.write_block_as_tip(&new_block).await?;

    archival_state.update_mutator_set(&new_block).await.unwrap();

    archival_state.add_to_archival_block_mmr(&new_block).await;

    Ok(())
}

/// Create a randomly named `DataDirectory` so filesystem-bound tests can run
/// in parallel. If this is not done, parallel execution of unit tests will
/// fail as they each hold a lock on the database.
///
/// For now we use databases on disk. In-memory databases would be nicer.
pub(crate) fn unit_test_data_directory(network: Network) -> Result<DataDirectory> {
    let mut rng = rand::thread_rng();
    let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
    let tmp_root: PathBuf = env::temp_dir()
        .join(format!("neptune-unit-tests-{}", user))
        .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));

    DataDirectory::get(Some(tmp_root), network)
}

// Box<Vec<T>> is unnecessary because Vec<T> is already heap-allocated.
// However, Box<...> is used here because Pin<T> does not allow a &mut T,
// So a Box<T> (which also implements DerefMut) allows a pinned, mutable
// pointer.
//
// We suppress `clippy::box-collection` on a type alias because the can't
// easily place the pragma inside the `pin_project!` macro.
#[allow(clippy::box_collection)]
type ActionList<Item> = Box<Vec<Action<Item>>>;

pin_project! {
#[derive(Debug)]
pub struct Mock<Item> {
    #[pin]
    actions: ActionList<Item>,
}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockError {
    WrongSend,
    UnexpectedSend,
    UnexpectedRead,
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MockError::WrongSend => write!(f, "WrongSend"),
            MockError::UnexpectedSend => write!(f, "UnexpectedSend"),
            MockError::UnexpectedRead => write!(f, "UnexpectedRead"),
        }
    }
}

impl std::error::Error for MockError {}

#[derive(Debug, Clone)]
pub enum Action<Item> {
    Read(Item),
    Write(Item),
    // Todo: Some tests with these things
    // Wait(Duration),
    // ReadError(Option<Arc<io::Error>>),
    // WriteError(Option<Arc<io::Error>>),
}

impl<Item> Mock<Item> {
    pub fn new(actions: Vec<Action<Item>>) -> Mock<Item> {
        Mock {
            actions: Box::new(actions.into_iter().rev().collect()),
        }
    }
}

impl<Item: PartialEq> sink::Sink<Item> for Mock<Item> {
    type Error = MockError;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        match (self.actions.pop(), item) {
            (Some(Action::Write(a)), item) if item == a => Ok(()),
            (Some(Action::Write(_)), _) => Err(MockError::WrongSend),
            _ => Err(MockError::UnexpectedSend),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<Item> stream::Stream for Mock<Item> {
    type Item = Result<Item, MockError>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(Action::Read(a)) = self.actions.pop() {
            Poll::Ready(Some(Ok(a)))
        } else {
            // Returning `Poll::Ready(None)` here would probably simulate better
            // a peer closing the connection. Otherwise we have to close with a
            // `Bye` in all tests.
            Poll::Ready(Some(Err(MockError::UnexpectedRead)))
        }
    }
}

pub fn pseudorandom_option<T>(seed: [u8; 32], thing: T) -> Option<T> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    if rng.next_u32() % 2 == 0 {
        None
    } else {
        Some(thing)
    }
}

pub fn pseudorandom_amount(seed: [u8; 32]) -> NeptuneCoins {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let number: u128 = rng.gen::<u128>() >> 10;
    NeptuneCoins::from_nau(number.into()).unwrap()
}

pub fn pseudorandom_utxo(seed: [u8; 32]) -> Utxo {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    (
        rng.gen(),
        NeptuneCoins::new(rng.gen_range(0..42000000)).to_native_coins(),
    )
        .into()
}

pub fn random_transaction_kernel() -> TransactionKernel {
    let mut rng = thread_rng();
    let num_inputs = 1 + (rng.next_u32() % 5) as usize;
    let num_outputs = 1 + (rng.next_u32() % 6) as usize;
    let num_public_announcements = (rng.next_u32() % 5) as usize;
    pseudorandom_transaction_kernel(rng.gen(), num_inputs, num_outputs, num_public_announcements)
}

pub fn pseudorandom_public_announcement(seed: [u8; 32]) -> PublicAnnouncement {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let len = 10 + (rng.next_u32() % 50) as usize;
    let message = (0..len).map(|_| rng.gen()).collect_vec();
    PublicAnnouncement { message }
}

pub fn random_public_announcement() -> PublicAnnouncement {
    let mut rng = thread_rng();
    pseudorandom_public_announcement(rng.gen::<[u8; 32]>())
}

pub fn random_amount() -> NeptuneCoins {
    let mut rng = thread_rng();
    pseudorandom_amount(rng.gen::<[u8; 32]>())
}

pub fn random_option<T>(thing: T) -> Option<T> {
    let mut rng = thread_rng();
    pseudorandom_option(rng.gen::<[u8; 32]>(), thing)
}

pub(crate) fn make_mock_txs_with_primitive_witness_with_timestamp(
    count: usize,
    timestamp: Timestamp,
) -> Vec<Transaction> {
    let mut test_runner = TestRunner::deterministic();
    let primitive_witnesses = vec(
        arbitrary_primitive_witness_with_expired_timelocks(2, 2, 2, timestamp),
        count,
    )
    .new_tree(&mut test_runner)
    .unwrap()
    .current();

    primitive_witnesses
        .into_iter()
        .map(|pw| Transaction {
            kernel: pw.kernel.clone(),
            proof: TransactionProof::Witness(pw),
        })
        .collect_vec()
}

pub(crate) fn make_plenty_mock_transaction_with_primitive_witness(
    count: usize,
) -> Vec<Transaction> {
    let mut test_runner = TestRunner::deterministic();
    let deterministic_now = arb::<Timestamp>()
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
    let primitive_witnesses = vec(
        arbitrary_primitive_witness_with_expired_timelocks(2, 2, 2, deterministic_now),
        count,
    )
    .new_tree(&mut test_runner)
    .unwrap()
    .current();

    primitive_witnesses
        .into_iter()
        .map(|pw| Transaction {
            kernel: pw.kernel.clone(),
            proof: TransactionProof::Witness(pw),
        })
        .collect_vec()
}

/// Make a transaction with `Invalid` transaction proof.
pub fn make_mock_transaction(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
) -> Transaction {
    make_mock_transaction_with_mutator_set_hash(inputs, outputs, Digest::default())
}

pub(crate) fn make_mock_transaction_with_mutator_set_hash(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
) -> Transaction {
    let timestamp = Timestamp::now();

    Transaction {
        kernel: TransactionKernelProxy {
            inputs,
            outputs,
            public_announcements: vec![],
            fee: NeptuneCoins::new(1),
            timestamp,
            coinbase: None,
            mutator_set_hash,
            merge_bit: false,
        }
        .into_kernel(),
        proof: TransactionProof::invalid(),
    }
}

pub(crate) fn dummy_expected_utxo() -> ExpectedUtxo {
    ExpectedUtxo {
        utxo: Utxo::new_native_currency(LockScript::anyone_can_spend(), NeptuneCoins::zero()),
        addition_record: AdditionRecord::new(Default::default()),
        sender_randomness: Default::default(),
        receiver_preimage: Default::default(),
        received_from: UtxoNotifier::Myself,
        notification_received: Timestamp::now(),
        mined_in_block: None,
    }
}

pub(crate) fn mock_item_and_randomnesses() -> (Digest, Digest, Digest) {
    let mut rng = rand::thread_rng();
    let item: Digest = rng.gen();
    let sender_randomness: Digest = rng.gen();
    let receiver_preimage: Digest = rng.gen();
    (item, sender_randomness, receiver_preimage)
}

// TODO: Change this function into something more meaningful!
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    fee: NeptuneCoins,
    _wallet_state: &WalletState,
    timestamp: Option<Timestamp>,
) -> Transaction {
    let timestamp = match timestamp {
        Some(ts) => ts,
        None => Timestamp::now(),
    };
    let kernel = TransactionKernelProxy {
        inputs,
        outputs,
        public_announcements: vec![],
        fee,
        timestamp,
        coinbase: None,
        mutator_set_hash: random(),
        merge_bit: false,
    }
    .into_kernel();

    Transaction {
        kernel,
        proof: TransactionProof::invalid(),
    }
}

/// Create a block containing the supplied transaction kernel, starting from
/// the supplied mutator set.
///
/// The block proof will be invalid.
pub(crate) fn mock_block_from_transaction_and_msa(
    tx_kernel: TransactionKernel,
    mutator_set_before: MutatorSetAccumulator,
    network: Network,
) -> Block {
    let genesis_block = Block::genesis_block(network);
    let new_block_height: BlockHeight = BlockHeight::from(100u64);
    let block_header = BlockHeader {
        version: bfe!(0),
        height: new_block_height,
        prev_block_digest: genesis_block.hash().hash(),
        timestamp: tx_kernel.timestamp,
        nonce: Digest::default(),
        cumulative_proof_of_work: genesis_block.header().cumulative_proof_of_work,
        difficulty: genesis_block.header().difficulty,
    };

    let mut next_mutator_set = mutator_set_before.clone();
    let ms_update = MutatorSetUpdate::new(tx_kernel.inputs.clone(), tx_kernel.outputs.clone());
    ms_update
        .apply_to_accumulator(&mut next_mutator_set)
        .unwrap();

    let empty_mmr = MmrAccumulator::init(vec![], 0);
    let body = BlockBody::new(tx_kernel, next_mutator_set, empty_mmr.clone(), empty_mmr);
    let appendix = BlockAppendix::default();

    Block::new(block_header, body, appendix, BlockProof::Invalid)
}

/// Create a block containing the supplied transaction.
///
/// The returned block has an invalid block proof.
pub(crate) fn invalid_block_with_transaction(
    previous_block: &Block,
    transaction: Transaction,
) -> Block {
    let new_block_height: BlockHeight = previous_block.kernel.header.height.next();
    let block_header = BlockHeader {
        version: bfe!(0),
        height: new_block_height,
        prev_block_digest: previous_block.hash(),
        timestamp: transaction.kernel.timestamp,
        nonce: Digest::default(),
        cumulative_proof_of_work: previous_block.header().cumulative_proof_of_work,
        difficulty: previous_block.header().difficulty,
    };

    let mut next_mutator_set = previous_block.mutator_set_accumulator_after().clone();
    let mut block_mmr = previous_block.kernel.body.block_mmr_accumulator.clone();
    block_mmr.append(previous_block.hash());

    let ms_update = MutatorSetUpdate::new(
        transaction.kernel.inputs.clone(),
        transaction.kernel.outputs.clone(),
    );
    ms_update
        .apply_to_accumulator(&mut next_mutator_set)
        .unwrap();

    let body = BlockBody::new(
        transaction.kernel,
        next_mutator_set,
        previous_block.body().lock_free_mmr_accumulator.clone(),
        block_mmr,
    );
    let appendix = BlockAppendix::default();

    Block::new(block_header, body, appendix, BlockProof::Invalid)
}

/// Build a fake and invalid block where the caller can specify the
/// nonce-preimage and guesser fraction.
///
/// Returns (block, composer's expected UTXOs).
pub(crate) async fn make_mock_block_with_nonce_preimage_and_guesser_fraction(
    previous_block: &Block,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    seed: [u8; 32],
    guesser_fraction: f64,
    nonce_preimage: Digest,
) -> (Block, Vec<ExpectedUtxo>) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);

    // Build coinbase UTXO and associated data
    let block_timestamp = match block_timestamp {
        Some(ts) => ts,
        None => previous_block.kernel.header.timestamp + TARGET_BLOCK_INTERVAL,
    };

    let coinbase_sender_randomness: Digest = rng.gen();
    let composer_parameters = ComposerParameters::new(
        composer_key.to_address().into(),
        coinbase_sender_randomness,
        guesser_fraction,
    );

    let (tx, composer_txos) = make_coinbase_transaction_stateless(
        previous_block,
        composer_parameters,
        block_timestamp,
        TxProvingCapability::PrimitiveWitness,
        &JobQueue::dummy(),
    )
    .await
    .unwrap();

    let block = Block::block_template_invalid_proof(
        previous_block,
        tx,
        block_timestamp,
        nonce_preimage,
        None,
    );

    let composer_expected_utxos = composer_txos
        .iter()
        .map(|txo| {
            ExpectedUtxo::new(
                txo.utxo(),
                txo.sender_randomness(),
                composer_key.privacy_preimage(),
                UtxoNotifier::OwnMinerComposeBlock,
            )
        })
        .collect();

    (block, composer_expected_utxos)
}

/// Build a fake block with a random hash, containing *two* outputs for the
/// composer.
///
/// Returns (block, composer-utxos).
pub(crate) async fn make_mock_block(
    previous_block: &Block,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    seed: [u8; 32],
) -> (Block, Vec<ExpectedUtxo>) {
    let nonce_preimage = Digest::default();
    let (block, composer_expected_utxos) =
        make_mock_block_with_nonce_preimage_and_guesser_fraction(
            previous_block,
            block_timestamp,
            composer_key,
            seed,
            0f64,
            nonce_preimage,
        )
        .await;

    (block, composer_expected_utxos)
}

/// Return a dummy-wallet used for testing. The returned wallet is populated with
/// whatever UTXOs are present in the genesis block.
pub async fn mock_genesis_wallet_state(
    wallet_secret: WalletSecret,
    network: Network,
) -> WalletState {
    let data_dir = unit_test_data_directory(network).unwrap();
    mock_genesis_wallet_state_with_data_dir(wallet_secret, network, &data_dir).await
}

pub async fn mock_genesis_wallet_state_with_data_dir(
    wallet_secret: WalletSecret,
    network: Network,
    data_dir: &DataDirectory,
) -> WalletState {
    let cli_args: cli_args::Args = cli_args::Args {
        number_of_mps_per_utxo: 30,
        network,
        ..Default::default()
    };
    WalletState::new_from_wallet_secret(data_dir, wallet_secret, &cli_args).await
}

/// Return an archival state populated with the genesis block
pub(crate) async fn mock_genesis_archival_state(
    network: Network,
) -> (ArchivalState, PeerDatabases, DataDirectory) {
    let (block_index_db, peer_db, data_dir) = unit_test_databases(network).await.unwrap();

    let ams = ArchivalState::initialize_mutator_set(&data_dir)
        .await
        .unwrap();

    let archival_block_mmr = ArchivalState::initialize_archival_block_mmr(&data_dir)
        .await
        .unwrap();

    let archival_state = ArchivalState::new(
        data_dir.clone(),
        block_index_db,
        ams,
        archival_block_mmr,
        network,
    )
    .await;

    (archival_state, peer_db, data_dir)
}

/// Create and store the next block including any transactions presently in the
/// mempool.  The coinbase and guesser fee will go to our own wallet.
///
/// the stored block does NOT have valid proof-of-work, nor does it have a valid
/// block proof.
pub(crate) async fn mine_block_to_wallet_invalid_block_proof(
    global_state_lock: &mut GlobalStateLock,
    timestamp: Timestamp,
) -> Result<Block> {
    let tip_block = global_state_lock
        .lock_guard()
        .await
        .chain
        .light_state()
        .to_owned();

    let (transaction, expected_composer_utxos) =
        crate::mine_loop::create_block_transaction(&tip_block, global_state_lock, timestamp)
            .await?;

    let nonce_preimage = Digest::default();
    let block = Block::block_template_invalid_proof(
        &tip_block,
        transaction,
        timestamp,
        nonce_preimage,
        None,
    );
    let expected_utxos = block
        .guesser_fee_expected_utxos(nonce_preimage)
        .into_iter()
        .chain(expected_composer_utxos)
        .collect_vec();

    global_state_lock
        .set_new_self_mined_tip(block.clone(), expected_utxos)
        .await?;

    Ok(block)
}

pub(crate) fn invalid_empty_block(predecessor: &Block) -> Block {
    let tx = make_mock_transaction_with_mutator_set_hash(
        vec![],
        vec![],
        predecessor.mutator_set_accumulator_after().hash(),
    );
    let timestamp = predecessor.header().timestamp + Timestamp::hours(1);
    Block::block_template_invalid_proof(predecessor, tx, timestamp, Digest::default(), None)
}

pub(crate) async fn valid_block_from_tx_for_tests(
    predecessor: &Block,
    tx: Transaction,
    seed: [u8; 32],
) -> Block {
    let timestamp = tx.kernel.timestamp;
    let mut block = Block::compose(
        predecessor,
        tx,
        timestamp,
        Digest::default(),
        None,
        &TritonVmJobQueue::dummy(),
        TritonVmJobPriority::default().into(),
    )
    .await
    .unwrap();

    let threshold = predecessor.header().difficulty.target();
    let mut rng = StdRng::from_seed(seed);
    while !block.has_proof_of_work(predecessor.header()) {
        mine_iteration_for_tests(&mut block, threshold, &mut rng);
    }

    block
}

pub(crate) async fn valid_successor_for_tests(
    predecessor: &Block,
    timestamp: Timestamp,
    seed: [u8; 32],
) -> Block {
    let mut rng = StdRng::from_seed(seed);

    let composer_parameters = ComposerParameters::new(
        GenerationReceivingAddress::derive_from_seed(rng.gen()).into(),
        rng.gen(),
        0.5f64,
    );
    let (block_tx, _) = create_block_transaction_stateless(
        predecessor,
        composer_parameters,
        timestamp,
        rng.gen(),
        &TritonVmJobQueue::dummy(),
        vec![],
    )
    .await
    .unwrap();

    valid_block_from_tx_for_tests(predecessor, block_tx, rng.gen()).await
}

/// Create a valid block with coinbase going to self. For testing purposes.
///
/// The block will be valid both in terms of PoW and block proof and will pass
/// the Block::is_valid() function.
pub(crate) async fn valid_block_for_tests(state_lock: &GlobalStateLock, seed: [u8; 32]) -> Block {
    let current_tip = state_lock.lock_guard().await.chain.light_state().clone();
    valid_successor_for_tests(
        &current_tip,
        current_tip.header().timestamp + Timestamp::hours(1),
        seed,
    )
    .await
}

/// Create a deterministic sequence of valid blocks.
///
/// Sequence is N-long. Every block i with i > 0 has block i-1 as its
/// predecessor; block 0 has the `predecessor` argument as predecessor. Every
/// block is valid in terms of both `is_valid` and `has_proof_of_work`.
pub(crate) async fn valid_sequence_of_blocks_for_tests<const N: usize>(
    mut predecessor: &Block,
    block_interval: Timestamp,
    seed: [u8; 32],
) -> [Block; N] {
    let mut blocks = vec![];
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    for _ in 0..N {
        let block = valid_successor_for_tests(
            predecessor,
            predecessor.header().timestamp + block_interval,
            rng.gen(),
        )
        .await;
        blocks.push(block);
        predecessor = blocks.last().unwrap();
    }
    blocks.try_into().unwrap()
}

pub(crate) async fn wallet_state_has_all_valid_mps(
    wallet_state: &WalletState,
    tip_block: &Block,
) -> bool {
    let monitored_utxos = wallet_state.wallet_db.monitored_utxos();
    for monitored_utxo in monitored_utxos.get_all().await.iter() {
        let current_mp = monitored_utxo.get_membership_proof_for_block(tip_block.hash());

        match current_mp {
            Some(mp) => {
                if !tip_block
                    .mutator_set_accumulator_after()
                    .verify(Tip5::hash(&monitored_utxo.utxo), &mp)
                {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}
