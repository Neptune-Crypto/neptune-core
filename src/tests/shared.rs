use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::bail;
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
use proptest::prelude::BoxedStrategy;
use proptest::prelude::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest_arbitrary_interop::arb;
use rand::Rng;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_serde::formats::SymmetricalBincode;
use tokio_serde::Serializer;
use tokio_util::codec::Encoder;
use tokio_util::codec::LengthDelimitedCodec;
use tracing::warn;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::digest::Digest;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use crate::config_models::cli_args;
use crate::config_models::data_directory::DataDirectory;
use crate::config_models::fee_notification_policy::FeeNotificationPolicy;
use crate::config_models::network::Network;
use crate::database::storage::storage_vec::traits::StorageVecBase;
use crate::mine_loop::composer_parameters::ComposerParameters;
use crate::mine_loop::make_coinbase_transaction_stateless;
use crate::mine_loop::prepare_coinbase_transaction_stateless;
use crate::mine_loop::tests::mine_iteration_for_tests;
use crate::models::blockchain::block::block_appendix::BlockAppendix;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use crate::models::blockchain::block::validity::block_program::BlockProgram;
use crate::models::blockchain::block::validity::block_proof_witness::BlockProofWitness;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockProof;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_kernel;
use crate::models::blockchain::transaction::transaction_kernel::tests::propcompose_txkernel_with_lengths;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelModifier;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelProxy;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::validity::neptune_proof::Proof;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::blockchain::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
use crate::models::channel::MainToPeerTask;
use crate::models::channel::PeerTaskToMain;
use crate::models::database::PeerDatabases;
use crate::models::peer::handshake_data::VersionString;
use crate::models::peer::peer_info::PeerConnectionInfo;
use crate::models::peer::peer_info::PeerInfo;
use crate::models::peer::PeerMessage;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::verifier::cache_true_claim;
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::blockchain_state::BlockchainArchivalState;
use crate::models::state::blockchain_state::BlockchainState;
use crate::models::state::light_state::LightState;
use crate::models::state::mempool::Mempool;
use crate::models::state::networking_state::NetworkingState;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::address::generation_address;
use crate::models::state::wallet::address::generation_address::GenerationReceivingAddress;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::transaction_output::TxOutputList;
use crate::models::state::wallet::wallet_configuration::WalletConfiguration;
use crate::models::state::wallet::wallet_entropy::WalletEntropy;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::models::state::GlobalState;
use crate::models::state::GlobalStateLock;
use crate::prelude::twenty_first;
use crate::tests::shared::files::unit_test_data_directory;
use crate::triton_vm_job_queue::TritonVmJobQueue;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::HandshakeData;
use crate::RPCServerToMain;
use crate::PEER_CHANNEL_CAPACITY;
use crate::VERSION;

pub mod files;

/// Ubiquitous container holding any combination of randomness used in the test helpers; implements both
/// random and `proptest` generation. Useful when helper needs few random values and a call to it becomes
/// cluttered.
#[derive(arbitrary::Arbitrary, Debug, Clone, PartialEq, Eq)]
pub struct Randomness<const BA: usize, const D: usize> {
    pub bytes_arr: [[u8; 32]; BA],
    pub digests: [Digest; D],
}
impl<const BA: usize, const D: usize> rand::distr::Distribution<Randomness<BA, D>>
    for rand::distr::StandardUniform
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Randomness<BA, D> {
        let mut bytes = [[Default::default(); 32]; BA];
        let mut digests = [Default::default(); D];
        for b in &mut bytes {
            rng.fill_bytes(b);
        }
        for d in &mut digests {
            *d = rng.random();
        }
        Randomness {
            bytes_arr: bytes,
            digests,
        }
    }
}
impl<const BA: usize, const D: usize> Default for Randomness<BA, D> {
    fn default() -> Self {
        Self {
            bytes_arr: [[Default::default(); 32]; BA],
            digests: [Default::default(); D],
        }
    }
}

/// Return an empty peer map
pub fn get_peer_map() -> HashMap<SocketAddr, PeerInfo> {
    HashMap::new()
}

pub fn get_dummy_socket_address(count: u8) -> SocketAddr {
    std::net::SocketAddr::from_str(&format!("127.0.0.{}:8080", count)).unwrap()
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
        timestamp: SystemTime::now(),
    }
}

pub(crate) fn to_bytes(message: &PeerMessage) -> Result<Bytes> {
    let mut transport = LengthDelimitedCodec::new();
    let mut formatting = SymmetricalBincode::<PeerMessage>::default();
    let mut buf = BytesMut::new();
    transport.encode(Pin::new(&mut formatting).serialize(message)?, &mut buf)?;
    Ok(buf.freeze())
}

pub(crate) fn get_dummy_peer_connection_data_genesis(
    network: Network,
    id: u8,
) -> (HandshakeData, SocketAddr) {
    let handshake = get_dummy_handshake_data_for_genesis(network);
    let socket_address = get_dummy_socket_address(id);

    (handshake, socket_address)
}

/// Get a global state object for unit test purposes. This global state is
/// populated with state from a caller-defined genesis block.
/// All contained peers represent outgoing connections.
pub(crate) async fn mock_genesis_global_state_with_block(
    peer_count: u8,
    wallet: WalletEntropy,
    cli: cli_args::Args,
    genesis_block: Block,
) -> GlobalStateLock {
    let data_dir: DataDirectory = unit_test_data_directory(cli.network).unwrap();
    let archival_state = ArchivalState::new(data_dir.clone(), genesis_block.clone()).await;

    let peer_db = NetworkingState::initialize_peer_databases(&data_dir)
        .await
        .unwrap();
    let mut peer_map: HashMap<SocketAddr, PeerInfo> = get_peer_map();
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
    let chain = BlockchainState::Archival(Box::new(BlockchainArchivalState {
        light_state,
        archival_state,
    }));
    let mempool = Mempool::new(
        cli.max_mempool_size,
        cli.max_mempool_num_tx,
        genesis_block.hash(),
    );

    let configuration = WalletConfiguration::new(&data_dir).absorb_options(&cli);
    let wallet_state = WalletState::try_new(configuration, wallet, &genesis_block)
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
    coinbase_sender_randomness_coll: [Digest; NUM_BLOCKS_MINED],
) -> GlobalStateLock {
    let network = cli_args.network;
    let wallet = WalletEntropy::devnet_wallet();
    let own_key = wallet.nth_generation_spending_key_for_tests(0);
    let mut global_state_lock =
        mock_genesis_global_state(2, wallet.clone(), cli_args.clone()).await;
    let mut previous_block = Block::genesis(network);

    for coinbase_sender_randomness in coinbase_sender_randomness_coll {
        let (next_block, composer_utxos) =
            make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
                network,
                &previous_block,
                vec![],
                vec![],
                None,
                own_key,
                coinbase_sender_randomness,
                (0.5, wallet.guesser_preimage(previous_block.hash())),
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
) -> Result<(
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

    let devnet_wallet = WalletEntropy::devnet_wallet();
    let state = mock_genesis_global_state(peer_count, devnet_wallet, cli).await;
    Ok((
        peer_broadcast_tx,
        from_main_rx,
        to_main_tx,
        to_main_rx,
        state,
        get_dummy_handshake_data_for_genesis(network),
    ))
}

/// Set a new block as tip
pub(crate) async fn add_block_to_archival_state(
    archival_state: &mut ArchivalState,
    new_block: Block,
) -> Result<()> {
    archival_state.write_block_as_tip(&new_block).await?;

    archival_state.update_mutator_set(&new_block).await.unwrap();

    archival_state
        .append_to_archival_block_mmr(&new_block)
        .await;

    Ok(())
}

// Box<Vec<T>> is unnecessary because Vec<T> is already heap-allocated.
// However, Box<...> is used here because Pin<T> does not allow a &mut T,
// So a Box<T> (which also implements DerefMut) allows a pinned, mutable
// pointer.
type ActionList<Item> = Box<Vec<Action<Item>>>;

pin_project! {
#[derive(Debug)]
pub struct Mock<Item> {
    #[pin]
    actions: ActionList<Item>,
}
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
            // a peer closing the connection. Otherwise, we have to close with a
            // `Bye` in all tests.
            Poll::Ready(Some(Err(MockError::UnexpectedRead)))
        }
    }
}

// TODO ditch this by rewriting the underlying `Strategy` with `IntoRange`
proptest::prop_compose! {
    pub fn propcompose_txkernel() (num_inputs in 1usize..=5, num_outputs in 1usize..=6, num_public_announcements in 0usize..5)
    (r in propcompose_txkernel_with_lengths(num_inputs, num_outputs, num_public_announcements)) -> TransactionKernel {
        r
    }
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

pub(crate) fn make_plenty_mock_transaction_supported_by_invalid_single_proofs(
    count: usize,
) -> Vec<Transaction> {
    let mut pw_backeds = make_plenty_mock_transaction_supported_by_primitive_witness(count);
    for pw_backed in &mut pw_backeds {
        pw_backed.proof = TransactionProof::invalid();
    }

    pw_backeds
}

pub(crate) fn make_plenty_mock_transaction_supported_by_primitive_witness(
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

/// A SingleProof-backed transaction with no inputs or outputs
pub(crate) fn invalid_empty_single_proof_transaction() -> Transaction {
    let tx = make_mock_transaction(vec![], vec![]);
    assert!(matches!(tx.proof, TransactionProof::SingleProof(_)));
    tx
}

/// Make a transaction with `Invalid` transaction proof.
pub fn make_mock_transaction(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
) -> Transaction {
    make_mock_transaction_with_mutator_set_hash(inputs, outputs, Digest::default())
}

pub(crate) fn make_mock_transaction_with_mutator_set_hash_and_timestamp(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
    timestamp: Timestamp,
) -> Transaction {
    Transaction {
        kernel: TransactionKernelProxy {
            inputs,
            outputs,
            public_announcements: vec![],
            fee: NativeCurrencyAmount::coins(1),
            timestamp,
            coinbase: None,
            mutator_set_hash,
            merge_bit: false,
        }
        .into_kernel(),
        proof: TransactionProof::invalid(),
    }
}

pub(crate) fn make_mock_transaction_with_mutator_set_hash(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
) -> Transaction {
    let timestamp = Timestamp::now();

    make_mock_transaction_with_mutator_set_hash_and_timestamp(
        inputs,
        outputs,
        mutator_set_hash,
        timestamp,
    )
}

pub(crate) fn dummy_expected_utxo() -> ExpectedUtxo {
    ExpectedUtxo {
        utxo: Utxo::new_native_currency(
            LockScript::anyone_can_spend(),
            NativeCurrencyAmount::zero(),
        ),
        addition_record: AdditionRecord::new(Default::default()),
        sender_randomness: Default::default(),
        receiver_preimage: Default::default(),
        received_from: UtxoNotifier::Myself,
        notification_received: Timestamp::now(),
        mined_in_block: None,
    }
}

// TODO: Change this function into something more meaningful!
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    fee: NativeCurrencyAmount,
    _wallet_state: &WalletState,
    timestamp: Option<Timestamp>,
) -> BoxedStrategy<Transaction> {
    transaction_kernel::tests::propcompose_txkernel_with_usualtxdata(
        inputs,
        outputs,
        fee,
        match timestamp {
            Some(ts) => ts,
            None => Timestamp::now(),
        },
    )
    .prop_map(|kernel| Transaction {
        kernel,
        proof: TransactionProof::invalid(),
    })
    .boxed()
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
    let genesis_block = Block::genesis(network);
    let new_block_height: BlockHeight = BlockHeight::from(100u64);
    let block_header = BlockHeader {
        version: bfe!(0),
        height: new_block_height,
        prev_block_digest: genesis_block.hash().hash(),
        timestamp: tx_kernel.timestamp,
        nonce: Digest::default(),
        guesser_digest: Digest::default(),
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
        guesser_digest: Digest::default(),
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
/// guesser-preimage and guesser fraction.
///
/// Returns (block, composer's expected UTXOs).
#[expect(clippy::too_many_arguments)]
pub(crate) async fn make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
    network: Network,
    previous_block: &Block,
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
    guesser_parameters: (f64, Digest),
) -> (Block, Vec<ExpectedUtxo>) {
    let (guesser_fraction, guesser_preimage) = guesser_parameters;

    // Build coinbase UTXO and associated data
    let block_timestamp = match block_timestamp {
        Some(ts) => ts,
        None => previous_block.kernel.header.timestamp + network.target_block_interval(),
    };

    let composer_parameters = ComposerParameters::new(
        composer_key.to_address().into(),
        coinbase_sender_randomness,
        Some(composer_key.privacy_preimage()),
        guesser_fraction,
        FeeNotificationPolicy::OffChain,
    );

    let cli = cli_args::Args {
        network,
        ..Default::default()
    };

    let (mut transaction, composer_txos) = make_coinbase_transaction_stateless(
        previous_block,
        composer_parameters,
        block_timestamp,
        TritonVmJobQueue::get_instance(),
        cli.proof_job_options_primitive_witness(),
    )
    .await
    .unwrap();

    let kernel_proxy = TransactionKernelProxy::from(transaction.kernel.clone());
    let new_outputs = [kernel_proxy.outputs, outputs].concat();
    let new_inputs = [kernel_proxy.inputs, inputs].concat();

    let new_kernel = TransactionKernelModifier::default()
        .outputs(new_outputs)
        .inputs(new_inputs)
        .modify(transaction.kernel.clone());
    transaction.kernel = new_kernel;

    let mut block = Block::block_template_invalid_proof(
        previous_block,
        transaction,
        block_timestamp,
        network.target_block_interval(),
    );
    block.set_header_guesser_digest(guesser_preimage.hash());

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
    network: Network,
    previous_block: &Block,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
) -> (Block, Vec<ExpectedUtxo>) {
    make_mock_block_with_inputs_and_outputs(
        network,
        previous_block,
        vec![],
        vec![],
        block_timestamp,
        composer_key,
        coinbase_sender_randomness,
    )
    .await
}

/// Build a fake block with a random hash, containing the given inputs and
/// outputs as well as two outputs for the composer.
///
/// Returns (block, composer-utxos).
pub(crate) async fn make_mock_block_with_inputs_and_outputs(
    network: Network,
    previous_block: &Block,
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    block_timestamp: Option<Timestamp>,
    composer_key: generation_address::GenerationSpendingKey,
    coinbase_sender_randomness: Digest,
) -> (Block, Vec<ExpectedUtxo>) {
    make_mock_block_with_puts_and_guesser_preimage_and_guesser_fraction(
        network,
        previous_block,
        inputs,
        outputs,
        block_timestamp,
        composer_key,
        coinbase_sender_randomness,
        (0f64, Digest::default()),
    )
    .await
}

pub(crate) async fn mock_genesis_wallet_state(
    wallet_entropy: WalletEntropy,
    cli_args: &cli_args::Args,
) -> WalletState {
    let data_dir = unit_test_data_directory(cli_args.network).unwrap();
    WalletState::new_from_wallet_entropy(&data_dir, wallet_entropy, cli_args).await
}

/// Return an archival state populated with the genesis block
pub(crate) async fn mock_genesis_archival_state(
    network: Network,
) -> (ArchivalState, PeerDatabases, DataDirectory) {
    let data_dir: DataDirectory = unit_test_data_directory(network).unwrap();

    let genesis = Block::genesis(network);
    let archival_state = ArchivalState::new(data_dir.clone(), genesis).await;
    let peer_db = NetworkingState::initialize_peer_databases(&data_dir)
        .await
        .unwrap();

    (archival_state, peer_db, data_dir)
}

/// Create and store the next block including any transactions presently in the
/// mempool.  The coinbase and guesser fee will go to our own wallet.
///
/// the stored block does NOT have valid proof-of-work, nor does it have a valid
/// block proof.
pub(crate) async fn mine_block_to_wallet_invalid_block_proof(
    global_state_lock: &mut GlobalStateLock,
    timestamp: Option<Timestamp>,
) -> Result<Block> {
    let tip_block = global_state_lock
        .lock_guard()
        .await
        .chain
        .light_state()
        .to_owned();

    let timestamp =
        timestamp.unwrap_or_else(|| tip_block.header().timestamp + Timestamp::minutes(10));

    let (transaction, expected_composer_utxos) = crate::mine_loop::create_block_transaction(
        &tip_block,
        global_state_lock,
        timestamp,
        Default::default(),
    )
    .await?;

    let guesser_preimage = global_state_lock
        .lock_guard()
        .await
        .wallet_state
        .wallet_entropy
        .guesser_preimage(tip_block.hash());
    let mut block = Block::block_template_invalid_proof(
        &tip_block,
        transaction,
        timestamp,
        global_state_lock.cli().network.target_block_interval(),
    );
    block.set_header_guesser_digest(guesser_preimage.hash());

    global_state_lock
        .set_new_self_composed_tip(block.clone(), expected_composer_utxos)
        .await?;

    Ok(block)
}

pub(crate) fn invalid_empty_block(network: Network, predecessor: &Block) -> Block {
    let tx = make_mock_transaction_with_mutator_set_hash(
        vec![],
        vec![],
        predecessor.mutator_set_accumulator_after().hash(),
    );
    let timestamp = predecessor.header().timestamp + Timestamp::hours(1);
    Block::block_template_invalid_proof(predecessor, tx, timestamp, network.target_block_interval())
}

/// Return a list of `n` invalid, empty blocks.
pub(crate) fn invalid_empty_blocks(network: Network, ancestor: &Block, n: usize) -> Vec<Block> {
    let mut blocks = vec![];
    let mut predecessor = ancestor;
    for _ in 0..n {
        blocks.push(invalid_empty_block(network, predecessor));
        predecessor = blocks.last().unwrap();
    }

    blocks
}

pub(crate) fn invalid_empty_block_with_timestamp(
    network: Network,
    predecessor: &Block,
    timestamp: Timestamp,
) -> Block {
    let tx = make_mock_transaction_with_mutator_set_hash_and_timestamp(
        vec![],
        vec![],
        predecessor.mutator_set_accumulator_after().hash(),
        timestamp,
    );
    Block::block_template_invalid_proof(predecessor, tx, timestamp, network.target_block_interval())
}

/// Create a fake block proposal; will pass `is_valid` but fail pow-check. Will
/// be a valid block except for proof and PoW.
pub(crate) async fn fake_valid_block_proposal_from_tx(
    network: Network,
    predecessor: &Block,
    tx: Transaction,
) -> Block {
    let timestamp = tx.kernel.timestamp;

    let primitive_witness = BlockPrimitiveWitness::new(predecessor.to_owned(), tx);

    let body = primitive_witness.body().to_owned();
    let header = primitive_witness.header(timestamp, network.target_block_interval());
    let (appendix, proof) = {
        let block_proof_witness = BlockProofWitness::produce(primitive_witness);
        let appendix = block_proof_witness.appendix();
        let claim = BlockProgram::claim(&body, &appendix);
        cache_true_claim(claim.clone()).await;
        (appendix, BlockProof::SingleProof(Proof::invalid()))
    };

    Block::new(header, body, appendix, proof)
}

/// Create a block from a transaction without the hassle of proving but such
/// that it appears valid.
pub(crate) async fn fake_valid_block_from_tx_for_tests(
    network: Network,
    predecessor: &Block,
    tx: Transaction,
    seed: [u8; 32],
) -> Block {
    let mut block = fake_valid_block_proposal_from_tx(network, predecessor, tx).await;

    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(seed);
    while !block.has_proof_of_work(network, predecessor.header()) {
        mine_iteration_for_tests(&mut block, &mut rng);
    }

    block
}

/// Create a `Transaction` from `TransactionDetails` such that verification
/// seems to pass but without the hassle of producing a proof for it. Behind the
/// scenes, this method updates the true claims cache, such that the call to
/// `triton_vm::verify` will be by-passed.
async fn fake_create_transaction_from_details_for_tests(
    transaction_details: TransactionDetails,
) -> Transaction {
    let kernel = PrimitiveWitness::from_transaction_details(&transaction_details).kernel;

    let claim = SingleProof::claim(kernel.mast_hash());
    cache_true_claim(claim.clone()).await;

    Transaction {
        kernel,
        proof: TransactionProof::SingleProof(Proof::invalid()),
    }
}

/// Merge two transactions for tests, without the hassle of proving but such
/// that the result seems valid.
async fn fake_merge_transactions_for_tests(
    lhs: Transaction,
    rhs: Transaction,
    shuffle_seed: [u8; 32],
) -> Result<Transaction> {
    let TransactionProof::SingleProof(lhs_proof) = lhs.proof else {
        bail!("arguments must be bogus singleproof transactions")
    };
    let TransactionProof::SingleProof(rhs_proof) = rhs.proof else {
        bail!("arguments must be bogus singleproof transactions")
    };
    let merge_witness =
        MergeWitness::from_transactions(lhs.kernel, lhs_proof, rhs.kernel, rhs_proof, shuffle_seed);
    let new_kernel = merge_witness.new_kernel.clone();

    let claim = SingleProof::claim(new_kernel.mast_hash());
    cache_true_claim(claim).await;

    Ok(Transaction {
        kernel: new_kernel,
        proof: TransactionProof::SingleProof(Proof::invalid()),
    })
}

/// Create a block-transaction with a bogus proof but such that `verify` passes.
pub(crate) async fn fake_create_block_transaction_for_tests(
    predecessor_block: &Block,
    composer_parameters: ComposerParameters,
    timestamp: Timestamp,
    shuffle_seed: [u8; 32],
    mut selected_mempool_txs: Vec<Transaction>,
    network: Network,
) -> Result<(Transaction, TxOutputList)> {
    let (composer_txos, transaction_details) = prepare_coinbase_transaction_stateless(
        predecessor_block,
        composer_parameters,
        timestamp,
        network,
    );

    let coinbase_transaction =
        fake_create_transaction_from_details_for_tests(transaction_details).await;

    let mut block_transaction = coinbase_transaction;
    if selected_mempool_txs.is_empty() {
        // create the nop-tx and merge into the coinbase transaction to set the
        // merge bit to allow the tx to be included in a block.
        let nop_details = TransactionDetails::nop(
            predecessor_block.mutator_set_accumulator_after(),
            timestamp,
            network,
        );
        let nop_transaction = fake_create_transaction_from_details_for_tests(nop_details).await;

        selected_mempool_txs = vec![nop_transaction];
    }

    for tx_to_include in selected_mempool_txs {
        block_transaction =
            fake_merge_transactions_for_tests(block_transaction, tx_to_include, shuffle_seed)
                .await
                .expect("Must be able to merge transactions in mining context");
    }

    Ok((block_transaction, composer_txos))
}

async fn fake_block_successor(
    predecessor: &Block,
    timestamp: Timestamp,
    with_valid_pow: bool,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    fake_block_successor_with_merged_tx(
        predecessor,
        timestamp,
        with_valid_pow,
        vec![],
        rness,
        network,
    )
    .await
}

pub async fn fake_block_successor_with_merged_tx(
    predecessor: &Block,
    timestamp: Timestamp,
    with_valid_pow: bool,
    txs: Vec<Transaction>,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    let (mut seed_bytes, mut seed_digests) = (rness.bytes_arr.to_vec(), rness.digests.to_vec());
    let composer_parameters = ComposerParameters::new(
        GenerationReceivingAddress::derive_from_seed(seed_digests.pop().unwrap()).into(),
        seed_digests.pop().unwrap(),
        None,
        0.5f64,
        FeeNotificationPolicy::OffChain,
    );
    let (block_tx, _) = fake_create_block_transaction_for_tests(
        predecessor,
        composer_parameters,
        timestamp,
        seed_bytes.pop().unwrap(),
        txs,
        network,
    )
    .await
    .unwrap();

    if with_valid_pow {
        fake_valid_block_from_tx_for_tests(
            network,
            predecessor,
            block_tx,
            seed_bytes.pop().unwrap(),
        )
        .await
    } else {
        fake_valid_block_proposal_from_tx(network, predecessor, block_tx).await
    }
}

pub(crate) async fn fake_valid_block_proposal_successor_for_test(
    predecessor: &Block,
    timestamp: Timestamp,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    fake_block_successor(predecessor, timestamp, false, rness, network).await
}

pub(crate) async fn fake_valid_successor_for_tests(
    predecessor: &Block,
    timestamp: Timestamp,
    rness: Randomness<2, 2>,
    network: Network,
) -> Block {
    fake_block_successor(predecessor, timestamp, true, rness, network).await
}

/// Create a block with coinbase going to self. For testing purposes.
///
/// The block will be valid both in terms of PoW and and will pass the
/// Block::is_valid() function. However, the associated (claim, proof) pair will
/// will not pass `triton_vm::verify`, as its validity is only mocked.
pub(crate) async fn fake_valid_block_for_tests(
    state_lock: &GlobalStateLock,
    rness: Randomness<2, 2>,
) -> Block {
    let current_tip = state_lock.lock_guard().await.chain.light_state().clone();
    fake_valid_successor_for_tests(
        &current_tip,
        current_tip.header().timestamp + Timestamp::hours(1),
        rness,
        state_lock.cli().network,
    )
    .await
}

/// Create a deterministic sequence of valid blocks.
///
/// Sequence is N-long. Every block i with i > 0 has block i-1 as its
/// predecessor; block 0 has the `predecessor` argument as predecessor. Every
/// block is valid in terms of both `is_valid` and `has_proof_of_work`. But
/// the STARK proofs are mocked.
pub(crate) async fn fake_valid_sequence_of_blocks_for_tests<const N: usize>(
    predecessor: &Block,
    block_interval: Timestamp,
    rness: [Randomness<2, 2>; N],
    network: Network,
) -> [Block; N] {
    fake_valid_sequence_of_blocks_for_tests_dyn(
        predecessor,
        block_interval,
        rness.to_vec(),
        network,
    )
    .await
    .try_into()
    .unwrap()
}

/// Create a deterministic sequence of valid blocks.
///
/// Sequence is N-long. Every block i with i > 0 has block i-1 as its
/// predecessor; block 0 has the `predecessor` argument as predecessor. Every
/// block is valid in terms of both `is_valid` and `has_proof_of_work`. But
/// the STARK proofs are mocked.
pub(crate) async fn fake_valid_sequence_of_blocks_for_tests_dyn(
    mut predecessor: &Block,
    block_interval: Timestamp,
    mut rness_vec: Vec<Randomness<2, 2>>,
    network: Network,
) -> Vec<Block> {
    let mut blocks = vec![];
    while let Some(rness) = rness_vec.pop() {
        let block = fake_valid_successor_for_tests(
            predecessor,
            predecessor.header().timestamp + block_interval,
            rness,
            network,
        )
        .await;
        blocks.push(block);
        predecessor = blocks.last().unwrap();
    }
    blocks
}

pub(crate) async fn wallet_state_has_all_valid_mps(
    wallet_state: &WalletState,
    tip_block: &Block,
) -> bool {
    let monitored_utxos = wallet_state.wallet_db.monitored_utxos();
    for monitored_utxo in &monitored_utxos.get_all().await {
        let current_mp = monitored_utxo.get_membership_proof_for_block(tip_block.hash());

        match current_mp {
            Some(mp) => {
                if !tip_block
                    .mutator_set_accumulator_after()
                    .verify(Tip5::hash(&monitored_utxo.utxo), &mp)
                {
                    warn!("Invalid MSMP");
                    return false;
                }
            }
            None => {
                warn!("No MSMP");
                return false;
            }
        }
    }

    true
}

/// Waits for an async predicate to return true or a timeout.
///
/// # Arguments
///
/// * `predicate`: `async || -> bool` closure to evaluate.
/// * `timeout_secs`: Max seconds to wait (floating-point).
///
/// # Returns
///
/// `Ok(())` on success, `Err(_)` on timeout.
///
/// # Example
///
/// ```
/// async fn is_ready() -> bool { true }
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     wait_until(async || is_ready().await, 1.5).await?;
///     Ok(())
/// }
/// ```
pub async fn wait_until<F, Fut>(
    timeout: std::time::Duration,
    mut predicate: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = bool> + Send + 'static,
{
    let start = std::time::Instant::now();
    loop {
        if predicate().await {
            break;
        }
        if start.elapsed() > timeout {
            anyhow::bail!(
                "timeout reached after {} seconds",
                start.elapsed().as_secs_f32()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(())
}
