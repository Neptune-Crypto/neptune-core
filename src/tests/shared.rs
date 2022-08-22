use anyhow::Result;
use bytes::{Bytes, BytesMut};
use clap::Parser;
use futures::sink;
use futures::stream;
use futures::task::{Context, Poll};
use mutator_set_tf::util_types::mutator_set::addition_record::AdditionRecord;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use num_traits::One;
use num_traits::Zero;
use pin_project_lite::pin_project;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use secp256k1::Secp256k1;
use std::path::PathBuf;
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc};
use tokio_serde::{formats::SymmetricalBincode, Serializer};
use tokio_util::codec::{Encoder, LengthDelimitedCodec};
use twenty_first::shared_math::traits::GetRandomElements;
use twenty_first::{amount::u32s::U32s, shared_math::b_field_element::BFieldElement};

use crate::database::leveldb::LevelDB;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::digest::Hashable;
use crate::models::database::BlockIndexKey;
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::blockchain_state::BlockchainState;
use crate::models::state::light_state::LightState;
use crate::models::state::networking_state::NetworkingState;
use crate::models::state::State;
use crate::{
    config_models::{cli_args, network::Network},
    initialize_databases,
    models::{
        blockchain::{
            block::{
                block_header::{BlockHeader, TARGET_DIFFICULTY_U32_SIZE},
                block_height::BlockHeight,
                Block,
            },
            digest::{Digest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
            shared::Hash,
            transaction::{utxo::Utxo, Transaction},
        },
        channel::{MainToPeerThread, PeerThreadToMain},
        database::{BlockDatabases, PeerDatabases},
        peer::{HandshakeData, PeerInfo, PeerMessage, PeerStanding},
        shared::LatestBlockInfo,
    },
    PEER_CHANNEL_CAPACITY,
};

pub fn get_peer_map() -> Arc<std::sync::Mutex<HashMap<SocketAddr, PeerInfo>>> {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

// Return empty database objects, and root directory for this unit test instantiation's
/// data directory.
#[allow(clippy::type_complexity)]
pub fn databases(
    network: Network,
) -> Result<(
    Arc<tokio::sync::Mutex<BlockDatabases>>,
    Arc<tokio::sync::Mutex<PeerDatabases>>,
    PathBuf,
)> {
    // Create databases for unit tests on disk, and return objects for them.
    // For now, we use databases on disk, but it would be nicer to use
    // something that is in-memory only.
    let mut root_data_dir: PathBuf = get_data_director_for_unit_tests()?;

    // Create a randomly named directory to allow the tests to run in parallel.
    // If this is not done, the parallel execution of unit tests will fail as
    // they each hold a lock on the database.
    let random_directory: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    root_data_dir.push(random_directory);

    root_data_dir.push(network.to_string());
    let mut database_dir = root_data_dir.clone();
    database_dir.push("databases");

    // The `initialize_databases` function call should create a new directory for the databases
    // meaning that all directories above this are also created.
    let (block_dbs, peer_dbs) = initialize_databases(&database_dir)?;

    Ok((
        Arc::new(tokio::sync::Mutex::new(block_dbs)),
        Arc::new(tokio::sync::Mutex::new(peer_dbs)),
        root_data_dir,
    ))
}

pub fn get_dummy_address() -> SocketAddr {
    std::net::SocketAddr::from_str("127.0.0.1:8080").unwrap()
}

pub fn get_dummy_peer(address: SocketAddr) -> PeerInfo {
    PeerInfo {
        connected_address: address,
        inbound: false,
        instance_id: rand::random(),
        last_seen: SystemTime::now(),
        standing: PeerStanding::default(),
        version: get_dummy_version(),
        address_for_incoming_connections: Some(address),
    }
}

pub fn get_dummy_version() -> String {
    "0.1.0".to_string()
}

pub fn get_dummy_latest_block(
    input_block: Option<Block>,
) -> (Block, LatestBlockInfo, Arc<std::sync::Mutex<BlockHeader>>) {
    let block = match input_block {
        None => Block::genesis_block(),
        Some(block) => block,
    };

    let latest_block_info: LatestBlockInfo = block.clone().into();
    let block_header = block.header.clone();
    (
        block,
        latest_block_info,
        Arc::new(std::sync::Mutex::new(block_header)),
    )
}

/// Return a handshake object with a randomly set instance ID
pub fn get_dummy_handshake_data(network: Network) -> HandshakeData {
    HandshakeData {
        instance_id: rand::random(),
        tip_header: get_dummy_latest_block(None).2.lock().unwrap().to_owned(),
        listen_address: Some(get_dummy_address()),
        network,
        version: get_dummy_version(),
    }
}

pub fn to_bytes(message: &PeerMessage) -> Result<Bytes> {
    let mut transport = LengthDelimitedCodec::new();
    let mut formating = SymmetricalBincode::<PeerMessage>::default();
    let mut buf = BytesMut::new();
    transport.encode(Pin::new(&mut formating).serialize(message)?, &mut buf)?;
    Ok(buf.freeze())
}

/// Return a setup with empty databases, and with the genesis block in the
/// block header field of the state.
/// Returns:
/// (peer_broadcast_channel, from_main_receiver, to_main_transmitter, to_main_receiver, state, peer_map)
#[allow(clippy::type_complexity)]
pub fn get_genesis_setup(
    network: Network,
    peer_count: u8,
) -> Result<(
    broadcast::Sender<MainToPeerThread>,
    broadcast::Receiver<MainToPeerThread>,
    mpsc::Sender<PeerThreadToMain>,
    mpsc::Receiver<PeerThreadToMain>,
    State,
    HandshakeData,
)> {
    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let peer_map: Arc<std::sync::Mutex<HashMap<SocketAddr, PeerInfo>>> = get_peer_map();
    for i in 0..peer_count {
        let peer_address =
            std::net::SocketAddr::from_str(&format!("123.123.123.{}:8080", i)).unwrap();
        peer_map
            .lock()
            .unwrap()
            .insert(peer_address, get_dummy_peer(peer_address));
    }

    let (block, _, _) = get_dummy_latest_block(None);
    let (block_databases, peer_databases, root_data_dir_path) = databases(network)?;
    let cli_default_args = cli_args::Args::from_iter::<Vec<String>, _>(vec![]);
    let syncing = Arc::new(std::sync::RwLock::new(false));
    let networking_state = NetworkingState::new(peer_map, peer_databases, syncing);
    let light_state: LightState = LightState::new(block.header);
    let blockchain_state = BlockchainState {
        light_state,
        archival_state: Some(ArchivalState::new(block_databases, root_data_dir_path)),
    };
    let state = State {
        chain: blockchain_state,
        cli: cli_default_args,
        net: networking_state,
    };
    Ok((
        peer_broadcast_tx,
        from_main_rx_clone,
        to_main_tx,
        _to_main_rx1,
        state,
        get_dummy_handshake_data(network),
    ))
}

pub async fn add_block_to_archival_state(
    archival_state: &ArchivalState,
    new_block: Block,
) -> Result<()> {
    let mut db_lock = archival_state.block_databases.lock().await;
    let tip_digest: Option<Digest> = db_lock
        .block_index
        .get(BlockIndexKey::BlockTipDigest)
        .map(|x| x.as_tip_digest());
    let tip_header: Option<BlockHeader> = tip_digest.map(|digest| {
        db_lock
            .block_index
            .get(BlockIndexKey::Block(digest))
            .unwrap()
            .as_block_record()
            .block_header
    });
    archival_state.write_block(
        Box::new(new_block),
        &mut db_lock,
        tip_header.map(|x| x.proof_of_work_family),
    )?;

    Ok(())
}

fn get_data_director_for_unit_tests() -> Result<PathBuf> {
    let mut dir: PathBuf = env::temp_dir();
    dir.push("neptune-unit-tests");

    Ok(dir)
}

/// Helper function for tests to update state with a new block
pub async fn add_block(state: &State, new_block: Block) -> Result<()> {
    let mut db_lock = state
        .chain
        .archival_state
        .as_ref()
        .unwrap()
        .block_databases
        .lock()
        .await;
    let mut light_state_locked: std::sync::MutexGuard<BlockHeader> =
        state.chain.light_state.latest_block_header.lock().unwrap();

    let previous_pow_family = light_state_locked.proof_of_work_family;
    state.chain.archival_state.as_ref().unwrap().write_block(
        Box::new(new_block.clone()),
        &mut db_lock,
        Some(previous_pow_family),
    )?;
    if previous_pow_family < new_block.header.proof_of_work_family {
        *light_state_locked = new_block.header;
    }

    Ok(())
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

/// Return a fake block with a random hash
pub fn make_mock_block(
    previous_block: &Block,
    target_difficulty: Option<U32s<TARGET_DIFFICULTY_U32_SIZE>>,
) -> Block {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
        secp.generate_keypair(&mut rng);

    let new_block_height: BlockHeight = previous_block.header.height.next();
    let coinbase_utxo = Utxo {
        amount: Block::get_mining_reward(new_block_height),
        public_key,
    };
    let output_randomness =
        BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut thread_rng());
    let timestamp: BFieldElement = BFieldElement::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Got bad time timestamp in mining process")
            .as_secs(),
    );
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![(coinbase_utxo.clone(), output_randomness.clone().into())],
        public_scripts: vec![],
        fee: U32s::zero(),
        timestamp,
    };
    let mut new_ms = previous_block.body.next_mutator_set_accumulator.clone();
    let previous_ms = new_ms.clone();
    let coinbase_digest: Digest = coinbase_utxo.hash();

    let mut coinbase_addition_record: AdditionRecord<Hash> =
        new_ms.commit(&coinbase_digest.into(), &output_randomness);
    let mutator_set_update: MutatorSetUpdate = MutatorSetUpdate {
        removals: vec![],
        additions: vec![coinbase_addition_record.clone()],
    };
    new_ms.add(&mut coinbase_addition_record);

    let block_body: BlockBody = BlockBody {
        transactions: vec![tx],
        next_mutator_set_accumulator: new_ms.clone(),
        mutator_set_update,

        // TODO: Consider to use something else than an empty MS here
        previous_mutator_set_accumulator: previous_ms,
        stark_proof: vec![],
    };

    let block_target_difficulty = previous_block.header.target_difficulty;
    let pow_line = previous_block.header.proof_of_work_line + block_target_difficulty;
    let pow_family = pow_line;
    let zero = BFieldElement::ring_zero();
    let block_header = BlockHeader {
        version: zero,
        height: new_block_height,
        mutator_set_commitment: new_ms.get_commitment().into(),
        prev_block_digest: previous_block.hash,
        timestamp,
        nonce: [zero, zero, zero],
        max_block_size: 1_000_000,
        proof_of_work_line: pow_family,
        proof_of_work_family: pow_family,
        target_difficulty: match target_difficulty {
            Some(td) => td,
            None => U32s::one(),
        },
        block_body_merkle_root: block_body.hash(),
        uncles: vec![],
    };

    Block::new(block_header, block_body)
}
