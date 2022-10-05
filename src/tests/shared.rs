use anyhow::Result;
use bytes::{Bytes, BytesMut};
use clap::Parser;
use futures::sink;
use futures::stream;
use futures::task::{Context, Poll};
use mutator_set_tf::util_types::mutator_set::addition_record::AdditionRecord;
use mutator_set_tf::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet;
use mutator_set_tf::util_types::mutator_set::chunk_dictionary::ChunkDictionary;
use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use mutator_set_tf::util_types::mutator_set::removal_record::RemovalRecord;
use num_traits::One;
use num_traits::Zero;
use pin_project_lite::pin_project;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rusty_leveldb;
use secp256k1::ecdsa;
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
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::{broadcast, mpsc};
use tokio_serde::{formats::SymmetricalBincode, Serializer};
use tokio_util::codec::{Encoder, LengthDelimitedCodec};
use twenty_first::shared_math::traits::GetRandomElements;
use twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use twenty_first::{amount::u32s::U32s, shared_math::b_field_element::BFieldElement};

use crate::database::leveldb::LevelDB;
use crate::database::rusty::RustyLevelDB;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::digest::Hashable;
use crate::models::blockchain::transaction::devnet_input::DevNetInput;
use crate::models::blockchain::transaction::Amount;
use crate::models::database::BlockIndexKey;
use crate::models::database::WalletDbKey;
use crate::models::database::WalletDbValue;
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::blockchain_state::BlockchainState;
use crate::models::state::light_state::LightState;
use crate::models::state::mempool::Mempool;
use crate::models::state::networking_state::NetworkingState;
use crate::models::state::wallet;
use crate::models::state::wallet::Wallet;
use crate::models::state::wallet::WalletState;
use crate::models::state::GlobalState;
use crate::Hash;
use crate::{
    config_models::{cli_args, network::Network},
    models::{
        blockchain::{
            block::{
                block_header::{BlockHeader, TARGET_DIFFICULTY_U32_SIZE},
                block_height::BlockHeight,
                Block,
            },
            digest::{Digest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
            transaction::{utxo::Utxo, Transaction},
        },
        channel::{MainToPeerThread, PeerThreadToMain},
        database::{BlockDatabases, PeerDatabases},
        peer::{HandshakeData, PeerInfo, PeerMessage, PeerStanding},
        shared::LatestBlockInfo,
    },
    PEER_CHANNEL_CAPACITY,
};

/// Return an empty peer map
pub fn get_peer_map() -> Arc<std::sync::Mutex<HashMap<SocketAddr, PeerInfo>>> {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

// Return empty database objects, and root directory for this unit test instantiation's
/// data directory.
#[allow(clippy::type_complexity)]
pub fn unit_test_databases(
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
    let block_dbs = ArchivalState::initialize_block_databases(&database_dir)?;
    let peer_dbs = NetworkingState::initialize_peer_databases(&database_dir)?;

    Ok((
        Arc::new(tokio::sync::Mutex::new(block_dbs)),
        Arc::new(tokio::sync::Mutex::new(peer_dbs)),
        root_data_dir,
    ))
}

pub fn get_dummy_address(count: u8) -> SocketAddr {
    std::net::SocketAddr::from_str(&format!("127.0.0.{}:8080", count)).unwrap()
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
pub fn get_dummy_handshake_data(network: Network, id: u8) -> HandshakeData {
    HandshakeData {
        instance_id: rand::random(),
        tip_header: get_dummy_latest_block(None).2.lock().unwrap().to_owned(),
        listen_address: Some(get_dummy_address(id)),
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

pub fn get_dummy_peer_connection_data(network: Network, id: u8) -> (HandshakeData, SocketAddr) {
    let handshake = get_dummy_handshake_data(network, id);
    let socket_address = get_dummy_address(id);

    (handshake, socket_address)
}

/// Return a setup with empty databases, and with the genesis block in the
/// block header field of the state.
/// Returns:
/// (peer_broadcast_channel, from_main_receiver, to_main_transmitter, to_main_receiver, global state, peer's handshake data)
#[allow(clippy::type_complexity)]
pub async fn get_test_genesis_setup(
    network: Network,
    peer_count: u8,
) -> Result<(
    broadcast::Sender<MainToPeerThread>,
    broadcast::Receiver<MainToPeerThread>,
    mpsc::Sender<PeerThreadToMain>,
    mpsc::Receiver<PeerThreadToMain>,
    GlobalState,
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
    let (block_databases, peer_databases, root_data_dir_path) = unit_test_databases(network)?;
    let (ams, ms_block_sync) = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
    let ams = Arc::new(tokio::sync::Mutex::new(ams));
    let ms_block_sync = Arc::new(tokio::sync::Mutex::new(ms_block_sync));
    let archival_state =
        ArchivalState::new(block_databases, ams, root_data_dir_path, ms_block_sync).await;
    let cli_default_args = cli_args::Args::from_iter::<Vec<String>, _>(vec![]);
    let syncing = Arc::new(std::sync::RwLock::new(false));
    let networking_state = NetworkingState::new(peer_map, peer_databases, syncing);
    let light_state: LightState = LightState::new(block);
    let blockchain_state = BlockchainState {
        light_state,
        archival_state: Some(archival_state),
    };
    let mempool = Mempool::default();
    let state = GlobalState {
        chain: blockchain_state,
        cli: cli_default_args,
        net: networking_state,
        wallet_state: get_mock_wallet_state(None).await,
        mempool,
    };
    Ok((
        peer_broadcast_tx,
        from_main_rx_clone,
        to_main_tx,
        _to_main_rx1,
        state,
        get_dummy_handshake_data(network, 0),
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

/// Return an appropriate data directory for unit tests
fn get_data_director_for_unit_tests() -> Result<PathBuf> {
    let mut dir: PathBuf = env::temp_dir();
    dir.push("neptune-unit-tests");

    Ok(dir)
}

/// Helper function for tests to update state with a new block
pub async fn add_block(state: &GlobalState, new_block: Block) -> Result<()> {
    let mut db_lock = state
        .chain
        .archival_state
        .as_ref()
        .unwrap()
        .block_databases
        .lock()
        .await;
    let mut light_state_locked: tokio::sync::MutexGuard<Block> =
        state.chain.light_state.latest_block.lock().await;

    let previous_pow_family = light_state_locked.header.proof_of_work_family;
    state.chain.archival_state.as_ref().unwrap().write_block(
        Box::new(new_block.clone()),
        &mut db_lock,
        Some(previous_pow_family),
    )?;
    if previous_pow_family < new_block.header.proof_of_work_family {
        *light_state_locked = new_block;
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

pub fn add_output_to_block(block: &mut Block, utxo: Utxo) {
    let tx = &mut block.body.transaction;
    let output_randomness: Vec<BFieldElement> =
        BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut thread_rng());
    let addition_record: AdditionRecord<Hash> = block
        .body
        .previous_mutator_set_accumulator
        .commit(&utxo.neptune_hash().into(), &output_randomness);
    tx.outputs.push((utxo, output_randomness.into()));

    // Add addition record for this output
    block
        .body
        .mutator_set_update
        .additions
        .push(addition_record);
    let mut next_mutator_set_accumulator = block.body.previous_mutator_set_accumulator.clone();
    block
        .body
        .mutator_set_update
        .apply(&mut next_mutator_set_accumulator)
        .expect("MS update application must work");
    block.body.next_mutator_set_accumulator = next_mutator_set_accumulator;

    // update header fields
    block.header.mutator_set_commitment = block
        .body
        .next_mutator_set_accumulator
        .get_commitment()
        .into();
    block.header.block_body_merkle_root = block.body.neptune_hash();
}

/// Add an unsigned (incorrectly signed) devnet input to a transaction
/// Membership proofs and removal records must be valid against `previous_mutator_set_accumulator`,
/// not against `next_mutator_set_accumulator`.
pub fn add_unsigned_dev_net_input_to_block_transaction(
    block: &mut Block,
    input_utxo: Utxo,
    membership_proof: MsMembershipProof<Hash>,
    removal_record: RemovalRecord<Hash>,
) {
    let mut tx = block.body.transaction.clone();
    let new_devnet_input = DevNetInput {
        utxo: input_utxo,
        membership_proof: membership_proof.into(),
        removal_record: removal_record.clone(),
        // We're just using a dummy signature here to type-check. The caller should apply a correct signature to the transaction
        signature: Some(ecdsa::Signature::from_str("3044022012048b6ac38277642e24e012267cf91c22326c3b447d6b4056698f7c298fb36202201139039bb4090a7cfb63c57ecc60d0ec8b7483bf0461a468743022759dc50124").unwrap()),
    };
    tx.inputs.push(new_devnet_input);
    block.body.transaction = tx;

    // add removal record for this spending
    block.body.mutator_set_update.removals.push(removal_record);

    // Update block mutator set accumulator. We have to apply *all* elements in the `mutator_set_update`
    // to the previous mutator set accumulator here, as the removal records need to be updated throughout
    // this process. This means that the input membership proof and removal records are expected to be
    // valid against `block.body.previous_mutator_set_accumulator`, not against
    // `block.body.next_mutator_set_accumulator`
    let mut next_mutator_set_accumulator = block.body.previous_mutator_set_accumulator.clone();
    block
        .body
        .mutator_set_update
        .apply(&mut next_mutator_set_accumulator)
        .expect("MS update application must work");
    block.body.next_mutator_set_accumulator = next_mutator_set_accumulator;

    // update header fields
    block.header.mutator_set_commitment = block
        .body
        .next_mutator_set_accumulator
        .get_commitment()
        .into();
    block.header.block_body_merkle_root = block.body.neptune_hash();
}

pub fn add_unsigned_input_to_block(
    block: &mut Block,
    consumed_utxo: Utxo,
    membership_proof: MsMembershipProof<Hash>,
) {
    let item = consumed_utxo.neptune_hash();
    let input_removal_record = block
        .body
        .previous_mutator_set_accumulator
        .drop(&item.into(), &membership_proof);
    add_unsigned_dev_net_input_to_block_transaction(
        block,
        consumed_utxo,
        membership_proof,
        input_removal_record,
    );
}

/// Helper function to add an unsigned input to a block's transaction
pub async fn add_unsigned_input_to_block_ams(
    block: &mut Block,
    consumed_utxo: Utxo,
    randomness: Digest,
    ams: &Arc<tokio::sync::Mutex<ArchivalMutatorSet<Hash>>>,
    aocl_leaf_index: u128,
) {
    let item = consumed_utxo.neptune_hash();
    let input_membership_proof = ams
        .lock()
        .await
        .restore_membership_proof(&item.into(), &randomness.into(), aocl_leaf_index)
        .unwrap();

    // Sanity check that restored membership proof agrees with AMS
    assert!(
        ams.lock()
            .await
            .verify(&item.into(), &input_membership_proof),
        "Restored MS membership proof must validate against own AMS"
    );

    // Sanity check that restored membership proof agree with block
    assert!(
        block
            .body
            .previous_mutator_set_accumulator
            .verify(&item.into(), &input_membership_proof),
        "Restored MS membership proof must validate against input block"
    );

    let input_removal_record = ams
        .lock()
        .await
        .set_commitment
        .drop(&item.into(), &input_membership_proof);
    add_unsigned_dev_net_input_to_block_transaction(
        block,
        consumed_utxo,
        input_membership_proof,
        input_removal_record,
    );
}

pub fn new_random_wallet() -> Wallet {
    Wallet::new(wallet::generate_secret_key())
}

/// Create a mock `DevNetInput`
///
/// This mock currently contains a lot of things that don't pass block validation.
pub fn make_mock_unsigned_devnet_input(amount: Amount, wallet: &Wallet) -> DevNetInput {
    let mock_mmr_membership_proof = MmrMembershipProof {
        data_index: 0,
        authentication_path: vec![],
    };
    let mock_ms_membership_proof = MsMembershipProof {
        randomness: Digest::default().into(),
        auth_path_aocl: mock_mmr_membership_proof,
        target_chunks: ChunkDictionary::default(),
        cached_bits: None,
    };
    let mut mock_ms_acc = MutatorSetAccumulator::default();
    let mock_removal_record =
        mock_ms_acc.drop(&Digest::default().into(), &mock_ms_membership_proof);

    let utxo = Utxo {
        amount,
        public_key: wallet.get_public_key(),
    };

    DevNetInput {
        utxo,
        membership_proof: mock_ms_membership_proof.into(),
        removal_record: mock_removal_record,
        // We're just using a dummy signature here to type-check. The caller should apply a correct signature to the transaction
        signature: Some(ecdsa::Signature::from_str("3044022012048b6ac38277642e24e012267cf91c22326c3b447d6b4056698f7c298fb36202201139039bb4090a7cfb63c57ecc60d0ec8b7483bf0461a468743022759dc50124").unwrap()),
    }
}

pub fn make_mock_signed_valid_tx() -> Transaction {
    // Build a transaction
    let mut rng = thread_rng();
    let wallet_1 = new_random_wallet();
    let output_amount_1: Amount = 42.into();
    let output_1 = Utxo {
        amount: output_amount_1,
        public_key: wallet_1.get_public_key(),
    };
    let randomness: Digest =
        BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut rng).into();

    let input_1 = make_mock_unsigned_devnet_input(42.into(), &wallet_1);
    let mut transaction_1 = make_mock_transaction(vec![input_1], vec![(output_1, randomness)]);
    transaction_1.sign(&wallet_1);

    transaction_1
}

// `make_mock_transaction`, in contrast to `make_mock_transaction2`, assumes you
// already have created `DevNetInput`s.
pub fn make_mock_transaction(
    inputs: Vec<DevNetInput>,
    outputs: Vec<(Utxo, Digest)>,
) -> Transaction {
    let timestamp: BFieldElement = BFieldElement::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Got bad time timestamp in mining process")
            .as_secs(),
    );

    Transaction {
        inputs,
        outputs,
        public_scripts: vec![],
        fee: U32s::zero(),
        timestamp,
        authority_proof: None,
    }
}

// `make_mock_transaction2`, in contrast to `make_mock_transaction`, allows you
// to choose signing wallet, fee, and timestamp.
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<Utxo>,
    outputs: Vec<Utxo>,
    fee: Amount,
    wallet_state: &WalletState,
    timestamp: Option<BFieldElement>,
) -> Transaction {
    let input_utxos_with_signature = inputs
        .iter()
        .map(|in_utxo| make_mock_unsigned_devnet_input(in_utxo.amount, &wallet_state.wallet))
        .collect::<Vec<_>>();

    // TODO: This is probably the wrong digest.  Other code uses: output_randomness.clone().into()
    let output_utxos_with_digest = outputs
        .into_iter()
        .map(|out_utxo| (out_utxo, <Utxo as Hashable>::neptune_hash(&out_utxo)))
        .collect::<Vec<_>>();

    let timestamp = timestamp.unwrap_or_else(|| {
        BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Timestamping failed")
                .as_secs(),
        )
    });

    Transaction {
        inputs: input_utxos_with_signature,
        outputs: output_utxos_with_digest,
        public_scripts: vec![],
        fee,
        timestamp,
        authority_proof: None,
    }
}

/// Return a fake block with a random hash, containing *one* output UTXO in the form
/// of a coinbase output.
pub fn make_mock_block(
    previous_block: &Block,
    target_difficulty: Option<U32s<TARGET_DIFFICULTY_U32_SIZE>>,
    coinbase_beneficiary: secp256k1::PublicKey,
) -> Block {
    let new_block_height: BlockHeight = previous_block.header.height.next();
    let coinbase_utxo = Utxo {
        amount: Block::get_mining_reward(new_block_height),
        public_key: coinbase_beneficiary,
    };
    let output_randomness =
        BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut thread_rng());
    let transaction = make_mock_transaction(
        vec![],
        vec![(coinbase_utxo, output_randomness.clone().into())],
    );
    let mut new_ms = previous_block.body.next_mutator_set_accumulator.clone();
    let previous_ms = new_ms.clone();
    let coinbase_digest: Digest = coinbase_utxo.neptune_hash();

    let mut coinbase_addition_record: AdditionRecord<Hash> =
        new_ms.commit(&coinbase_digest.into(), &output_randomness);
    let mutator_set_update: MutatorSetUpdate = MutatorSetUpdate {
        removals: vec![],
        additions: vec![coinbase_addition_record.clone()],
    };
    new_ms.add(&mut coinbase_addition_record);

    let block_body: BlockBody = BlockBody {
        transaction,
        next_mutator_set_accumulator: new_ms.clone(),
        mutator_set_update,

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
        timestamp: block_body.transaction.timestamp,
        nonce: [zero, zero, zero],
        max_block_size: 1_000_000,
        proof_of_work_line: pow_family,
        proof_of_work_family: pow_family,
        target_difficulty: match target_difficulty {
            Some(td) => td,
            None => U32s::one(),
        },
        block_body_merkle_root: block_body.neptune_hash(),
        uncles: vec![],
    };

    Block::new(block_header, block_body)
}

/// Return a dummy-wallet used for testing
pub async fn get_mock_wallet_state(wallet: Option<Wallet>) -> WalletState {
    let wallet = match wallet {
        Some(wallet) => wallet,
        None => Wallet::devnet_authority_wallet(),
    };

    let test_path = get_data_director_for_unit_tests().unwrap();
    let wallet_block_db_name = "mock_wallet_block_db";

    let wallet_db = Arc::new(TokioMutex::new(
        RustyLevelDB::<WalletDbKey, WalletDbValue>::new(
            &test_path,
            wallet_block_db_name,
            rusty_leveldb::in_memory(),
        )
        .unwrap(),
    ));

    let outgoing_utxo_counter_db = Arc::new(TokioMutex::new(
        RustyLevelDB::<(), u128>::new(
            &test_path,
            "outgoing_utxo_counter_db",
            rusty_leveldb::in_memory(),
        )
        .unwrap(),
    ));

    let ret = WalletState {
        outgoing_utxo_counter_db,
        wallet_db: wallet_db.clone(),
        wallet,
    };

    // Wallet state has to be initialized with the genesis block, otherwise the outputs
    // from it would be unspendable.
    let mut wallet_db_lock = wallet_db.lock().await;
    ret.update_wallet_state_with_new_block(&Block::genesis_block(), &mut wallet_db_lock)
        .expect("Applying genesis block in unit test setup must succeed");

    ret
}

pub async fn make_unit_test_archival_state() -> ArchivalState {
    let (block_databases, _, root_data_dir_path) = unit_test_databases(Network::Main).unwrap();
    println!("root_data_dir_path = {:?}", root_data_dir_path);

    let (ams, ms_block_sync) = ArchivalState::initialize_mutator_set(&root_data_dir_path).unwrap();
    let ams = Arc::new(tokio::sync::Mutex::new(ams));
    let ms_block_sync = Arc::new(tokio::sync::Mutex::new(ms_block_sync));

    ArchivalState::new(block_databases, ams, root_data_dir_path, ms_block_sync).await
}
