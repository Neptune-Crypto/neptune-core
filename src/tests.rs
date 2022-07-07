use super::*;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_header::TARGET_DIFFICULTY_U32_SIZE;
use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::digest::Digest;
use crate::models::blockchain::digest::Hashable;
use crate::models::blockchain::digest::RESCUE_PRIME_OUTPUT_SIZE_IN_BFES;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::Transaction;
use crate::models::peer::ConnectionRefusedReason;
use crate::models::shared::LatestBlockInfo;
use bytes::{Bytes, BytesMut};
use futures::sink;
use futures::stream;
use futures::task::{Context, Poll};
use num_traits::One;
use num_traits::Zero;
use pin_project_lite::pin_project;
use rand::thread_rng;
use rand::{distributions::Alphanumeric, Rng};
use secp256k1::rand::rngs::OsRng;
use secp256k1::Secp256k1;
use std::collections::hash_map::RandomState;
use std::env;
use std::pin::Pin;
use std::str::FromStr;
use std::time::UNIX_EPOCH;
use tokio_serde::Serializer;
use tokio_test::io::Builder;
use tokio_util::codec::Encoder;
use tracing_test::traced_test;
use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::traits::GetRandomElements;
use twenty_first::util_types::mutator_set::addition_record::AdditionRecord;
use twenty_first::util_types::mutator_set::mutator_set_trait::MutatorSet;

const UNIT_TEST_DB_DIRECTORY: &str = "neptune_unit_test_databases";

fn get_peer_map() -> Arc<std::sync::Mutex<HashMap<SocketAddr, Peer>>> {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

// Create databases for unit tests on disk, and return objects for them.
// For now, we use databases on disk, but it would be nicer to use
// something that is in-memory only.
fn databases(
    network: Network,
) -> Result<(
    Arc<tokio::sync::Mutex<BlockDatabases>>,
    Arc<tokio::sync::Mutex<PeerDatabases>>,
)> {
    let temp_dir = env::temp_dir();
    let mut path = temp_dir.to_owned();
    path.push(UNIT_TEST_DB_DIRECTORY);
    path.push(network.to_string());

    // Create a randomly named directory to allow the tests to run in parallel.
    // If this is not done, the parallel execution of unit tests will fail as
    // they each hold a lock on the database.
    let random_directory: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    path.push(random_directory);

    let (block_dbs, peer_dbs) = initialize_databases(&path);

    Ok((
        Arc::new(tokio::sync::Mutex::new(block_dbs)),
        Arc::new(tokio::sync::Mutex::new(peer_dbs)),
    ))
}

fn get_dummy_address() -> SocketAddr {
    std::net::SocketAddr::from_str("127.0.0.1:8080").unwrap()
}

fn get_dummy_peer(address: SocketAddr) -> Peer {
    Peer {
        address,
        banscore: 0,
        inbound: false,
        instance_id: rand::random(),
        last_seen: SystemTime::now(),
        version: get_dummy_version(),
    }
}

fn get_dummy_version() -> String {
    "0.1.0".to_string()
}

fn get_dummy_latest_block(
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
fn get_dummy_handshake_data(network: Network) -> HandshakeData {
    HandshakeData {
        instance_id: rand::random(),
        latest_block_info: get_dummy_latest_block(None).1,
        listen_address: Some(get_dummy_address()),
        network,
        version: get_dummy_version(),
    }
}

fn to_bytes(message: &PeerMessage) -> Result<Bytes> {
    let mut transport = LengthDelimitedCodec::new();
    let mut formating = SymmetricalBincode::<PeerMessage>::default();
    let mut buf = BytesMut::new();
    let () = transport.encode(
        Bytes::from(Pin::new(&mut formating).serialize(message)?),
        &mut buf,
    )?;
    Ok(buf.freeze())
}

/// Return a setup with empty databases, and with the genesis block in the
/// block header field of the state.
/// Returns:
/// (peer_broadcast_channel, from_main_receiver, to_main_transmitter, to_main_receiver, state, peer_map)
fn get_genesis_setup(
    network: Network,
    peer_count: u8,
) -> Result<(
    broadcast::Sender<MainToPeerThread>,
    broadcast::Receiver<MainToPeerThread>,
    mpsc::Sender<PeerThreadToMain>,
    mpsc::Receiver<PeerThreadToMain>,
    State,
    Arc<std::sync::Mutex<HashMap<SocketAddr, Peer, RandomState>>>,
)> {
    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let peer_map: Arc<std::sync::Mutex<HashMap<SocketAddr, Peer>>> = get_peer_map();
    for i in 0..peer_count {
        let peer_address =
            std::net::SocketAddr::from_str(&format!("123.123.123.{}:8080", i)).unwrap();
        peer_map
            .lock()
            .unwrap()
            .insert(peer_address, get_dummy_peer(peer_address));
    }

    let (_, _, latest_block_header) = get_dummy_latest_block(None);
    let (block_databases, peer_databases) = databases(network)?;
    let state = State {
        peer_map: peer_map.clone(),
        block_databases,
        latest_block_header,
        syncing: Arc::new(std::sync::RwLock::new(false)),
        peer_databases,
    };
    Ok((
        peer_broadcast_tx,
        from_main_rx_clone,
        to_main_tx,
        _to_main_rx1,
        state,
        peer_map,
    ))
}

#[traced_test]
#[tokio::test]
async fn test_incoming_connection_succeed() -> Result<()> {
    // This builds a mock object which expects to have a certain
    // sequence of methods called on it: First it expects to have
    // the `MAGIC_STRING_REQUEST` and then the `MAGIC_STRING_RESPONSE`
    // value written. This is followed by a read of the bye message,
    // as this is a way to close the connection by the peer initiating
    // the connection. If this sequence is not followed, the `mock`
    // object will panic, and the `await` operator will evaluate
    // to Error.
    let network = Network::Main;
    let other_handshake = get_dummy_handshake_data(network);
    let own_handshake = get_dummy_handshake_data(network);
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            other_handshake,
        )))?)
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            own_handshake.clone(),
        )))?)
        .write(&to_bytes(&PeerMessage::ConnectionStatus(
            ConnectionStatus::Accepted,
        ))?)
        .read(&to_bytes(&PeerMessage::Bye)?)
        .build();
    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, peer_map) =
        get_genesis_setup(network, 0)?;
    main_loop::answer_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        own_handshake,
        8,
    )
    .await?;

    // Verify that peer map is empty after connection has been closed
    match peer_map.lock().unwrap().keys().len() {
        0 => (),
        _ => bail!("Incorrect number of maps in peer map"),
    };

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_incoming_connection_fail_bad_magic_value() -> Result<()> {
    let network = Network::Main;
    let other_handshake = get_dummy_handshake_data(network);
    let own_handshake = get_dummy_handshake_data(network);
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            other_handshake,
        )))?)
        .build();

    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _) =
        get_genesis_setup(network, 0)?;
    if let Err(_) = main_loop::answer_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        own_handshake,
        8,
    )
    .await
    {
        Ok(())
    } else {
        bail!("Expected error from run")
    }
}

#[traced_test]
#[tokio::test]
async fn test_incoming_connection_fail_bad_network() -> Result<()> {
    let other_handshake = get_dummy_handshake_data(Network::Testnet);
    let own_handshake = get_dummy_handshake_data(Network::Main);
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            other_handshake,
        )))?)
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            own_handshake.clone(),
        )))?)
        .build();

    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _) =
        get_genesis_setup(Network::Main, 0)?;
    if let Err(_) = main_loop::answer_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        own_handshake,
        8,
    )
    .await
    {
        Ok(())
    } else {
        bail!("Expected error from run")
    }
}

#[traced_test]
#[tokio::test]
async fn test_outgoing_connection_succeed() -> Result<()> {
    let network = Network::Main;
    let other_handshake = get_dummy_handshake_data(network);
    let own_handshake = get_dummy_handshake_data(network);
    let mock = Builder::new()
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            own_handshake.clone(),
        )))?)
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            other_handshake,
        )))?)
        .read(&to_bytes(&PeerMessage::ConnectionStatus(
            ConnectionStatus::Accepted,
        ))?)
        .read(&to_bytes(&PeerMessage::Bye)?)
        .build();

    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 0)?;
    call_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        &own_handshake,
    )
    .await?;

    // Verify that peer map is empty after connection has been closed
    match peer_map.lock().unwrap().keys().len() {
        0 => (),
        _ => bail!("Incorrect number of maps in peer map"),
    };

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_incoming_connection_fail_max_peers_exceeded() -> Result<()> {
    let network = Network::Main;
    let other_handshake = get_dummy_handshake_data(network);
    let own_handshake = get_dummy_handshake_data(network);
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            other_handshake,
        )))?)
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            own_handshake.clone(),
        )))?)
        .build();

    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, state, _peer_map) =
        get_genesis_setup(Network::Main, 2)?;
    let (_, _, _latest_block_header) = get_dummy_latest_block(None);

    if let Err(_) = main_loop::answer_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        own_handshake,
        2,
    )
    .await
    {
        Ok(())
    } else {
        bail!("Expected error from run")
    }
}

pin_project! {
#[derive(Debug)]
pub struct Mock<Item> {
    #[pin]
    actions: Box<Vec<Action<Item>>>,
}
}

#[derive(Debug, Clone, PartialEq)]
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
fn make_mock_block(
    previous_block: Block,
    target_difficulty: Option<U32s<TARGET_DIFFICULTY_U32_SIZE>>,
) -> Block {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
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
    let mut new_ms = previous_block.body.next_mutator_set_accumulator;
    let previous_ms = new_ms.clone();
    let coinbase_digest: Digest = coinbase_utxo.hash();

    let coinbase_addition_record: AdditionRecord<Hash> =
        new_ms.commit(&coinbase_digest.into(), &output_randomness.into());
    let mutator_set_update: MutatorSetUpdate = MutatorSetUpdate {
        removals: vec![],
        additions: vec![coinbase_addition_record.clone()],
    };
    new_ms.add(&coinbase_addition_record);

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

#[traced_test]
#[tokio::test]
async fn test_peer_loop_bye() -> Result<()> {
    let mock = Mock::new(vec![Action::Read(PeerMessage::Bye)]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (_to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
    let (_peer_broadcast_tx, _from_main_rx_clone, to_main_tx, _to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;

    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let from_main_rx_clone = peer_broadcast_tx.subscribe();
    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("for reconciliation block list must be empty");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_peer_loop_peer_list() -> Result<()> {
    let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, _to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::PeerListRequest),
        Action::Write(PeerMessage::PeerListResponse(vec![peer_address])),
        Action::Read(PeerMessage::Bye),
    ]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("for reconciliation block list must be empty");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn bad_block_test() -> Result<()> {
    // In this scenario, a block without a valid PoW is received. This block should be rejected
    // by the peer loop and a notification should never reach the main loop.
    let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, _to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;

    // Make a with hash above what the implied threshold from
    // `target_difficulty` requires
    let block_without_valid_pow = make_mock_block(
        genesis_block,
        Some(U32s::<TARGET_DIFFICULTY_U32_SIZE>::new([
            1_000_000, 0, 0, 0, 0,
        ])),
    );
    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_without_valid_pow.into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    // Verify that no message was sent to main loop
    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(_block)) => {
            bail!("Block notification must not be sent for block with invalid PoW")
        }
        Some(msg) => bail!(
            "No message must be sent to main loop when receiving old block. Got {:?}",
            msg
        ),
        None => (),
    };

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("for reconciliation block list must be empty");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_peer_loop_block_with_block_in_db() -> Result<()> {
    // The scenario tested here is that a client receives a block that is already
    // in the database. The expected behavior is to ignore the block and not send
    // a message to the main thread.
    let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, _to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;

    let block_1 = make_mock_block(genesis_block, None);
    state.update_latest_block(Box::new(block_1.clone())).await?;

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_1.into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    // Verify that no message was sent to main loop
    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(_block)) => {
            bail!("Block notification must not be sent for old block")
        }
        Some(msg) => bail!(
            "No message must be sent to main loop when receiving old block. Got {:?}",
            msg
        ),
        None => (),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("for reconciliation block list must be empty");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_peer_loop_receival_of_first_block() -> Result<()> {
    // Scenario: client only knows genesis block. The receives block 1.
    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(
            make_mock_block(genesis_block, None).into(),
        ))),
        Action::Read(PeerMessage::Bye),
    ]);

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    // Verify that a message was sent to `main_loop`?
    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(_block)) => (),
        _ => bail!("Did not find msg sent to main thread"),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("for reconciliation block list must be empty");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_peer_loop_receival_of_second_block_no_blocks_in_db() -> Result<()> {
    // In this scenario, the client only knows the genesis block (block 0) and then
    // receives block 2, meaning that block 1 will have to be requested.
    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;
    let block_1 = make_mock_block(genesis_block.clone(), None);
    let block_2 = make_mock_block(block_1.clone(), None);

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_1.hash)),
        Action::Read(PeerMessage::Block(Box::new(block_1.clone().into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(blocks)) => {
            if blocks[0].hash != block_1.hash {
                bail!("1st received block by main loop must be block 1");
            }
            if blocks[1].hash != block_2.hash {
                bail!("2nd received block by main loop must be block 2");
            }
        }
        _ => bail!("Did not find msg sent to main thread 1"),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("fork reconciliation block list must be empty after two-depth reconciliation");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_peer_loop_receival_of_fourth_block_one_block_in_db() -> Result<()> {
    // In this scenario, the client know the genesis block (block 0) and block 1, it
    // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;
    let block_1 = make_mock_block(genesis_block.clone(), None);
    let block_2 = make_mock_block(block_1.clone(), None);
    let block_3 = make_mock_block(block_2.clone(), None);
    let block_4 = make_mock_block(block_3.clone(), None);
    state.update_latest_block(Box::new(block_1)).await?;

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
        Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
        Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(blocks)) => {
            if blocks[0].hash != block_2.hash {
                bail!("1st received block by main loop must be block 1");
            }
            if blocks[1].hash != block_3.hash {
                bail!("2nd received block by main loop must be block 2");
            }
            if blocks[2].hash != block_4.hash {
                bail!("3rd received block by main loop must be block 3");
            }
        }
        _ => bail!("Did not find msg sent to main thread"),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("fork reconciliation block list must be empty after three-depth reconciliation");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_peer_loop_receival_of_third_block_no_blocks_in_db() -> Result<()> {
    // In this scenario, the client only knows the genesis block (block 0) and then
    // receives block 3, meaning that block 2 and 1 will have to be requested.
    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;
    let block_1 = make_mock_block(genesis_block.clone(), None);
    let block_2 = make_mock_block(block_1.clone(), None);
    let block_3 = make_mock_block(block_2.clone(), None);

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
        Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_1.hash)),
        Action::Read(PeerMessage::Block(Box::new(block_1.clone().into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(blocks)) => {
            if blocks[0].hash != block_1.hash {
                bail!("1st received block by main loop must be block 1");
            }
            if blocks[1].hash != block_2.hash {
                bail!("2nd received block by main loop must be block 2");
            }
            if blocks[2].hash != block_3.hash {
                bail!("3rd received block by main loop must be block 3");
            }
        }
        _ => bail!("Did not find msg sent to main thread"),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("fork reconciliation block list must be empty after three-depth reconciliation");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_block_reconciliation_interrupted_by_block_notification() -> Result<()> {
    // In this scenario, the client know the genesis block (block 0) and block 1, it
    // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
    // But the requests are interrupted by the peer sending another message: a new block
    // notification.
    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;
    let block_1 = make_mock_block(genesis_block.clone(), None);
    let block_2 = make_mock_block(block_1.clone(), None);
    let block_3 = make_mock_block(block_2.clone(), None);
    let block_4 = make_mock_block(block_3.clone(), None);
    let block_5 = make_mock_block(block_4.clone(), None);
    state.update_latest_block(Box::new(block_1)).await?;

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
        Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
        //
        // Now make the interruption of the block reconciliation process
        Action::Read(PeerMessage::BlockNotification(block_5.clone().into())),
        //
        // Complete the block reconciliation process by requesting the last block
        // in this process, to get back to a mutually known block.
        Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
        //
        // Then anticipate the request of the block that was announced
        // in the interruption.
        // Note that we cannot anticipate the response, as only the main
        // thread writes to the database. And the database needs to be updated
        // for the handling of block 5 to be done correctly.
        Action::Write(PeerMessage::BlockRequestByHeight(block_5.header.height)),
        Action::Read(PeerMessage::Bye),
    ]);

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(blocks)) => {
            if blocks[0].hash != block_2.hash {
                bail!("1st received block by main loop must be block 1");
            }
            if blocks[1].hash != block_3.hash {
                bail!("2nd received block by main loop must be block 2");
            }
            if blocks[2].hash != block_4.hash {
                bail!("3rd received block by main loop must be block 3");
            }
        }
        _ => bail!("Did not find msg sent to main thread"),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("fork reconciliation block list must be empty after three-depth reconciliation");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_block_reconciliation_interrupted_by_peer_list_request() -> Result<()> {
    // In this scenario, the client knows the genesis block (block 0) and block 1, it
    // then receives block 4, meaning that block 3, 2, and 1 will have to be requested.
    // But the requests are interrupted by the peer sending another message: a request
    // for a list of peers.
    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, mut to_main_rx1, state, peer_map) =
        get_genesis_setup(Network::Main, 1)?;
    let peer_address = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].address;
    let genesis_block: Block = state.get_latest_block().await;
    let block_1 = make_mock_block(genesis_block.clone(), None);
    let block_2 = make_mock_block(block_1.clone(), None);
    let block_3 = make_mock_block(block_2.clone(), None);
    let block_4 = make_mock_block(block_3.clone(), None);
    state.update_latest_block(Box::new(block_1)).await?;

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_4.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_3.hash)),
        Action::Read(PeerMessage::Block(Box::new(block_3.clone().into()))),
        Action::Write(PeerMessage::BlockRequestByHash(block_2.hash)),
        //
        // Now make the interruption of the block reconciliation process
        Action::Read(PeerMessage::PeerListRequest),
        //
        // Answer the request for a peer list
        Action::Write(PeerMessage::PeerListResponse(vec![peer_address])),
        //
        // Complete the block reconciliation process by requesting the last block
        // in this process, to get back to a mutually known block.
        Action::Read(PeerMessage::Block(Box::new(block_2.clone().into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let mut peer_state = PeerState::default();
    peer_loop::peer_loop(
        mock,
        from_main_rx_clone,
        to_main_tx,
        state,
        &peer_address,
        &mut peer_state,
    )
    .await?;

    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlocks(blocks)) => {
            if blocks[0].hash != block_2.hash {
                bail!("1st received block by main loop must be block 1");
            }
            if blocks[1].hash != block_3.hash {
                bail!("2nd received block by main loop must be block 2");
            }
            if blocks[2].hash != block_4.hash {
                bail!("3rd received block by main loop must be block 3");
            }
        }
        _ => bail!("Did not find msg sent to main thread"),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    }

    if !peer_state.fork_reconciliation_blocks.is_empty() {
        bail!("fork reconciliation block list must be empty after three-depth reconciliation");
    }

    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_connection_status() -> Result<()> {
    let network = Network::Main;
    let (_peer_broadcast_tx, _from_main_rx_clone, _to_main_tx, _to_main_rx1, state, peer_map) =
        get_genesis_setup(network, 1)?;
    let peer = peer_map.lock().unwrap().values().collect::<Vec<_>>()[0].clone();
    let peer_id = peer.instance_id;

    let own_handshake = get_dummy_handshake_data(network);
    let mut other_handshake = get_dummy_handshake_data(network);

    let mut status = main_loop::get_connection_status(4, &state, &own_handshake, &other_handshake);
    if status != ConnectionStatus::Accepted {
        bail!("Must return ConnectionStatus::Accepted");
    }

    status = main_loop::get_connection_status(4, &state, &own_handshake, &own_handshake);
    if status != ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect) {
        bail!("Must return ConnectionStatus::Refused(ConnectionRefusedReason::SelfConnect))");
    }

    status = main_loop::get_connection_status(1, &state, &own_handshake, &other_handshake);
    if status != ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded) {
        bail!(
            "Must return ConnectionStatus::Refused(ConnectionRefusedReason::MaxPeerNumberExceeded))"
        );
    }

    // Attempt to connect to already connected peer
    other_handshake.instance_id = peer_id;
    status = main_loop::get_connection_status(100, &state, &own_handshake, &other_handshake);
    if status != ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected) {
        bail!("Must return ConnectionStatus::Refused(ConnectionRefusedReason::AlreadyConnected))");
    }

    Ok(())
}
