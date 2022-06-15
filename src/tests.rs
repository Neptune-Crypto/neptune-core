use super::*;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockBody;
use crate::models::blockchain::block::BlockHeader;
use crate::models::blockchain::digest::RESCUE_PRIME_OUTPUT_SIZE_IN_BFES;
use crate::models::blockchain::mutator_set_update::MutatorSetUpdate;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::Utxo;
use crate::models::peer::ConnectionRefusedReason;
use bytes::{Bytes, BytesMut};
use futures::sink;
use futures::stream;
use futures::task::{Context, Poll};
use leveldb::options::WriteOptions;
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
use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::traits::GetRandomElements;
use twenty_first::util_types::mutator_set::addition_record::AdditionRecord;
use twenty_first::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use twenty_first::util_types::mutator_set::mutator_set_trait::MutatorSet;

const UNIT_TEST_DB_DIRECTORY: &str = "neptune_unit_test_databases";

fn get_peer_map() -> Arc<std::sync::Mutex<HashMap<SocketAddr, Peer>>> {
    Arc::new(std::sync::Mutex::new(HashMap::new()))
}

// Create databases for unit tests on disk, and return objects for them.
// For now, we use databases on disk, but it would be nicer to use
// something that is in-memory only.
fn get_unit_test_database(network: Network) -> Result<Arc<tokio::sync::Mutex<Databases>>> {
    let temp_dir = env::temp_dir();
    let mut path = temp_dir.to_owned();
    path.push(UNIT_TEST_DB_DIRECTORY);

    // Create a randomly named directory to allow the tests to run in parallel.
    // If this is not done, the parallel execution of unit tests will fail as
    // they each hold a lock on the database.
    let random_directory: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    path.push(random_directory);

    let db = initialize_databases(path.as_path(), network);

    Ok(Arc::new(tokio::sync::Mutex::new(db)))
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

fn get_dummy_handshake_data(network: Network) -> HandshakeData {
    HandshakeData {
        instance_id: rand::random(),
        latest_block_info: None,
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

fn get_dummy_setup(
    network: Network,
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

    let peer_map = get_peer_map();
    let databases = get_unit_test_database(network)?;
    let state = State {
        peer_map: peer_map.clone(),
        databases,
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
        get_dummy_setup(network)?;
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
        get_dummy_setup(network)?;
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
        get_dummy_setup(Network::Main)?;
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
        get_dummy_setup(Network::Main)?;
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

    let (_peer_broadcast_tx, from_main_rx_clone, to_main_tx, _to_main_rx1, _, _) =
        get_dummy_setup(Network::Main)?;
    let peer_map = get_peer_map();
    let peer_address0 = get_dummy_address();
    let peer_address1 = std::net::SocketAddr::from_str("123.123.123.123:8080").unwrap();
    peer_map
        .lock()
        .unwrap()
        .insert(peer_address0, get_dummy_peer(peer_address0));
    peer_map
        .lock()
        .unwrap()
        .insert(peer_address1, get_dummy_peer(peer_address1));
    let state = State {
        peer_map,
        databases: get_unit_test_database(Network::Main)?,
    };

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
            Poll::Ready(Some(Err(MockError::UnexpectedRead)))
        }
    }
}

/// Return a fake block with a random hash
fn make_mock_block(height: u64) -> Block {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let (_secret_key, public_key): (secp256k1::SecretKey, secp256k1::PublicKey) =
        secp.generate_keypair(&mut rng);

    let coinbase_utxo = Utxo {
        amount: U32s::new([100u32, 0, 0, 0]),
        public_key,
    };
    let timestamp: BFieldElement = BFieldElement::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Got bad time timestamp in mining process")
            .as_secs(),
    );
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![coinbase_utxo.clone()],
        public_scripts: vec![],
        fee: U32s::zero(),
        timestamp,
    };
    let mut new_ms = MutatorSetAccumulator::default();
    let coinbase_digest: RescuePrimeDigest = coinbase_utxo.hash();
    let randomness =
        BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut thread_rng());
    let coinbase_addition_record: AdditionRecord<Hash> =
        new_ms.commit(&coinbase_digest.into(), &randomness.into());
    let mutator_set_update: MutatorSetUpdate = MutatorSetUpdate {
        removals: vec![],
        additions: vec![coinbase_addition_record.clone()],
    };
    new_ms.add(&coinbase_addition_record);

    let block_body: BlockBody = BlockBody {
        transactions: vec![tx],
        mutator_set_accumulator: new_ms.clone(),
        mutator_set_update,
    };

    let zero = BFieldElement::ring_zero();
    let block_header = BlockHeader {
        version: zero,
        height: BlockHeight::from(height),
        mutator_set_commitment: new_ms.get_commitment().into(),
        prev_block_digest: RescuePrimeDigest::default(),
        timestamp,
        nonce: [zero, zero, zero],
        max_block_size: 1_000_000,
        proof_of_work_line: U32s::zero(),
        proof_of_work_family: U32s::zero(),
        target_difficulty: U32s::zero(),

        // TODO: Wrong: Fix this by implementing a hash function on BlockBody
        block_body_merkle_root: RescuePrimeDigest::default(),
        uncles: vec![],
    };

    Block::new(block_header, block_body)
}

#[tokio::test]
async fn test_peer_loop_bye() -> Result<()> {
    let mock = Mock::new(vec![Action::Read(PeerMessage::Bye)]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);

    let peer_map = get_peer_map();
    let peer_address = get_dummy_address();
    peer_map
        .lock()
        .unwrap()
        .insert(peer_address, get_dummy_peer(peer_address));
    let databases = get_unit_test_database(Network::Main)?;
    let state = State {
        peer_map: peer_map.clone(),
        databases,
    };
    let from_main_rx_clone = peer_broadcast_tx.subscribe();
    peer_loop::peer_loop(mock, from_main_rx_clone, to_main_tx, state, &peer_address).await?;

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    } else {
        Ok(())
    }
}

#[tokio::test]
async fn test_peer_loop_peer_list() -> Result<()> {
    let peer_map = get_peer_map();
    let peer_address = get_dummy_address();
    peer_map
        .lock()
        .unwrap()
        .insert(peer_address, get_dummy_peer(peer_address));
    let databases = get_unit_test_database(Network::Main)?;
    let state = State {
        peer_map: peer_map.clone(),
        databases,
    };

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::PeerListRequest),
        Action::Write(PeerMessage::PeerListResponse(vec![peer_address])),
        Action::Read(PeerMessage::Bye),
    ]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    peer_loop::peer_loop(mock, from_main_rx_clone, to_main_tx, state, &peer_address).await?;

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    } else {
        Ok(())
    }
}

#[tokio::test]
async fn test_peer_loop_block_with_block_in_db() -> Result<()> {
    let peer_map = get_peer_map();
    let peer_address = get_dummy_address();
    peer_map
        .lock()
        .unwrap()
        .insert(peer_address, get_dummy_peer(peer_address));
    let databases = get_unit_test_database(Network::Main)?;

    let block_14 = make_mock_block(14);
    let latest_block_info_14 = LatestBlockInfo::new(block_14.hash, block_14.header.height);
    // let block_hash_raw: [u8; 32] = block_14.hash.into();
    {
        let dbs = databases.lock().await;
        dbs.latest_block.put(
            WriteOptions::new(),
            DatabaseUnit(),
            &bincode::serialize(&latest_block_info_14)?,
        )?;
        dbs.block_hash_to_block.put(
            WriteOptions::new(),
            block_14.hash,
            &bincode::serialize(&block_14)?,
        )?;
        dbs.block_height_to_hash.put(
            WriteOptions::new(),
            block_14.header.height,
            &bincode::serialize(&block_14.hash)?,
        )?;
    }
    let state = State {
        peer_map: peer_map.clone(),
        databases: databases,
    };

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(block_14.into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    peer_loop::peer_loop(mock, from_main_rx_clone, to_main_tx, state, &peer_address).await?;

    // Verify that no message was sent to main loop
    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlock(_block)) => {
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
    } else {
        Ok(())
    }
}

#[tokio::test]
async fn test_peer_loop_block_no_existing_block_in_db() -> Result<()> {
    let peer_map = get_peer_map();
    let peer_address = get_dummy_address();
    peer_map
        .lock()
        .unwrap()
        .insert(peer_address, get_dummy_peer(peer_address));
    let databases = get_unit_test_database(Network::Main)?;
    let state = State {
        peer_map: peer_map.clone(),
        databases,
    };

    let mock = Mock::new(vec![
        Action::Read(PeerMessage::Block(Box::new(make_mock_block(0).into()))),
        Action::Read(PeerMessage::Bye),
    ]);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    peer_loop::peer_loop(mock, from_main_rx_clone, to_main_tx, state, &peer_address).await?;

    // Verify that a message was sent to `main_loop`?
    match to_main_rx1.recv().await {
        Some(PeerThreadToMain::NewBlock(_block)) => (),
        _ => bail!("Did not find msg sent to main thread"),
    };

    if !peer_map.lock().unwrap().is_empty() {
        bail!("peer map must be empty after closing connection gracefully");
    } else {
        Ok(())
    }
}

#[tokio::test]
async fn test_get_connection_status() -> Result<()> {
    let network = Network::Main;
    let peer_map = get_peer_map();
    let peer_address = get_dummy_address();
    let peer = get_dummy_peer(peer_address);
    let peer_id = peer.instance_id;
    peer_map.lock().unwrap().insert(peer_address, peer);
    let databases = get_unit_test_database(network)?;
    let state = State {
        peer_map: peer_map.clone(),
        databases,
    };

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
