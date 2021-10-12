use super::*;

use bytes::{Bytes, BytesMut};
use futures::sink;
use futures::stream;
use futures::task::{Context, Poll};
use pin_project_lite::pin_project;
use rand::{distributions::Alphanumeric, Rng};
use std::env;
use std::pin::Pin;
use std::str::FromStr;
use tokio_serde::Serializer;
use tokio_test::io::Builder;
use tokio_util::codec::Encoder;

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
        last_seen: SystemTime::now(),
        version: get_dummy_version(),
    }
}

fn get_dummy_version() -> String {
    "0.1.0".to_string()
}

fn get_dummy_handshake_data(network: Network) -> HandshakeData {
    HandshakeData {
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
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            get_dummy_handshake_data(network),
        )))?)
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            get_dummy_handshake_data(network),
        )))?)
        .read(&to_bytes(&PeerMessage::Bye)?)
        .build();

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
    main_loop::answer_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        get_dummy_handshake_data(Network::Main),
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
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            get_dummy_handshake_data(network),
        )))?)
        .build();

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

    if let Err(_) = main_loop::answer_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        get_dummy_handshake_data(Network::Main),
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
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            get_dummy_handshake_data(Network::Testnet),
        )))?)
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            get_dummy_handshake_data(Network::Main),
        )))?)
        .build();

    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let peer_map = get_peer_map();
    let databases = get_unit_test_database(Network::Main)?;
    let state = State {
        peer_map: peer_map.clone(),
        databases,
    };

    if let Err(_) = main_loop::answer_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        get_dummy_handshake_data(Network::Main),
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
    let mock = Builder::new()
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            get_dummy_handshake_data(network),
        )))?)
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            get_dummy_handshake_data(network),
        )))?)
        .read(&to_bytes(&PeerMessage::Bye)?)
        .build();

    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

    let peer_map = get_peer_map();
    let databases = get_unit_test_database(network)?;
    let state = State {
        peer_map: peer_map.clone(),
        databases,
    };
    let from_main_rx_clone = peer_broadcast_tx.subscribe();
    call_peer(
        mock,
        state,
        get_dummy_address(),
        from_main_rx_clone,
        to_main_tx,
        &get_dummy_handshake_data(Network::Main),
    )
    .await?;

    // Verify that peer map is empty after connection has been closed
    match peer_map.lock().unwrap().keys().len() {
        0 => (),
        _ => bail!("Incorrect number of maps in peer map"),
    };

    Ok(())
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
    peer_loop::peer_loop(mock, from_main_rx_clone, to_main_tx, state, &peer_address).await
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

    Ok(())
}
