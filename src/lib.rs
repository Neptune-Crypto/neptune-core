use anyhow::{bail, Result};
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio_serde::formats::*;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

mod model;
use model::{FromMainMessage, PeerMessage, ToMainMessage};
mod peer;
use peer::Peer;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";
const CHANNEL_MESSAGE_CAPACITY: usize = 1000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[instrument]
pub async fn connection_handler(
    listen_addr: IpAddr,
    port: u16,
    peers: Vec<SocketAddr>,
) -> Result<()> {
    // Bind socket to port on this machine
    let listener = TcpListener::bind((listen_addr, port))
        .await
        .unwrap_or_else(|_| panic!("Failed to bind to local TCP port {}:{}. Is an instance of this program already running?", listen_addr, port));

    let peer_map = Arc::new(Mutex::new(HashMap::new()));

    // Construct the broadcast channel to communicate from the main thread to peer threads
    let (from_main_tx, _) = broadcast::channel::<FromMainMessage>(CHANNEL_MESSAGE_CAPACITY);

    // Add the MPSC (multi-producer, single consumer) channel for peer-thread-to-main communication
    let (to_main_tx, mut to_main_rx) = mpsc::channel::<ToMainMessage>(CHANNEL_MESSAGE_CAPACITY);

    // Connect to peers
    for peer in peers {
        let thread_arc = Arc::clone(&peer_map);
        let from_main_rx_clone: broadcast::Receiver<FromMainMessage> = from_main_tx.subscribe();
        let to_main_tx_clone: mpsc::Sender<ToMainMessage> = to_main_tx.clone();
        tokio::spawn(async move {
            initiate_connection(peer, thread_arc, from_main_rx_clone, to_main_tx_clone).await;
        });
    }

    // Handle incoming connections and messages from peer threads
    loop {
        select! {
            // The second item contains the IP and port of the new connection.
            Ok((stream, _)) = listener.accept() => {
                let thread_arc = Arc::clone(&peer_map);
                let from_main_rx_clone: broadcast::Receiver<FromMainMessage> = from_main_tx.subscribe();
                let to_main_tx_clone: mpsc::Sender<ToMainMessage> = to_main_tx.clone();
                tokio::spawn(async move {
                    receive_connection(stream, thread_arc, from_main_rx_clone, to_main_tx_clone).await;
                });
            }
            Some(msg) = to_main_rx.recv() => {
                info!("Received message sent to main thread. Got: {:?}", msg);
            }
            // TODO: Add signal::ctrl_c/shutdown handling here
        }
    }
}

/// Loop for the peer threads. Awaits either a message from the peer over TCP,
/// or a message from main over the main-to-peer-threads broadcast channel.
#[instrument]
pub async fn peer_loop<S>(
    mut serialized: SymmetricallyFramed<
        Framed<S, LengthDelimitedCodec>,
        PeerMessage,
        Bincode<PeerMessage, PeerMessage>,
    >,
    mut from_main_rx: broadcast::Receiver<FromMainMessage>,
    to_main_tx: mpsc::Sender<model::ToMainMessage>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    loop {
        select! {
            Ok(peer_message) = serialized.try_next() => {
                match peer_message {
                    None => {
                        info!("Peer closed connection.");
                        println!("Peer closed connection.");
                        break;
                    }
                    Some(PeerMessage::Bye) => {
                        info!("Got bye. Closing connection to peer");
                        println!("Got bye. Closing connection to peer");
                        break;
                    }
                    Some(msg) => {
                        warn!("Uninplemented peer message received. Got: {:?}", msg);
                        println!("Uninplemented peer message received. Got: {:?}", msg);
                    }
                }
            }
            val = from_main_rx.recv() => {
                println!("Got message from main: {:?}", val);
            }
        }
        // TODO: Add signal::ctrl_c/shutdown handling here
    }

    Ok(())
}

#[instrument]
pub async fn outgoing_transaction<S>(
    stream: S,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
    peer_address: std::net::SocketAddr,
    from_main_rx: broadcast::Receiver<FromMainMessage>,
    to_main_tx: mpsc::Sender<model::ToMainMessage>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    info!("Established connection");

    // Delimit frames using a length header
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());

    // Serialize frames with bincode
    let mut serialized: SymmetricallyFramed<
        Framed<S, LengthDelimitedCodec>,
        PeerMessage,
        Bincode<PeerMessage, PeerMessage>,
    > = SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());

    // Make Neptune handshake
    serialized
        .send(PeerMessage::MagicValue((
            Vec::from(MAGIC_STRING_REQUEST),
            VERSION.to_string(),
        )))
        .await?;
    let peer_version;
    match serialized.try_next().await? {
        Some(PeerMessage::MagicValue((v, version))) if &v[..] == MAGIC_STRING_RESPONSE => {
            peer_version = version;
            debug!("Got correct magic value response!");
        }
        v => {
            bail!("Expected magic value, got {:?}", v);
        }
    }

    // Add peer to peer map if not already there
    let new_peer = Peer {
        address: peer_address,
        banscore: 0,
        inbound: false,
        last_seen: SystemTime::now(),
        version: peer_version,
    };
    if let Ok(mut x) = peer_map.lock() {
        x.entry(peer_address).or_insert(new_peer);
    } else {
        bail!("Failed to lock peer map");
    }

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop(serialized, from_main_rx, to_main_tx).await?;

    Ok(())
}

#[instrument]
pub async fn incoming_transaction<S>(
    stream: S,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
    peer_address: std::net::SocketAddr,
    from_main_rx: broadcast::Receiver<FromMainMessage>,
    to_main_tx: mpsc::Sender<model::ToMainMessage>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    info!("Established connection");

    // Build the communication/serialization/frame handler
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
    let mut deserialized = tokio_serde::SymmetricallyFramed::new(
        length_delimited,
        SymmetricalBincode::<PeerMessage>::default(),
    );

    // Complete Neptune handshake
    let peer_version;
    match deserialized.try_next().await? {
        Some(PeerMessage::MagicValue((v, version))) if &v[..] == MAGIC_STRING_REQUEST => {
            info!("Got correct magic value!");
            peer_version = version;
            deserialized
                .send(PeerMessage::MagicValue((
                    MAGIC_STRING_RESPONSE.to_vec(),
                    VERSION.to_string(),
                )))
                .await?;
        }
        Some(PeerMessage::MagicValue(v)) => {
            bail!("Got invalid magic value: {:?}", v);
        }
        v => {
            bail!("Expected magic value, got {:?}", v);
        }
    }

    // Add peer to peer map if not already there
    let new_peer = Peer {
        address: peer_address,
        banscore: 0,
        inbound: true,
        last_seen: SystemTime::now(),
        version: peer_version,
    };
    if let Ok(mut x) = peer_map.lock() {
        x.entry(peer_address).or_insert(new_peer);
    } else {
        bail!("Failed to lock peer map");
    }

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop(deserialized, from_main_rx, to_main_tx).await?;

    Ok(())
}

#[instrument]
pub async fn initiate_connection(
    peer_address: std::net::SocketAddr,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
    from_main_rx: broadcast::Receiver<FromMainMessage>,
    to_main_tx: mpsc::Sender<model::ToMainMessage>,
) {
    debug!("Attempting to initiate connection");
    match tokio::net::TcpStream::connect(peer_address).await {
        Err(e) => {
            warn!("Failed to establish connection: {}", e);
        }
        Ok(stream) => {
            match outgoing_transaction(stream, peer_map, peer_address, from_main_rx, to_main_tx)
                .await
            {
                Ok(()) => (),
                Err(e) => error!("An error occurred: {}. Connection closing", e),
            }
        }
    };

    info!("Connection closing");
}

#[instrument]
pub async fn receive_connection(
    stream: TcpStream,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
    from_main_rx: broadcast::Receiver<FromMainMessage>,
    to_main_tx: mpsc::Sender<model::ToMainMessage>,
) {
    info!("Connection established");

    let peer_address: SocketAddr = stream.peer_addr().unwrap();
    match incoming_transaction(stream, peer_map, peer_address, from_main_rx, to_main_tx).await {
        Ok(()) => (),
        Err(e) => error!("An error occurred: {}. Connection closing", e),
    };

    info!("Connection closing");
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut};
    use std::pin::Pin;
    use std::str::FromStr;
    use tokio_serde::Serializer;
    use tokio_test::io::Builder;
    use tokio_util::codec::Encoder;

    fn get_peer_map() -> Arc<Mutex<HashMap<SocketAddr, Peer>>> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    fn get_dummy_address() -> SocketAddr {
        std::net::SocketAddr::from_str("127.0.0.1:8080").unwrap()
    }

    fn get_dummy_version() -> String {
        "0.1.0".to_string()
    }

    fn to_bytes(message: &PeerMessage) -> Result<Bytes> {
        let mut transport = LengthDelimitedCodec::new();
        let mut formating = SymmetricalBincode::<model::PeerMessage>::default();
        let mut buf = BytesMut::new();
        let () = transport.encode(
            Bytes::from(Pin::new(&mut formating).serialize(message)?),
            &mut buf,
        )?;
        Ok(buf.freeze())
    }

    #[tokio::test]
    async fn test_incoming_transaction_succeed() -> Result<()> {
        // This builds a mock object which expects to have a certain
        // sequence of methods called on it: First it expects to have
        // the `MAGIC_STRING_REQUEST` and then the `MAGIC_STRING_RESPONSE`
        // value written. This is followed by a read of the bye message,
        // as this is a way to close the connection by the peer initiating
        // the connection. If this sequence is not followed, the `mock`
        // object will panic, and the `await` operator will evaluate
        // to Error.
        let mock = Builder::new()
            .read(&to_bytes(&model::PeerMessage::MagicValue(
                MAGIC_STRING_REQUEST.to_vec(),
                get_dummy_version(),
            )))?)
            .write(&to_bytes(&PeerMessage::MagicValue((
                MAGIC_STRING_RESPONSE.to_vec(),
                get_dummy_version(),
            )))?)
            .read(&to_bytes(&PeerMessage::Bye)?)
            .build();

        let (from_main_tx, mut _from_main_rx1) =
            broadcast::channel::<FromMainMessage>(CHANNEL_MESSAGE_CAPACITY);
        let (to_main_tx, mut _to_main_rx1) =
            mpsc::channel::<ToMainMessage>(CHANNEL_MESSAGE_CAPACITY);
        let from_main_rx_clone = from_main_tx.subscribe();

        let peer_map = get_peer_map();
        incoming_transaction(
            mock,
            peer_map.clone(),
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
        )
        .await?;
        match peer_map.lock().unwrap().keys().len() {
            1 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }

    #[tokio::test]
    async fn test_incoming_transaction_fail() -> Result<()> {
        let mock = Builder::new()
            .read(&to_bytes(&PeerMessage::MagicValue((
                MAGIC_STRING_RESPONSE.to_vec(),
                get_dummy_version(),
            )))?)
            .build();

        let (from_main_tx, mut _from_main_rx1) =
            broadcast::channel::<FromMainMessage>(CHANNEL_MESSAGE_CAPACITY);
        let (to_main_tx, mut _to_main_rx1) =
            mpsc::channel::<ToMainMessage>(CHANNEL_MESSAGE_CAPACITY);
        let from_main_rx_clone = from_main_tx.subscribe();

        if let Err(_) = incoming_transaction(
            mock,
            get_peer_map(),
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
        )
        .await
        {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }

    #[tokio::test]
    async fn test_outgoing_transaction_succeed() -> Result<()> {
        let mock = Builder::new()
            .write(&to_bytes(&PeerMessage::MagicValue((
                MAGIC_STRING_REQUEST.to_vec(),
                get_dummy_version(),
            )))?)
            .read(&to_bytes(&PeerMessage::MagicValue((
                MAGIC_STRING_RESPONSE.to_vec(),
                get_dummy_version(),
            )))?)
            .read(&to_bytes(&PeerMessage::Bye)?)
            .build();

        let (from_main_tx, mut _from_main_rx1) =
            broadcast::channel::<FromMainMessage>(CHANNEL_MESSAGE_CAPACITY);
        let (to_main_tx, mut _to_main_rx1) =
            mpsc::channel::<ToMainMessage>(CHANNEL_MESSAGE_CAPACITY);

        let peer_map = get_peer_map();
        let from_main_rx_clone = from_main_tx.subscribe();
        outgoing_transaction(
            mock,
            peer_map.clone(),
            get_dummy_address(),
            from_main_rx_clone,
            to_main_tx,
        )
        .await?;
        match peer_map.lock().unwrap().keys().len() {
            1 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }
}
