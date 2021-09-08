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
use tokio_serde::formats::*;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

mod model;
mod peer;
use peer::Peer;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";

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

    // Connect to peers
    for peer in peers {
        let thread_arc = Arc::clone(&peer_map);
        tokio::spawn(async move {
            initiate_connection(peer, thread_arc).await;
        });
    }

    // Handle incoming connections
    loop {
        // The second item contains the IP and port of the new connection.
        let (stream, _) = listener.accept().await?;
        let thread_arc = Arc::clone(&peer_map);
        tokio::spawn(async move {
            receive_connection(stream, thread_arc).await;
        });
    }
}

#[instrument]
pub async fn outgoing_transaction<S>(
    stream: S,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
    peer_address: std::net::SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    info!("Established connection");

    // Delimit frames using a length header
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());

    // Serialize frames with bincode
    let mut serialized =
        tokio_serde::SymmetricallyFramed::new(length_delimited, SymmetricalBincode::default());

    serialized
        .send(model::Message::MagicValue(Vec::from(MAGIC_STRING_REQUEST)))
        .await?;

    match serialized.try_next().await? {
        Some(model::Message::MagicValue(v)) if &v[..] == MAGIC_STRING_RESPONSE => {
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
        version: "0.1.0".to_string(), // TODO: FIX
    };
    if let Ok(mut x) = peer_map.lock() {
        x.entry(peer_address).or_insert(new_peer);
    } else {
        bail!("Failed to lock peer map");
    }

    serialized.send(model::Message::Bye).await?;

    Ok(())
}

#[instrument]
pub async fn incoming_transaction<S>(
    stream: S,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
    peer_address: std::net::SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    info!("Established connection");

    // Build the communication/serialization/frame handler
    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());
    let mut deserialized = tokio_serde::SymmetricallyFramed::new(
        length_delimited,
        SymmetricalBincode::<model::Message>::default(),
    );

    // Await and respond to 1st incoming message
    match deserialized.try_next().await? {
        Some(model::Message::MagicValue(v)) if &v[..] == MAGIC_STRING_REQUEST => {
            info!("Got correct magic value!");
            deserialized
                .send(model::Message::MagicValue(MAGIC_STRING_RESPONSE.to_vec()))
                .await?;
        }
        Some(model::Message::MagicValue(v)) => {
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
        version: "0.1.0".to_string(), // TODO: FIX
    };
    if let Ok(mut x) = peer_map.lock() {
        x.entry(peer_address).or_insert(new_peer);
    } else {
        bail!("Failed to lock peer map");
    }

    // Loop for further messages
    loop {
        match deserialized.try_next().await? {
            Some(model::Message::Bye) => {
                info!("Got bye");
                break;
            }
            Some(v) => {
                info!("Got message: {:?}", v);
                deserialized.send(model::Message::NewBlock(42)).await?;
            }
            None => break,
        }
    }

    Ok(())
}

#[instrument]
pub async fn initiate_connection(
    peer_address: std::net::SocketAddr,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
) {
    debug!("Attempting to initiate connection");
    match tokio::net::TcpStream::connect(peer_address).await {
        Err(e) => {
            warn!("Failed to establish connection: {}", e);
        }
        Ok(stream) => match outgoing_transaction(stream, peer_map, peer_address).await {
            Ok(()) => (),
            Err(e) => error!("An error occurred: {}. Connection closing", e),
        },
    };

    info!("Connection closing");
}

#[instrument]
pub async fn receive_connection(
    stream: TcpStream,
    peer_map: Arc<Mutex<HashMap<SocketAddr, peer::Peer>>>,
) {
    info!("Connection established");

    let peer_address: SocketAddr = stream.peer_addr().unwrap();
    match incoming_transaction(stream, peer_map, peer_address).await {
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

    fn to_bytes(message: &model::Message) -> Result<Bytes> {
        let mut transport = LengthDelimitedCodec::new();
        let mut formating = SymmetricalBincode::<model::Message>::default();
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
            .read(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_REQUEST.to_vec(),
            ))?)
            .write(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_RESPONSE.to_vec(),
            ))?)
            .read(&to_bytes(&model::Message::Bye)?)
            .build();

        let peer_map = get_peer_map();
        incoming_transaction(mock, peer_map.clone(), get_dummy_address()).await?;
        match peer_map.lock().unwrap().keys().len() {
            1 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }

    #[tokio::test]
    async fn test_incoming_transaction_fail() -> Result<()> {
        let mock = Builder::new()
            .read(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_RESPONSE.to_vec(),
            ))?)
            .build();

        if let Err(_) = incoming_transaction(mock, get_peer_map(), get_dummy_address()).await {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }

    #[tokio::test]
    async fn test_outgoing_transaction_succeed() -> Result<()> {
        let mock = Builder::new()
            .write(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_REQUEST.to_vec(),
            ))?)
            .read(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_RESPONSE.to_vec(),
            ))?)
            .write(&to_bytes(&model::Message::Bye)?)
            .build();

        let peer_map = get_peer_map();
        outgoing_transaction(mock, peer_map.clone(), get_dummy_address()).await?;
        match peer_map.lock().unwrap().keys().len() {
            1 => (),
            _ => bail!("Incorrect number of maps in peer map"),
        };

        Ok(())
    }
}
