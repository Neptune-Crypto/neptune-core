use super::*;

use anyhow::Error;
use bytes::{Bytes, BytesMut};
use futures::sink;
use futures::stream;
use futures::task::{Context, Poll};
use pin_project_lite::pin_project;
use std::marker::PhantomData;
use std::pin::Pin;
use std::str::FromStr;
use tokio_serde::Serializer;
use tokio_test::io::Builder;
use tokio_util::codec::Encoder;

pin_project! {
#[derive(Debug)]
pub struct SinkStream<Sink: sink::Sink<Item>, Stream: stream::Stream, Item> {
    #[pin]
    sink: Sink,
    #[pin]
    stream: Stream,
    item: PhantomData<Item>,
}
}

impl<Sink: sink::Sink<Item>, Stream: stream::Stream, Item> SinkStream<Sink, Stream, Item> {
    pub fn new(sink: Sink, stream: Stream) -> SinkStream<Sink, Stream, Item> {
        SinkStream {
            sink,
            stream,
            item: PhantomData,
        }
    }
}

impl<Sink: sink::Sink<Item> + Unpin, Stream: stream::Stream, Item> sink::Sink<Item>
    for SinkStream<Sink, Stream, Item>
{
    type Error = Sink::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        self.project().sink.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.poll_close(cx)
    }
}

impl<Sink: sink::Sink<Item>, Stream: stream::Stream, Item> stream::Stream
    for SinkStream<Sink, Stream, Item>
{
    type Item = Stream::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}

fn get_peer_map() -> Arc<Mutex<HashMap<SocketAddr, Peer>>> {
    Arc::new(Mutex::new(HashMap::new()))
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
        extra_values: HashMap::new(),
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
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            get_dummy_handshake_data(Network::Main),
        )))?)
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            get_dummy_handshake_data(Network::Main),
        )))?)
        .read(&to_bytes(&PeerMessage::Bye)?)
        .build();

    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let peer_map = get_peer_map();
    incoming_transaction(
        mock,
        peer_map.clone(),
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
async fn test_incoming_transaction_fail_bad_magic_value() -> Result<()> {
    let mock = Builder::new()
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            get_dummy_handshake_data(Network::Main),
        )))?)
        .build();

    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    if let Err(_) = incoming_transaction(
        mock,
        get_peer_map(),
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
async fn test_incoming_transaction_fail_bad_network() -> Result<()> {
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

    if let Err(_) = incoming_transaction(
        mock,
        get_peer_map(),
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
async fn test_outgoing_transaction_succeed() -> Result<()> {
    let mock = Builder::new()
        .write(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_REQUEST.to_vec(),
            get_dummy_handshake_data(Network::Main),
        )))?)
        .read(&to_bytes(&PeerMessage::Handshake((
            MAGIC_STRING_RESPONSE.to_vec(),
            get_dummy_handshake_data(Network::Main),
        )))?)
        .read(&to_bytes(&PeerMessage::Bye)?)
        .build();

    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

    let peer_map = get_peer_map();
    let from_main_rx_clone = peer_broadcast_tx.subscribe();
    outgoing_transaction(
        mock,
        peer_map.clone(),
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

#[tokio::test]
async fn test_peer_loop_bye() -> Result<()> {
    let sink = sink::drain();
    let stream = stream::once(Box::pin(async { Ok::<_, Error>(PeerMessage::Bye) }));
    let ss = SinkStream::new(sink, stream);

    let (peer_broadcast_tx, mut _from_main_rx1) = broadcast::channel::<MainToPeerThread>(1);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerThreadToMain>(1);

    let peer_map = get_peer_map();
    let peer_address = get_dummy_address();
    peer_map
        .lock()
        .unwrap()
        .insert(peer_address, get_dummy_peer(peer_address));
    let from_main_rx_clone = peer_broadcast_tx.subscribe();
    peer_loop(
        ss,
        from_main_rx_clone,
        to_main_tx,
        peer_map.clone(),
        &peer_address,
    )
    .await
}
