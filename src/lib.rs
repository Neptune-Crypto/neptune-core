pub mod big_array;
pub mod config_models;
mod mine;
mod model;
mod peer;
use anyhow::{anyhow, bail, Context, Result};
use config_models::network::Network;
use futures::sink::{Sink, SinkExt};
use futures::stream::{TryStream, TryStreamExt};
use model::{
    FromMinerToMain, HandshakeData, MainToPeerThread, PeerMessage, PeerStateData, PeerThreadToMain,
    ToMiner,
};
use peer::Peer;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::Unpin;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_serde::formats::*;
use tokio_serde::SymmetricallyFramed;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";
const PEER_CHANNEL_CAPACITY: usize = 1000;
const MINER_CHANNEL_CAPACITY: usize = 3;
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[instrument]
pub async fn connection_handler(
    listen_addr: IpAddr,
    port: u16,
    peers: Vec<SocketAddr>,
    network: Network,
    mine: bool,
) -> Result<()> {
    // Bind socket to port on this machine
    let listener = TcpListener::bind((listen_addr, port))
        .await
        .with_context(|| format!("Failed to bind to local TCP port {}:{}. Is an instance of this program already running?", listen_addr, port))?;

    let peer_map = Arc::new(Mutex::new(HashMap::new()));

    // Construct the broadcast channel to communicate from the main thread to peer threads
    let (peer_broadcast_tx, _) = broadcast::channel::<MainToPeerThread>(PEER_CHANNEL_CAPACITY);

    // Add the MPSC (multi-producer, single consumer) channel for peer-thread-to-main communication
    let (to_main_tx, mut to_main_rx) = mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

    // Create handshake data
    let listen_addr_socket = SocketAddr::new(listen_addr, port);
    let own_handshake_data = HandshakeData {
        extra_values: HashMap::new(),
        listen_address: Some(listen_addr_socket),
        network,
        version: VERSION.to_string(),
    };

    // Connect to peers
    for peer in peers {
        let thread_arc = Arc::clone(&peer_map);
        let peer_broadcast_rx_clone: broadcast::Receiver<MainToPeerThread> =
            peer_broadcast_tx.subscribe();
        let to_main_tx_clone: mpsc::Sender<PeerThreadToMain> = to_main_tx.clone();
        let own_handshake_data_clone = own_handshake_data.clone();
        tokio::spawn(async move {
            initiate_connection(
                peer,
                thread_arc,
                peer_broadcast_rx_clone,
                to_main_tx_clone,
                &own_handshake_data_clone,
            )
            .await;
        });
    }

    // Start handling of mining
    let (from_miner_tx, mut from_miner_rx) =
        mpsc::channel::<FromMinerToMain>(MINER_CHANNEL_CAPACITY);
    let (to_miner_tx, to_miner_rx) = watch::channel::<ToMiner>(ToMiner::Empty);
    if mine && network == Network::RegTest {
        tokio::spawn(async move {
            mine::mock_regtest_mine(to_miner_rx, from_miner_tx)
                .await
                .map_err(|_e| anyhow!("Mining process stopped."))
                .expect("Error in mining thread.");
        });
    }

    // Handle incoming connections, messages from peer threads, and messages from the mining thread
    loop {
        select! {
            // The second item contains the IP and port of the new connection.
            Ok((stream, _)) = listener.accept() => {
                let thread_arc = Arc::clone(&peer_map);
                let from_main_rx_clone: broadcast::Receiver<MainToPeerThread> = peer_broadcast_tx.subscribe();
                let to_main_tx_clone: mpsc::Sender<PeerThreadToMain> = to_main_tx.clone();
                let peer_address = stream.peer_addr().unwrap();
                let own_handshake_data_clone = own_handshake_data.clone();
                tokio::spawn(async move {
                    match incoming_transaction(stream, thread_arc, peer_address, from_main_rx_clone, to_main_tx_clone, own_handshake_data_clone).await {
                        Ok(()) => (),
                        Err(err) => error!("Got error: {:?}", err),
                    }
                });
            }
            Some(msg) = to_main_rx.recv() => {
                info!("Received message sent to main thread.");
                match msg {
                    PeerThreadToMain::NewBlock(block) => {
                        if mine {
                            to_miner_tx.send(ToMiner::NewBlock(block))?;
                        }
                        // TODO: Share this block with other miners by sending broadcast to peer threads
                    }
                    PeerThreadToMain::NewTransaction(_txs) => {
                        error!("Unimplemented txs msg received");
                    }
                }
            }
            Some(main_message) = from_miner_rx.recv() => {
                match main_message {
                    FromMinerToMain::NewBlock(block) => {
                        info!("Miner found new block: {}", block.height);
                        peer_broadcast_tx.send(MainToPeerThread::NewBlock(block))?;
                        // TODO: Store block into own database
                    }
                }
            }
            // TODO: Add signal::ctrl_c/shutdown handling here
        }
    }
}

/// Loop for the peer threads. Awaits either a message from the peer over TCP,
/// or a message from main over the main-to-peer-threads broadcast channel.
pub async fn peer_loop<S>(
    mut serialized: S,
    mut from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<model::PeerThreadToMain>,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    peer_address: &SocketAddr,
) -> Result<()>
where
    S: Sink<PeerMessage> + TryStream<Ok = PeerMessage> + Unpin,
    <S as Sink<PeerMessage>>::Error: std::error::Error + Sync + Send + 'static,
{
    let mut peer_state_info = PeerStateData {
        highest_shared_block_height: 0,
    };

    // TODO: THV: own_state_info should be shared among all threads, I think.
    let mut own_state_info = PeerStateData {
        highest_shared_block_height: 0,
    };

    loop {
        select! {
            Ok(peer_message) = serialized.try_next() => {
                match peer_message {
                    None => {
                        info!("Peer closed connection.");
                        peer_map
                            .lock()
                            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                            .remove(peer_address)
                            .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                      peer_address));
                        break;
                    }
                    Some(PeerMessage::Bye) => {
                        info!("Got bye. Closing connection to peer");
                        peer_map
                            .lock()
                            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                            .remove(peer_address)
                            .unwrap_or_else(|| panic!("Failed to remove {} from peer map. Is peer map mangled?",
                                                       peer_address));
                        break;
                    }
                    Some(PeerMessage::PeerListRequest) => {
                        let peer_addresses = peer_map
                            .lock()
                            .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
                            .keys()
                            .cloned()
                            .collect();
                        serialized.send(PeerMessage::PeerListResponse(peer_addresses)).await?;
                    }
                    Some(PeerMessage::Block(block)) => {
                        info!("Got new block from peer, block height {}", block.height);
                        let new_block_height = block.height;
                        peer_state_info.highest_shared_block_height = new_block_height;
                        // TODO: All validation of block, increase ban score if block is bad
                        if own_state_info.highest_shared_block_height < new_block_height {
                            own_state_info.highest_shared_block_height = new_block_height;
                            // TODO: The following line *has* produced stack overflows on a lightweight
                            // computer. Why?
                            to_main_tx.send(PeerThreadToMain::NewBlock(block)).await?;
                            info!("Updated block info by block from peer. block height {}", new_block_height);
                        }
                    }
                    Some(PeerMessage::BlockNotification(block_notification)) => {
                        peer_state_info.highest_shared_block_height = block_notification.height;
                        if own_state_info.highest_shared_block_height < block_notification.height {
                            serialized.send(PeerMessage::BlockRequestByHeight(block_notification.height)).await?;
                            // TODO: Add logic to fetch, verify, and store response from peer
                            info!("Sent BlockRequestByHeight to peer");
                        }
                    }
                    Some(msg) => {
                        warn!("Uninplemented peer message received. Got: {:?}", msg);
                    }
                }
            }
            Ok(main_msg) = from_main_rx.recv() => {
                // info!("Got message from main: {:?}", main_msg);
                match main_msg {
                    MainToPeerThread::NewBlock(block) => {
                        info!("peer_loop got NewBlock message from main");
                        let new_block_height = block.height;
                        if new_block_height > peer_state_info.highest_shared_block_height {
                            peer_state_info.highest_shared_block_height = new_block_height;
                            serialized.send(PeerMessage::Block(block)).await?;
                        }
                    }
                    MainToPeerThread::NewTransaction(nt) => {
                        info!("peer_loop got NetTransaction message from main");
                        serialized.send(PeerMessage::NewTransaction(nt)).await?;
                    }
                }
            }
        }
    }

    Ok(())
}

#[instrument]
pub async fn outgoing_transaction<S>(
    stream: S,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    peer_address: std::net::SocketAddr,
    from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: &HandshakeData,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Debug + Unpin,
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
        .send(PeerMessage::Handshake((
            Vec::from(MAGIC_STRING_REQUEST),
            own_handshake_data.to_owned(),
        )))
        .await?;
    let peer_handshake_data: HandshakeData = match serialized.try_next().await? {
        Some(PeerMessage::Handshake((v, hsd))) if &v[..] == MAGIC_STRING_RESPONSE => {
            if hsd.network != own_handshake_data.network {
                bail!(
                    "Cannot connect with {}: Peer runs {}, this client runs {}.",
                    peer_address,
                    hsd.network,
                    own_handshake_data.network,
                );
            }
            debug!("Got correct magic value response!");
            hsd
        }
        v => {
            bail!("Expected magic value, got {:?}", v);
        }
    };

    // Add peer to peer map if not already there
    let new_peer = Peer {
        address: peer_address,
        banscore: 0,
        inbound: false,
        last_seen: SystemTime::now(),
        version: peer_handshake_data.version,
    };
    peer_map
        .lock()
        .unwrap_or_else(|e| panic!("Failed to lock peer map: {}", e))
        .entry(peer_address)
        .or_insert(new_peer);

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop(
        serialized,
        from_main_rx,
        to_main_tx,
        peer_map,
        &peer_address,
    )
    .await?;

    Ok(())
}

#[instrument]
pub async fn incoming_transaction<S>(
    stream: S,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    peer_address: std::net::SocketAddr,
    from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: HandshakeData,
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
    let peer_handshake_data: HandshakeData = match deserialized.try_next().await? {
        Some(PeerMessage::Handshake((v, hsd))) if &v[..] == MAGIC_STRING_REQUEST => {
            // Send handshake answer to peer
            deserialized
                .send(PeerMessage::Handshake((
                    MAGIC_STRING_RESPONSE.to_vec(),
                    own_handshake_data.clone(),
                )))
                .await?;

            // Verify peer network before moving on
            if hsd.network != own_handshake_data.network {
                bail!(
                    "Cannot connect with {}: Peer runs {}, this client runs {}.",
                    peer_address,
                    hsd.network,
                    own_handshake_data.network,
                );
            }
            debug!("Got correct magic value request!");
            hsd
        }
        v => {
            bail!("Expected magic value, got {:?}", v);
        }
    };

    // Add peer to peer map if not already there
    let new_peer = Peer {
        address: peer_address,
        banscore: 0,
        inbound: true,
        last_seen: SystemTime::now(),
        version: peer_handshake_data.version,
    };
    peer_map
        .lock()
        .map_err(|e| anyhow!("Failed to lock peer map: {}", e))?
        .entry(peer_address)
        .or_insert(new_peer);

    // Enter `peer_loop` to handle incoming peer messages/messages from main thread
    peer_loop(
        deserialized,
        from_main_rx,
        to_main_tx,
        peer_map,
        &peer_address,
    )
    .await?;

    Ok(())
}

#[instrument]
pub async fn initiate_connection(
    peer_address: std::net::SocketAddr,
    peer_map: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    from_main_rx: broadcast::Receiver<MainToPeerThread>,
    to_main_tx: mpsc::Sender<PeerThreadToMain>,
    own_handshake_data: &HandshakeData,
) {
    debug!("Attempting to initiate connection");
    match tokio::net::TcpStream::connect(peer_address).await {
        Err(e) => {
            warn!("Failed to establish connection: {}", e);
        }
        Ok(stream) => {
            match outgoing_transaction(
                stream,
                peer_map,
                peer_address,
                from_main_rx,
                to_main_tx,
                own_handshake_data,
            )
            .await
            {
                Ok(()) => (),
                Err(e) => error!("An error occurred: {}. Connection closing", e),
            }
        }
    };

    info!("Connection closing");
}

#[cfg(test)]
mod tests {
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
        let (to_main_tx, mut _to_main_rx1) =
            mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
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
        let (to_main_tx, mut _to_main_rx1) =
            mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
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
        let (to_main_tx, mut _to_main_rx1) =
            mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);
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
        let (to_main_tx, mut _to_main_rx1) =
            mpsc::channel::<PeerThreadToMain>(PEER_CHANNEL_CAPACITY);

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
}
