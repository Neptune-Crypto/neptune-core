use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures::AsyncRead;
use futures::AsyncReadExt;
use futures::AsyncWrite;
use futures::AsyncWriteExt;
use libp2p::core::upgrade::InboundUpgrade;
use libp2p::core::upgrade::OutboundUpgrade;
use libp2p::core::upgrade::UpgradeInfo;
use libp2p::Stream;
use libp2p::StreamProtocol;
use neptune_p2p::peer::handshake_data::HandshakeData;
use neptune_p2p::peer::handshake_data::HandshakeValidationError;
use neptune_p2p::peer::handshake_pow::Challenge;
use neptune_p2p::peer::handshake_pow::ChallengeError;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// The protocol negotiation and handshake logic for a stream.
///
/// The [`HandshakeUpgrade`] is a blueprint for libp2p to "upgrade" a raw socket
/// into a verified connection. It carries the `local_handshake` so it can be
/// transmitted to the remote peer during the negotiation phase.
pub(crate) struct HandshakeUpgrade {
    pub(crate) local_handshake: HandshakeData,

    /// The proof-of-work challenge we issue, carried in our handshake's
    /// `extra_data`. `Some` iff our node is the listener.
    challenge: Option<Challenge>,
}

/// How long the dialer will spend solving.
const POW_SOLVE_TIMEOUT: Duration = Duration::from_secs(6);

/// How long the listener waits for a solution. Exceeds the solve timeout so
/// that an honest dialer is not cut off in flight.
const POW_SOLUTION_TIMEOUT: Duration = Duration::from_secs(9);

impl HandshakeUpgrade {
    pub(crate) fn dialer(local_handshake: HandshakeData) -> Self {
        Self {
            local_handshake,
            challenge: None,
        }
    }

    pub(crate) fn listener(mut local_handshake: HandshakeData, challenge: Challenge) -> Self {
        local_handshake.extra_data = challenge.to_extra_data();
        Self {
            local_handshake,
            challenge: Some(challenge),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HandshakeError {
    #[error("IO Error({0})")]
    IO(#[from] std::io::Error),

    #[error("ValidationError({0})")]
    Validation(#[from] HandshakeValidationError),

    #[error("proof of work rejected")]
    ProofOfWork,

    #[error("proof of work timed out")]
    Timeout,

    #[error("{0}")]
    Challenge(#[from] ChallengeError),
}

impl HandshakeUpgrade {
    /// Perform the symmetric handshake exchange over the provided stream.
    ///
    /// This function encapsulates the core I/O logic: sending our local
    /// handshake and receiving the remote handshake. After decoding the remote
    /// handshake, the remote handshake and now-verified socket are returned.
    ///
    /// Both [`Self::upgrade_inbound`] and [`Self::upgrade_outbound`] invoke
    /// this function. Factoring out the symmetric handshake creates a single
    /// source of truth for the protocol's wire-format, and prevents logic
    /// mismatches between dialers and listeners.
    async fn handshake<C>(&self, mut socket: C) -> Result<(HandshakeData, C), HandshakeError>
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Send local handshake
        Self::encode_frame(&mut socket, &self.local_handshake)
            .await
            .map_err(HandshakeError::IO)?;

        // Receive peer's handshake
        let remote_handshake: HandshakeData = Self::decode_frame(&mut socket)
            .await
            .map_err(HandshakeError::IO)?;

        match HandshakeData::validate(&self.local_handshake, &remote_handshake) {
            Ok(()) => (),
            Err(e) => {
                tracing::warn!("Handshake failed: {e}.");
                return Err(HandshakeError::Validation(e));
            }
        };

        match self.challenge {
            None => {
                if let Some(challenge) = Challenge::parse(&remote_handshake.extra_data)? {
                    // We initiated this connection, and peer sent a PoW challenge
                    // that we must solve, or refuse to solve.
                    let solve = tokio::task::spawn_blocking(move || challenge.solve());
                    let nonce = tokio::time::timeout(POW_SOLVE_TIMEOUT, solve)
                        .await
                        .map_err(|_| HandshakeError::Timeout)?
                        .map_err(std::io::Error::other)?;
                    Self::encode_frame(&mut socket, &nonce).await?;
                }
            }
            Some(challenge) => {
                if remote_handshake.version.supports_handshake_pow() {
                    // Peer initiated the connection, and we sent peer a challenge
                    // through the handshake. Peer must solve it within the timeout.
                    let nonce: u64 =
                        tokio::time::timeout(POW_SOLUTION_TIMEOUT, Self::decode_frame(&mut socket))
                            .await
                            .map_err(|_| HandshakeError::Timeout)??;
                    if !challenge.verify(nonce) {
                        tracing::warn!("Handshake failed: proof of work rejected.");
                        return Err(HandshakeError::ProofOfWork);
                    }
                } else {
                    // Peer initiated the connection but their version does not
                    // support or understand the PoW handshake protocol. Don't
                    // demand a solution as connections to these peers will be
                    // prevented after activation of HF-delta.
                }
            }
        }

        // Return data and the socket. The socket is now "upgraded" and
        // ready for use.
        Ok((remote_handshake, socket))
    }

    /// Serializes a frame using Bincode with a 4-byte length prefix.
    async fn encode_frame<S, T>(socket: &mut S, data: &T) -> std::io::Result<()>
    where
        S: AsyncWrite + Unpin,
        T: Serialize,
    {
        // Bincode serialization
        let buffer = bincode::serialize(data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Write length prefix (Big Endian)
        let len = buffer.len() as u32;
        socket.write_all(&len.to_be_bytes()).await?;

        // Write actual bytes
        socket.write_all(&buffer).await?;
        socket.flush().await?;

        Ok(())
    }

    /// Reads length prefix and deserializes Bincode bytes.
    async fn decode_frame<S, T>(socket: &mut S) -> std::io::Result<T>
    where
        S: AsyncRead + Unpin,
        T: DeserializeOwned,
    {
        let mut len_bytes = [0u8; 4];
        socket.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // OOM Protection
        if len > 512 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Handshake too large",
            ));
        }

        let mut buffer = vec![0u8; len];
        socket.read_exact(&mut buffer).await?;

        // Bincode deserialization
        bincode::deserialize(&buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl UpgradeInfo for HandshakeUpgrade {
    type Info = StreamProtocol;
    type InfoIter = std::iter::Once<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        std::iter::once(StreamProtocol::new("/id/stream-gateway-handshake/1.0"))
    }
}

impl<C> InboundUpgrade<C> for HandshakeUpgrade
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (HandshakeData, C);
    type Error = HandshakeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    /// Execute the handshake logic for an incoming substream.
    fn upgrade_inbound(self, socket: C, _info: Self::Info) -> Self::Future {
        Box::pin(async move { self.handshake(socket).await })
    }
}

impl<C> OutboundUpgrade<C> for HandshakeUpgrade
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = (HandshakeData, C);
    type Error = HandshakeError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    /// Execute the handshake logic for an outgoing substream.
    fn upgrade_outbound(self, socket: C, _info: Self::Info) -> Self::Future {
        Box::pin(async move { self.handshake(socket).await })
    }
}

/// The outcome of a completed protocol handshake.
///
/// This enum encapsulates the successful handshake-exchange with a remote peer.
/// It acts as the final hand-off mechanism between the low-level
/// [`HandshakeUpgrade`] and the higher-level
/// [`StreamGateway`](super::gateway::StreamGateway).
#[derive(Debug)]
pub(crate) enum HandshakeResult {
    /// The handshake was successful.
    ///
    /// This variant carries both the peer's handshake and the communication
    /// channel itself, ensuring they are never separated.
    Success {
        remote_handshake: HandshakeData,
        stream: Stream,
    },
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use proptest::collection::vec;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest(cases = 10, async = "tokio")]
    async fn handshake_encoding_roundtrip(
        #[strategy(HandshakeData::arbitrary())] handshake: HandshakeData,
    ) {
        // 1. Prepare an in-memory "socket" (a buffer).
        let mut buffer = Vec::new();
        let mut write_cursor = Cursor::new(&mut buffer);

        // 2. Encode the data into the buffer.
        HandshakeUpgrade::encode_frame(&mut write_cursor, &handshake)
            .await
            .expect("Failed to encode default handshake");

        // 3. Prepare to read from the same buffer.
        let mut read_cursor = Cursor::new(buffer);

        // 4. Decode the data back out.
        let decoded: HandshakeData = HandshakeUpgrade::decode_frame(&mut read_cursor)
            .await
            .expect("Failed to decode handshake from buffer");

        // 5. Verify the data is identical.
        prop_assert_eq!(
            handshake,
            decoded,
            "The decoded data must match the default data sent."
        );
    }

    #[proptest(cases = 10, async = "tokio")]
    async fn handshake_encoding_cannot_crash(
        #[strategy(HandshakeData::arbitrary())] handshake: HandshakeData,
    ) {
        let mut buffer = Vec::new();
        let mut write_cursor = Cursor::new(&mut buffer);

        HandshakeUpgrade::encode_frame(&mut write_cursor, &handshake)
            .await
            .expect("not only is encoding guaranteed to not crash, it must be successful too");
    }

    #[proptest(cases = 10, async = "tokio")]
    async fn handshake_decoding_cannot_crash(
        #[strategy(vec(arb::<u8>(), 0..4096))] buffer: Vec<u8>,
    ) {
        let mut read_cursor = Cursor::new(buffer);

        // just not crash
        let _ = HandshakeUpgrade::decode_frame::<_, HandshakeData>(&mut read_cursor).await;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod pow_tests {
    use neptune_p2p::peer::handshake_data::VersionString;
    use neptune_p2p::peer::handshake_pow::MAX_HANDSHAKE_POW_BITS;
    use neptune_primitives::network::Network;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;
    use crate::tests::shared::globalstate::get_dummy_handshake_data_for_genesis;

    type Outcome = Result<HandshakeData, HandshakeError>;

    async fn run(
        dialer: HandshakeData,
        listener: HandshakeData,
        challenge: Challenge,
    ) -> (Outcome, Outcome) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let dial = HandshakeUpgrade::dialer(dialer);
        let listen = HandshakeUpgrade::listener(listener, challenge);
        let (d, l) = tokio::join!(dial.handshake(a.compat()), listen.handshake(b.compat()));
        (d.map(|(h, _)| h), l.map(|(h, _)| h))
    }

    #[tokio::test]
    async fn dialer_solves_and_listener_accepts() {
        let dialer = get_dummy_handshake_data_for_genesis(Network::Main);
        let listener = get_dummy_handshake_data_for_genesis(Network::Main);
        let (d, l) = run(dialer, listener, Challenge::random()).await;
        assert_eq!(listener.instance_id, d.unwrap().instance_id);
        assert_eq!(dialer, l.unwrap());
    }

    #[tokio::test]
    async fn an_old_dialer_is_not_challenged() {
        let mut dialer = get_dummy_handshake_data_for_genesis(Network::Main);
        dialer.version = VersionString::new_from_str("0.16.0");
        let listener = get_dummy_handshake_data_for_genesis(Network::Main);
        let (d, l) = run(dialer, listener, Challenge::random()).await;
        assert_eq!(listener.instance_id, d.unwrap().instance_id);
        assert_eq!(dialer, l.unwrap());
    }

    #[tokio::test]
    async fn an_excessive_difficulty_is_refused_without_solving() {
        let dialer = get_dummy_handshake_data_for_genesis(Network::Main);
        let listener = get_dummy_handshake_data_for_genesis(Network::Main);
        let too_hard = Challenge {
            bits: MAX_HANDSHAKE_POW_BITS + 1,
            ..Challenge::random()
        };
        let started = std::time::Instant::now();
        let (d, l) = run(dialer, listener, too_hard).await;
        assert!(
            matches!(
                d,
                Err(HandshakeError::Challenge(ChallengeError::TooHard(_)))
            ),
            "{d:?}"
        );
        assert!(l.is_err());
        assert!(started.elapsed() < POW_SOLVE_TIMEOUT);
    }

    #[tokio::test]
    async fn a_wrong_solution_is_rejected() {
        let dialer = get_dummy_handshake_data_for_genesis(Network::Main);
        let listener = get_dummy_handshake_data_for_genesis(Network::Main);
        let (a, mut b) = tokio::io::duplex(64 * 1024);
        let listen = HandshakeUpgrade::listener(listener, Challenge::random());
        let listener_task = tokio::spawn(async move { listen.handshake(a.compat()).await });

        let mut socket = (&mut b).compat();
        HandshakeUpgrade::encode_frame(&mut socket, &dialer)
            .await
            .unwrap();
        let remote: HandshakeData = HandshakeUpgrade::decode_frame(&mut socket).await.unwrap();
        let challenge = Challenge::parse(&remote.extra_data).unwrap().unwrap();
        let wrong = (0..).find(|&n| !challenge.verify(n)).unwrap();
        HandshakeUpgrade::encode_frame(&mut socket, &wrong)
            .await
            .unwrap();

        let outcome = listener_task.await.unwrap();
        assert!(
            matches!(outcome, Err(HandshakeError::ProofOfWork)),
            "{outcome:?}"
        );
    }
}
