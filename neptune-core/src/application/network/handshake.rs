use std::future::Future;
use std::pin::Pin;

use futures::AsyncRead;
use futures::AsyncReadExt;
use futures::AsyncWrite;
use futures::AsyncWriteExt;
use libp2p::core::upgrade::InboundUpgrade;
use libp2p::core::upgrade::OutboundUpgrade;
use libp2p::core::upgrade::UpgradeInfo;
use libp2p::Stream;
use libp2p::StreamProtocol;

use crate::protocol::peer::handshake_data::HandshakeData;
use crate::protocol::peer::handshake_data::HandshakeValidationError;

/// The protocol negotiation and handshake logic for a stream.
///
/// The [`HandshakeUpgrade`] is a blueprint for libp2p to "upgrade" a raw socket
/// into a verified connection. It carries the `local_handshake` so it can be
/// transmitted to the remote peer during the negotiation phase.
pub(crate) struct HandshakeUpgrade {
    pub(crate) local_handshake: HandshakeData,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HandshakeError {
    #[error("IO Error({0})")]
    IO(#[from] std::io::Error),

    #[error("ValidationError({0})")]
    Validation(#[from] HandshakeValidationError),
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
        Self::encode_handshake(&mut socket, &self.local_handshake)
            .await
            .map_err(HandshakeError::IO)?;

        // Receive peer's handshake
        let remote_handshake = Self::decode_handshake(&mut socket)
            .await
            .map_err(HandshakeError::IO)?;

        match HandshakeData::validate(&self.local_handshake, &remote_handshake) {
            Ok(()) => (),
            Err(e) => {
                tracing::warn!("Handshake failed: {e}.");
                return Err(HandshakeError::Validation(e));
            }
        };

        // Return data and the socket. The socket is now "upgraded" and
        // ready for use.
        Ok((remote_handshake, socket))
    }

    /// Serializes handshake using Bincode with a 4-byte length prefix.
    async fn encode_handshake<S>(socket: &mut S, data: &HandshakeData) -> std::io::Result<()>
    where
        S: AsyncWrite + Unpin,
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
    async fn decode_handshake<S>(socket: &mut S) -> std::io::Result<HandshakeData>
    where
        S: AsyncRead + Unpin,
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
        HandshakeUpgrade::encode_handshake(&mut write_cursor, &handshake)
            .await
            .expect("Failed to encode default handshake");

        // 3. Prepare to read from the same buffer.
        let mut read_cursor = Cursor::new(buffer);

        // 4. Decode the data back out.
        let decoded = HandshakeUpgrade::decode_handshake(&mut read_cursor)
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

        HandshakeUpgrade::encode_handshake(&mut write_cursor, &handshake)
            .await
            .expect("not only is encoding guaranteed to not crash, it must be successful too");
    }

    #[proptest(cases = 10, async = "tokio")]
    async fn handshake_decoding_cannot_crash(
        #[strategy(vec(arb::<u8>(), 0..4096))] buffer: Vec<u8>,
    ) {
        let mut read_cursor = Cursor::new(buffer);

        // just not crash
        let _ = HandshakeUpgrade::decode_handshake(&mut read_cursor).await;
    }
}
