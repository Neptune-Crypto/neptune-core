use anyhow::{bail, Result};
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_serde::formats::*;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

mod model;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING_REQUEST: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";
pub const MAGIC_STRING_RESPONSE: &[u8] = b"Hello Neptune!\n";

#[instrument]
pub async fn outgoing_transaction<S>(stream: S) -> Result<()>
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

    if let Some(msg) = &mut serialized.try_next().await? {
        info!("Got response {:?}", msg);
    }

    serialized.send(model::Message::Bye).await?;

    Ok(())
}

#[instrument]
pub async fn incoming_transaction<S>(stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    info!("Established connection");

    let length_delimited = Framed::new(stream, LengthDelimitedCodec::new());

    // Deserialize frames
    let mut deserialized = tokio_serde::SymmetricallyFramed::new(
        length_delimited,
        SymmetricalBincode::<model::Message>::default(),
    );

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
pub async fn initiate_connection(peer_address: std::net::SocketAddr) {
    debug!("Attempting to initiate connection");
    match tokio::net::TcpStream::connect(peer_address).await {
        Err(e) => {
            warn!("Failed to establish connection: {}", e);
        }
        Ok(stream) => match outgoing_transaction(stream).await {
            Ok(()) => (),
            Err(e) => error!("An error occurred: {}. Connection closing", e),
        },
    };

    info!("Connection closing");
}

#[instrument]
pub async fn receive_connection(stream: TcpStream) {
    info!("Connection established");

    match incoming_transaction(stream).await {
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
    use tokio_serde::Serializer;
    use tokio_test::io::Builder;
    use tokio_util::codec::Encoder;

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
        let mock = Builder::new()
            .read(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_REQUEST.to_vec(),
            ))?)
            .write(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_RESPONSE.to_vec(),
            ))?)
            .read(&to_bytes(&model::Message::Bye)?)
            .build();

        incoming_transaction(mock).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_incoming_transaction_fail() -> Result<()> {
        let mock = Builder::new()
            .read(&to_bytes(&model::Message::MagicValue(
                MAGIC_STRING_RESPONSE.to_vec(),
            ))?)
            .build();

        if let Err(_) = incoming_transaction(mock).await {
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

        outgoing_transaction(mock).await?;

        Ok(())
    }
}
