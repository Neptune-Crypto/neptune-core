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

    loop {
        match deserialized.try_next().await? {
            Some(model::Message::MagicValue(v)) if &v[..] == MAGIC_STRING_REQUEST => {
                debug!("Got correct magic value!");
                deserialized
                    .send(model::Message::MagicValue(MAGIC_STRING_RESPONSE.to_vec()))
                    .await?;
            }
            Some(_) => {
                warn!("Got bad magic value!");
                bail!("Got bad magic value!");
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
    use anyhow::bail;
    use std::io::{Cursor, Read};
    use std::pin::Pin;
    use tokio_serde::Serializer;

    async fn get_transport(
        message: &model::Message,
    ) -> tokio_util::codec::Framed<Cursor<Vec<u8>>, tokio_util::codec::LengthDelimitedCodec> {
        let mut transport = Framed::new(Cursor::new(Vec::new()), LengthDelimitedCodec::new());
        let mut formating = SymmetricalBincode::<model::Message>::default();
        let bytes = Pin::new(&mut formating).serialize(message).unwrap();
        let frame = bytes::Bytes::from(bytes);
        transport.send(frame).await.unwrap();

        transport
    }

    #[tokio::test]
    async fn test_run_succeed() -> Result<()> {
        let transport =
            get_transport(&model::Message::MagicValue(MAGIC_STRING_REQUEST.to_vec())).await;
        let mut buffer: Cursor<Vec<u8>> = transport.into_inner();
        let request_length = buffer.position();
        buffer.set_position(0);
        incoming_transaction(&mut buffer).await?;
        buffer.set_position(request_length);
        let mut res = [0; 1024];
        let bytes = buffer.read(&mut res).unwrap();

        let expected_transport =
            get_transport(&model::Message::MagicValue(MAGIC_STRING_RESPONSE.to_vec())).await;
        let mut expected_buffer = expected_transport.into_inner();
        expected_buffer.set_position(0);
        let mut expected_res = [0; 1024];
        let expected_bytes = expected_buffer.read(&mut expected_res).unwrap();

        assert_eq!(expected_res[..expected_bytes], res[..bytes]);

        Ok(())
    }

    #[tokio::test]
    async fn test_run_fail() -> Result<()> {
        let transport = get_transport(&model::Message::MagicValue(b"BLABLABLA".to_vec())).await;
        let mut buffer: Cursor<Vec<u8>> = transport.into_inner();
        buffer.set_position(0);
        if let Err(_) = incoming_transaction(&mut buffer).await {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }
}
