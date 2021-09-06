use anyhow::Result;
use futures::sink::SinkExt;
use futures::stream::TryStreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_serde::formats::*;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, error, info, instrument, warn};

mod model;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";

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
        .send(model::Message::MagicValue(Vec::from(MAGIC_STRING)))
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

    // Spawn a task that prints all received messages to STDOUT
    loop {
        match deserialized.try_next().await? {
            Some(model::Message::MagicValue(v)) if &v[..] == MAGIC_STRING => {
                info!("Got correct magic value!");
                deserialized.send(model::Message::NewBlock(42)).await?;
            }
            Some(msg) => {
                info!("Got some other value: {:?}", msg);
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
    use std::convert::TryInto;

    #[tokio::test]
    async fn test_run_succeed() -> Result<()> {
        use std::io::Cursor;
        let mut buffer = Cursor::new(Vec::new());
        buffer.write(MAGIC_STRING).await?;
        buffer.set_position(0);

        incoming_transaction(&mut buffer).await?;

        buffer.set_position(MAGIC_STRING.len().try_into().unwrap());
        let mut res = [0; 1024];
        let bytes = buffer.read(&mut res).await?;
        assert_eq!(&res[..bytes], &b"Hello Neptune!\n"[..]);

        Ok(())
    }

    #[tokio::test]
    async fn test_run_fail() -> Result<()> {
        let s = b"BLABLABLA";
        use std::io::Cursor;
        let mut buffer = Cursor::new(Vec::with_capacity(MAGIC_STRING.len()));
        buffer.write(&s[..]).await?;
        buffer.set_position(0);

        if let Err(_) = incoming_transaction(&mut buffer).await {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }
}
