use anyhow::{bail, Result};
use std::str;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, instrument, warn};

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";

#[instrument]
pub async fn outgoing_transaction<S>(mut stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    info!("Established connection");
    stream.write_all(MAGIC_STRING).await?;

    let mut buffer = [0; 1024];
    let len: usize = stream.read(&mut buffer).await?;
    let response_string = match str::from_utf8(&buffer[..len]) {
        Ok(v) => v,
        Err(e) => bail!("Invalid UTF-8 sequence: {}", e),
    };
    info!("Got response {}", response_string);

    Ok(())
}

#[instrument]
pub async fn incoming_transaction<S>(mut stream: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + std::fmt::Debug + std::marker::Unpin,
{
    let mut buffer = [0; 1024];

    let len = stream.read(&mut buffer).await?;

    if !buffer.starts_with(MAGIC_STRING) {
        bail!("Invalid magic string: {:?}", &buffer[..len]);
    }

    let response = "Hello Neptune!\n";

    stream.write_all(response.as_bytes()).await?;

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
