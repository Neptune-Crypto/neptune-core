use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::instrument;

/// Magic string to ensure other program is Neptune Core
pub const MAGIC_STRING: &[u8] = b"EDE8991A9C599BE908A759B6BF3279CD";

#[instrument]
pub async fn run<S>(mut stream: S) -> Result<()>
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufWriter;

    #[tokio::test]
    async fn test_run() -> Result<()> {
        use std::io::Cursor;
        let mut buffer = Cursor::new(vec![0; 100]);
        buffer.write(MAGIC_STRING);
        buffer.set_position(0);
        run(&mut buffer).await?;
        buffer.set_position(0);
        let mut res = [0; 1024];
        let bytes = buffer.read(&mut res);
        assert_eq!(&res[..], &b"Hello Neptune!\n"[..]);

        Ok(())
    }
}
