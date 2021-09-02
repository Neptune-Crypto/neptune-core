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
    use std::convert::TryInto;

    #[tokio::test]
    async fn test_run_succeed() -> Result<()> {
        use std::io::Cursor;
        let mut buffer = Cursor::new(Vec::new());
        buffer.write(MAGIC_STRING).await?;
        buffer.set_position(0);

        run(&mut buffer).await?;

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

        if let Err(_) = run(&mut buffer).await {
            Ok(())
        } else {
            bail!("Expected error from run")
        }
    }
}
