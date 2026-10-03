//! Notifications from `neptune-core`.
//!
//! `neptune-core` runs a command on every new block, mempool transaction and
//! block proposal. `neptune-defi` sets that command to
//! `neptune-defi notify <port> <kind> <id>`, which connects to the running
//! `neptune-defi` on a local port and sends one line, `<kind> <id>`.
//!
//! A notification is a hint, not a fact: any local process can connect to the
//! port. Whoever acts on one reads the block, transaction or proposal it names
//! from the node.

use std::fmt;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use neptune_defi::plugin::Kind;
use neptune_defi::plugin::Notification;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// The first argument of the command `neptune-core` runs.
pub(crate) const SUBCOMMAND: &str = "notify";

/// The longest line a notification can be: the longest kind, a space, and a
/// digest in hex.
const MAX_LINE_LENGTH: u64 = 128;

/// The `neptune-core` flag that runs the notify command for `kind`.
fn flag(kind: Kind) -> &'static str {
    match kind {
        Kind::Block => "--block-notify",
        Kind::Tx => "--tx-notify",
        Kind::Proposal => "--proposal-notify",
    }
}

/// Why `neptune-defi` cannot have `neptune-core` notify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommandError {
    /// `neptune-core` groups words between double quotes, and no character
    /// escapes another, so the path to the executable may not contain a double
    /// quote.
    QuoteInPath(String),

    /// The path to the executable is not valid UTF-8.
    NotUtf8,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuoteInPath(path) => write!(
                f,
                "neptune-core runs neptune-defi to notify it, and cannot run a \
                 program whose path contains a double quote. Please move or link \
                 neptune-defi to a path without one; it is now at {path:?}."
            ),
            Self::NotUtf8 => write!(
                f,
                "neptune-core runs neptune-defi to notify it, which needs the \
                 path to neptune-defi to be valid UTF-8."
            ),
        }
    }
}

/// The `neptune-core` flags that make it notify `executable` on `port`, one
/// per [`Kind`].
///
/// `neptune-core` splits a notify command into words at spaces outside double
/// quotes, so a path containing a space is quoted. A path without one is not,
/// because a `neptune-core` older than that rule splits at every space and
/// would keep the quotes as part of the path.
pub(crate) fn notify_flags(executable: &Path, port: u16) -> Result<Vec<String>, CommandError> {
    let path = executable.to_str().ok_or(CommandError::NotUtf8)?;
    if path.contains('"') {
        return Err(CommandError::QuoteInPath(path.to_owned()));
    }
    let path = if path.contains(' ') {
        format!("\"{path}\"")
    } else {
        path.to_owned()
    };

    Ok(Kind::ALL
        .into_iter()
        .map(|kind| format!("{}={path} {SUBCOMMAND} {port} {kind} %s", flag(kind)))
        .collect())
}

/// The `notify` subcommand: send `<kind> <id>` to the `neptune-defi` listening
/// on `port`, given the arguments after `notify`.
pub(crate) fn send(args: &[String]) -> Result<(), String> {
    let [port, kind, id] = args else {
        return Err(format!(
            "usage: neptune-defi {SUBCOMMAND} <port> <kind> <id>"
        ));
    };
    let port = port
        .parse::<u16>()
        .map_err(|e| format!("port {port:?}: {e}"))?;
    let notification = format!("{kind} {id}")
        .parse::<Notification>()
        .map_err(|()| format!("not a notification: {kind} {id}"))?;

    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|e| format!("cannot reach neptune-defi on {address}: {e}"))?;
    writeln!(stream, "{notification}").map_err(|e| e.to_string())
}

/// A listener for notifications, on a port of the operating system's choice.
pub(crate) async fn bind() -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await
}

/// Accept notifications on `listener` and send each to `notifications`, until
/// the receiver is dropped.
///
/// Every connection carries one line. A line that is not a notification is
/// dropped, and so is a connection that sends more than one notification's
/// worth of bytes. Since `neptune-core` starts a process per notification,
/// notifications sent close together may arrive in either order.
pub(crate) async fn listen(
    listener: TcpListener,
    notifications: mpsc::UnboundedSender<Notification>,
) {
    while !notifications.is_closed() {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let notifications = notifications.clone();
        tokio::spawn(async move {
            let mut line = String::new();
            let mut reader = BufReader::new(stream.take(MAX_LINE_LENGTH));
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            if let Ok(notification) = line.trim_end().parse() {
                let _ = notifications.send(notification);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use neptune_defi::tasm_lib::prelude::Digest;

    use super::*;

    fn digest() -> Digest {
        rand::random()
    }

    #[test]
    fn a_notify_flag_per_kind_runs_neptune_defi_on_the_port() {
        let flags = notify_flags(&PathBuf::from("/usr/bin/neptune-defi"), 4321).unwrap();
        assert_eq!(
            vec![
                "--block-notify=/usr/bin/neptune-defi notify 4321 block %s",
                "--tx-notify=/usr/bin/neptune-defi notify 4321 tx %s",
                "--proposal-notify=/usr/bin/neptune-defi notify 4321 proposal %s",
            ],
            flags
        );
    }

    #[test]
    fn a_path_with_a_space_is_quoted() {
        for path in [
            r"/opt/neptune defi/neptune-defi",
            r"C:\Program Files\Neptune\neptune-defi.exe",
        ] {
            let flags = notify_flags(&PathBuf::from(path), 4321).unwrap();
            assert_eq!(
                format!("--block-notify=\"{path}\" notify 4321 block %s"),
                flags[0]
            );
        }
    }

    #[test]
    fn a_path_with_a_double_quote_is_refused() {
        let path = r#"/opt/"neptune"/neptune-defi"#;
        assert_eq!(
            Err(CommandError::QuoteInPath(path.to_owned())),
            notify_flags(&PathBuf::from(path), 4321)
        );
    }

    #[tokio::test]
    async fn a_sent_notification_is_received() {
        let listener = bind().await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        tokio::spawn(listen(listener, sender));

        let sent = Notification {
            kind: Kind::Proposal,
            id: digest(),
        };
        let args = [port.to_string(), "proposal".to_owned(), sent.id.to_hex()];
        tokio::task::spawn_blocking(move || send(&args))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(Some(sent), receiver.recv().await);
    }

    #[test]
    fn send_refuses_malformed_arguments() {
        let hex = digest().to_hex();
        for args in [
            vec![],
            vec!["1".to_owned(), "block".to_owned()],
            vec!["port".to_owned(), "block".to_owned(), hex.clone()],
            vec!["1".to_owned(), "nonsense".to_owned(), hex.clone()],
            vec!["1".to_owned(), "block".to_owned(), "nonsense".to_owned()],
        ] {
            assert!(send(&args).is_err(), "{args:?}");
        }
    }
}
