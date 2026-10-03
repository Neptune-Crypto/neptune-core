//! The plugins connected to `neptune-defi`, one task per plugin.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use neptune_defi::plugin::FromPlugin;
use neptune_defi::plugin::Hello;
use neptune_defi::plugin::Notification;
use neptune_defi::plugin::ToPlugin;
use neptune_defi::plugin::Welcome;
use neptune_defi::plugin::PROTOCOL_VERSION;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::broadcast;

/// How many notifications a plugin may fall behind by before the oldest are
/// dropped for it.
pub(crate) const BACKLOG: usize = 1024;

/// How long a plugin has, after connecting, to send its hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest hello `neptune-defi` reads.
const MAX_HELLO_LENGTH: u64 = 64 * 1024;

/// What every plugin is told, and what it must prove.
#[derive(Debug, Clone)]
pub(crate) struct Terms {
    /// The plugin cookie, in hex.
    pub(crate) cookie: Arc<str>,

    /// Where `neptune-core` serves JSON-RPC.
    pub(crate) rpc: SocketAddr,
}

/// Accept plugins on `listener` and serve each in a task of its own, with the
/// notifications sent on `notifications`.
pub(crate) async fn serve(
    listener: TcpListener,
    terms: Terms,
    notifications: broadcast::Sender<Notification>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };

        // Subscribing before the handshake keeps the notifications sent
        // during it, so a welcomed plugin misses none sent after it connected.
        let receiver = notifications.subscribe();
        tokio::spawn(serve_one(stream, terms.clone(), receiver));
    }
}

/// Serve one plugin: shake hands, then send it every notification of a kind it
/// subscribed to, until it disconnects.
///
/// A plugin is refused, and the connection closed, if its first line does not
/// arrive within [`HELLO_TIMEOUT`], or is not a hello, or names another
/// protocol version, or carries the wrong cookie. A plugin that falls more
/// than [`BACKLOG`] notifications behind is sent [`ToPlugin::Lagged`] in place
/// of the ones dropped for it.
//
// ponytail: a plugin that disconnects is noticed only when the next
// notification for it cannot be written. Read from the plugin too once it has
// anything to say after its hello.
async fn serve_one(
    stream: TcpStream,
    terms: Terms,
    mut notifications: broadcast::Receiver<Notification>,
) {
    let (read, mut write) = stream.into_split();
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, read_hello(read)).await {
        Ok(hello) => hello,
        Err(_) => Err("no hello within 5 seconds".to_owned()),
    };
    let hello = match hello.and_then(|hello| accept(hello, &terms)) {
        Ok(hello) => hello,
        Err(reason) => {
            let _ = send(&mut write, &ToPlugin::Refused(reason)).await;
            return;
        }
    };

    let welcome = ToPlugin::Welcome(Welcome {
        protocol: PROTOCOL_VERSION,
        rpc: terms.rpc,
    });
    if send(&mut write, &welcome).await.is_err() {
        return;
    }
    eprintln!("neptune-defi: plugin {:?} connected", hello.name);

    loop {
        let message = match notifications.recv().await {
            Ok(notification) if hello.subscribe.contains(&notification.kind) => {
                ToPlugin::Notification(notification)
            }
            Ok(_) => continue,
            Err(broadcast::error::RecvError::Lagged(dropped)) => ToPlugin::Lagged(dropped),
            Err(broadcast::error::RecvError::Closed) => return,
        };
        if send(&mut write, &message).await.is_err() {
            eprintln!("neptune-defi: plugin {:?} disconnected", hello.name);
            return;
        }
    }
}

/// The plugin's first line, as a hello.
async fn read_hello(read: impl tokio::io::AsyncRead + Unpin) -> Result<Hello, String> {
    let mut line = String::new();
    BufReader::new(read.take(MAX_HELLO_LENGTH))
        .read_line(&mut line)
        .await
        .map_err(|error| error.to_string())?;
    match serde_json::from_str(&line) {
        Ok(FromPlugin::Hello(hello)) => Ok(hello),
        Err(error) => Err(format!("not a hello: {error}")),
    }
}

/// `hello`, if it speaks this protocol and carries the cookie.
fn accept(hello: Hello, terms: &Terms) -> Result<Hello, String> {
    if hello.protocol != PROTOCOL_VERSION {
        return Err(format!(
            "protocol {} is not supported; neptune-defi speaks {PROTOCOL_VERSION}",
            hello.protocol
        ));
    }
    if hello.cookie != *terms.cookie {
        return Err("wrong cookie".to_owned());
    }

    Ok(hello)
}

/// Write `message` as one line of JSON.
async fn send(write: &mut (impl AsyncWrite + Unpin), message: &ToPlugin) -> std::io::Result<()> {
    let mut line = serde_json::to_string(message).expect("a message serializes");
    line.push('\n');
    write.write_all(line.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use neptune_defi::plugin::Kind;
    use neptune_defi::tasm_lib::prelude::Digest;
    use tokio::io::AsyncBufReadExt;
    use tokio::io::BufReader;
    use tokio::io::Lines;
    use tokio::net::tcp::OwnedReadHalf;
    use tokio::net::tcp::OwnedWriteHalf;

    use super::*;

    const COOKIE: &str = "c0ffee";

    struct Server {
        address: SocketAddr,
        notifications: broadcast::Sender<Notification>,
    }

    async fn server() -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (notifications, _) = broadcast::channel(4);
        let terms = Terms {
            cookie: COOKIE.into(),
            rpc: "127.0.0.1:9797".parse().unwrap(),
        };
        tokio::spawn(serve(listener, terms, notifications.clone()));
        Server {
            address,
            notifications,
        }
    }

    struct Plugin {
        lines: Lines<BufReader<OwnedReadHalf>>,
        write: OwnedWriteHalf,
    }

    impl Plugin {
        async fn connect(server: &Server) -> Self {
            let (read, write) = TcpStream::connect(server.address)
                .await
                .unwrap()
                .into_split();
            Self {
                lines: BufReader::new(read).lines(),
                write,
            }
        }

        async fn send_line(&mut self, line: &str) {
            self.write
                .write_all(format!("{line}\n").as_bytes())
                .await
                .unwrap();
        }

        async fn hello(&mut self, protocol: u32, cookie: &str, subscribe: Vec<Kind>) {
            let hello = FromPlugin::Hello(Hello {
                name: "test".to_owned(),
                protocol,
                cookie: cookie.to_owned(),
                subscribe,
            });
            self.send_line(&serde_json::to_string(&hello).unwrap())
                .await;
        }

        /// The next message, or `None` once the connection is closed.
        async fn receive(&mut self) -> Option<ToPlugin> {
            let line = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line())
                .await
                .unwrap()
                .unwrap()?;
            Some(serde_json::from_str(&line).unwrap())
        }

        async fn welcomed(server: &Server, subscribe: Vec<Kind>) -> Self {
            let mut plugin = Self::connect(server).await;
            plugin.hello(PROTOCOL_VERSION, COOKIE, subscribe).await;
            assert!(matches!(plugin.receive().await, Some(ToPlugin::Welcome(_))));
            plugin
        }
    }

    fn notification(kind: Kind) -> Notification {
        Notification {
            kind,
            id: rand::random::<Digest>(),
        }
    }

    #[tokio::test]
    async fn a_plugin_with_the_cookie_is_welcomed_with_the_rpc_address() {
        let server = server().await;
        let mut plugin = Plugin::connect(&server).await;
        plugin.hello(PROTOCOL_VERSION, COOKIE, vec![]).await;

        assert_eq!(
            Some(ToPlugin::Welcome(Welcome {
                protocol: PROTOCOL_VERSION,
                rpc: "127.0.0.1:9797".parse().unwrap(),
            })),
            plugin.receive().await
        );
    }

    /// A refused plugin is told why, and then the connection closes.
    #[tokio::test]
    async fn a_plugin_is_refused_without_the_cookie_protocol_or_a_hello() {
        let server = server().await;
        let hello = |protocol: u32, cookie: &str| {
            serde_json::to_string(&FromPlugin::Hello(Hello {
                name: "test".to_owned(),
                protocol,
                cookie: cookie.to_owned(),
                subscribe: vec![Kind::Block],
            }))
            .unwrap()
        };
        for (line, reason) in [
            (hello(PROTOCOL_VERSION, "c0ffef"), "wrong cookie"),
            (hello(PROTOCOL_VERSION, ""), "wrong cookie"),
            (
                hello(PROTOCOL_VERSION + 1, COOKIE),
                "protocol 2 is not supported",
            ),
            ("hello".to_owned(), "not a hello"),
            (r#"{"welcome":{}}"#.to_owned(), "not a hello"),
            (String::new(), "not a hello"),
        ] {
            let mut plugin = Plugin::connect(&server).await;
            plugin.send_line(&line).await;
            match plugin.receive().await {
                Some(ToPlugin::Refused(refusal)) => {
                    assert!(refusal.starts_with(reason), "{refusal}")
                }
                other => panic!("{line:?} got {other:?}"),
            }
            assert_eq!(None, plugin.receive().await);
        }
    }

    /// Each plugin is sent the kinds it subscribed to, in the order they were
    /// sent, and no other.
    #[tokio::test]
    async fn each_plugin_is_sent_the_kinds_it_subscribed_to() {
        let server = server().await;
        let mut blocks = Plugin::welcomed(&server, vec![Kind::Block]).await;
        let mut both = Plugin::welcomed(&server, vec![Kind::Tx, Kind::Proposal]).await;

        let sent = [
            notification(Kind::Block),
            notification(Kind::Tx),
            notification(Kind::Proposal),
            notification(Kind::Block),
        ];
        for notification in sent {
            server.notifications.send(notification).unwrap();
        }

        for expected in [sent[0], sent[3]] {
            assert_eq!(
                Some(ToPlugin::Notification(expected)),
                blocks.receive().await
            );
        }
        for expected in [sent[1], sent[2]] {
            assert_eq!(Some(ToPlugin::Notification(expected)), both.receive().await);
        }
    }

    /// A plugin that falls behind is told how many notifications it missed,
    /// and then gets the ones still kept.
    #[tokio::test]
    async fn a_plugin_that_falls_behind_is_told_how_far() {
        let server = server().await;

        // Connect, but do not finish the handshake, so the plugin's task does
        // not consume notifications yet. The test channel keeps 4.
        let mut plugin = Plugin::connect(&server).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sent = (0..6)
            .map(|_| notification(Kind::Block))
            .collect::<Vec<_>>();
        for notification in &sent {
            server.notifications.send(*notification).unwrap();
        }
        plugin
            .hello(PROTOCOL_VERSION, COOKIE, vec![Kind::Block])
            .await;

        assert!(matches!(plugin.receive().await, Some(ToPlugin::Welcome(_))));
        assert_eq!(Some(ToPlugin::Lagged(2)), plugin.receive().await);
        for expected in &sent[2..] {
            assert_eq!(
                Some(ToPlugin::Notification(*expected)),
                plugin.receive().await
            );
        }
    }
}
