//! The protocol between `neptune-defi` and its plugins.
//!
//! A plugin connects to `neptune-defi` over TCP and the two exchange JSON
//! objects, one per line. The plugin speaks first, with a [`Hello`] that names
//! it, proves with the plugin cookie that it runs as the user who started
//! `neptune-defi`, and lists the notifications it wants. `neptune-defi` answers
//! with a [`Welcome`] that tells the plugin where `neptune-core` serves
//! JSON-RPC, or refuses it and closes the connection. After a welcome,
//! `neptune-defi` sends every notification of a kind the plugin subscribed to.
//!
//! A notification is a hint, not a fact: it says that something happened and
//! names it, and a plugin reads what it names from `neptune-core`.

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use neptune_primitives::data_directory::DataDirectory;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::io::Lines;
use tokio::net::TcpStream;

/// The version of this protocol. A plugin states the version it speaks, and
/// `neptune-defi` refuses any other.
pub const PROTOCOL_VERSION: u32 = 1;

/// Where `neptune-defi` listens for plugins unless told otherwise. The port is
/// the first one after those `neptune-core` uses by default.
pub const DEFAULT_ADDRESS: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9802);

/// The name of the file holding the plugin cookie, in `neptune-core`'s data
/// directory for the network it runs on.
///
/// `neptune-defi` writes a new random cookie there every time it starts, and
/// only the user who started it can read the file. A plugin proves it runs as
/// that user by sending the cookie in its [`Hello`].
pub const COOKIE_FILE_NAME: &str = ".defi-plugin-cookie";

/// The number of bytes in a plugin cookie.
pub const COOKIE_LENGTH: usize = 32;

/// The plugin cookie's file in `data_directory`: next to `neptune-core`'s own
/// RPC cookie.
pub fn cookie_path(data_directory: &DataDirectory) -> PathBuf {
    data_directory
        .rpc_cookie_file_path()
        .with_file_name(COOKIE_FILE_NAME)
}

/// `cookie` in lowercase hex, two digits per byte, as a [`Hello`] carries it.
pub fn cookie_hex(cookie: &[u8]) -> String {
    cookie.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What a notification is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A new tip; the id is the block's hash.
    Block,

    /// A transaction entered the mempool; the id is its transaction id.
    Tx,

    /// The node adopted a block proposal; the id is the hash of its body.
    Proposal,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Block, Kind::Tx, Kind::Proposal];
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Kind::Block => "block",
            Kind::Tx => "tx",
            Kind::Proposal => "proposal",
        };
        write!(f, "{name}")
    }
}

impl FromStr for Kind {
    type Err = ();

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Kind::ALL
            .into_iter()
            .find(|kind| kind.to_string() == name)
            .ok_or(())
    }
}

/// One notification: what happened, and the id of what it happened to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub kind: Kind,
    #[serde(with = "digest_hex")]
    pub id: Digest,
}

impl fmt::Display for Notification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind, self.id.to_hex())
    }
}

impl FromStr for Notification {
    type Err = ();

    /// Parse `<kind> <id>`, with the id in hex, as [`Display`](fmt::Display)
    /// writes it.
    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let (kind, id) = line.split_once(' ').ok_or(())?;
        Ok(Notification {
            kind: kind.parse()?,
            id: Digest::try_from_hex(id).map_err(|_| ())?,
        })
    }
}

/// A plugin's first message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// What the plugin calls itself, for `neptune-defi`'s log.
    pub name: String,

    /// The protocol version the plugin speaks.
    pub protocol: u32,

    /// The plugin cookie, in hex.
    pub cookie: String,

    /// The kinds of notification the plugin wants.
    pub subscribe: Vec<Kind>,
}

/// `neptune-defi`'s answer to a [`Hello`] it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Welcome {
    /// The protocol version `neptune-defi` speaks.
    pub protocol: u32,

    /// Where `neptune-core` serves JSON-RPC.
    pub rpc: SocketAddr,
}

/// A message from a plugin to `neptune-defi`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FromPlugin {
    Hello(Hello),
}

/// A message from `neptune-defi` to a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToPlugin {
    Welcome(Welcome),

    /// The plugin is refused, for the reason given, and the connection
    /// closes.
    Refused(String),

    Notification(Notification),

    /// The plugin fell behind and this many notifications for it were
    /// dropped, oldest first. Notifications are hints, so a plugin catches up
    /// by reading the state of the node rather than by replaying them.
    Lagged(u64),
}

/// Why a plugin could not connect, or lost its connection.
#[derive(Debug)]
pub enum ConnectError {
    /// The cookie could not be read, or the connection failed.
    Io(io::Error),

    /// `neptune-defi` refused the plugin, for the reason given.
    Refused(String),

    /// `neptune-defi` sent something this protocol does not allow at that
    /// point.
    Protocol(String),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Refused(reason) => write!(f, "neptune-defi refused the plugin: {reason}"),
            Self::Protocol(message) => write!(f, "protocol violation: {message}"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<io::Error> for ConnectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// What a welcomed plugin is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Notification(Notification),

    /// See [`ToPlugin::Lagged`].
    Lagged(u64),
}

/// A plugin's connection to `neptune-defi`, after the welcome.
#[derive(Debug)]
pub struct Connection {
    welcome: Welcome,
    lines: Lines<BufReader<TcpStream>>,
}

/// Connect to the `neptune-defi` listening on `address`, as the plugin `name`,
/// for the notifications of the kinds in `subscribe`.
///
/// The cookie is read from `cookie_path`, which [`cookie_path`] gives for the
/// data directory `neptune-core` runs with. The result is a connection if and
/// only if `neptune-defi` welcomes the plugin.
pub async fn connect(
    address: SocketAddr,
    cookie_path: &Path,
    name: &str,
    subscribe: Vec<Kind>,
) -> Result<Connection, ConnectError> {
    let cookie = tokio::fs::read(cookie_path).await?;
    let hello = FromPlugin::Hello(Hello {
        name: name.to_owned(),
        protocol: PROTOCOL_VERSION,
        cookie: cookie_hex(&cookie),
        subscribe,
    });
    let mut line = serde_json::to_string(&hello).expect("a hello serializes");
    line.push('\n');

    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(line.as_bytes()).await?;
    let mut lines = BufReader::new(stream).lines();
    match receive(&mut lines).await? {
        Some(ToPlugin::Welcome(welcome)) => Ok(Connection { welcome, lines }),
        Some(ToPlugin::Refused(reason)) => Err(ConnectError::Refused(reason)),
        Some(other) => Err(ConnectError::Protocol(format!(
            "expected a welcome, got {other:?}"
        ))),
        None => Err(ConnectError::Protocol(
            "the connection closed before a welcome".to_owned(),
        )),
    }
}

impl Connection {
    /// Where `neptune-core` serves JSON-RPC.
    pub fn rpc(&self) -> SocketAddr {
        self.welcome.rpc
    }

    /// The next notification or lag notice, or `None` once `neptune-defi`
    /// closes the connection.
    pub async fn next(&mut self) -> Result<Option<Event>, ConnectError> {
        match receive(&mut self.lines).await? {
            Some(ToPlugin::Notification(notification)) => {
                Ok(Some(Event::Notification(notification)))
            }
            Some(ToPlugin::Lagged(dropped)) => Ok(Some(Event::Lagged(dropped))),
            Some(other) => Err(ConnectError::Protocol(format!(
                "expected a notification, got {other:?}"
            ))),
            None => Ok(None),
        }
    }
}

/// The next message, or `None` once the connection is closed.
async fn receive(
    lines: &mut Lines<BufReader<TcpStream>>,
) -> Result<Option<ToPlugin>, ConnectError> {
    let Some(line) = lines.next_line().await? else {
        return Ok(None);
    };
    serde_json::from_str(&line)
        .map(Some)
        .map_err(|error| ConnectError::Protocol(format!("{error}: {line}")))
}

mod digest_hex {
    use serde::de::Error;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;
    use tasm_lib::prelude::Digest;

    pub(super) fn serialize<S: Serializer>(
        digest: &Digest,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&digest.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Digest, D::Error> {
        let hex = String::deserialize(deserializer)?;
        Digest::try_from_hex(&hex).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn a_notification_reads_back_from_its_line(
        #[strategy(arb())] id: Digest,
        #[strategy(0..3_usize)] kind: usize,
    ) {
        let notification = Notification {
            kind: Kind::ALL[kind],
            id,
        };
        assert_eq!(Ok(notification), notification.to_string().parse());
    }

    #[test]
    fn lines_that_are_not_notifications_are_refused() {
        let hex = Digest::default().to_hex();
        for line in [
            String::new(),
            "block".to_owned(),
            hex.clone(),
            format!("blocks {hex}"),
            format!("Block {hex}"),
            format!("block  {hex}"),
            format!("block {hex} extra"),
            format!("block {}", &hex[1..]),
            format!("block {}g", &hex[1..]),
        ] {
            assert_eq!(Err(()), line.parse::<Notification>(), "{line:?}");
        }
    }

    /// The JSON a plugin in any language reads and writes: one object per
    /// message, named by its kind, with digests in hex.
    #[test]
    fn messages_have_the_documented_json_form() {
        let id = Digest::default();
        let hex = id.to_hex();
        for (message, json) in [
            (
                ToPlugin::Notification(Notification {
                    kind: Kind::Block,
                    id,
                }),
                format!(r#"{{"notification":{{"kind":"block","id":"{hex}"}}}}"#),
            ),
            (ToPlugin::Lagged(3), r#"{"lagged":3}"#.to_owned()),
            (
                ToPlugin::Refused("no".to_owned()),
                r#"{"refused":"no"}"#.to_owned(),
            ),
            (
                ToPlugin::Welcome(Welcome {
                    protocol: 1,
                    rpc: "127.0.0.1:9797".parse().unwrap(),
                }),
                r#"{"welcome":{"protocol":1,"rpc":"127.0.0.1:9797"}}"#.to_owned(),
            ),
        ] {
            assert_eq!(json, serde_json::to_string(&message).unwrap());
            assert_eq!(message, serde_json::from_str(&json).unwrap());
        }

        let hello = FromPlugin::Hello(Hello {
            name: "sofun".to_owned(),
            protocol: 1,
            cookie: "00ff".to_owned(),
            subscribe: vec![Kind::Block, Kind::Proposal],
        });
        let json = r#"{"hello":{"name":"sofun","protocol":1,"cookie":"00ff","subscribe":["block","proposal"]}}"#;
        assert_eq!(json, serde_json::to_string(&hello).unwrap());
        assert_eq!(hello, serde_json::from_str(json).unwrap());
    }

    #[test]
    fn cookie_hex_is_lowercase_and_two_digits_per_byte() {
        assert_eq!("0aff00", cookie_hex(&[0x0a, 0xff, 0x00]));
        assert_eq!(2 * COOKIE_LENGTH, cookie_hex(&[7; COOKIE_LENGTH]).len());
    }

    mod connect {
        use tokio::io::AsyncBufReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::io::BufReader;
        use tokio::net::TcpListener;

        use super::*;

        /// A cookie file in a directory of its own, and its hex.
        fn cookie_file() -> (PathBuf, String) {
            let dir = std::env::temp_dir()
                .join("neptune-defi-connect-tests")
                .join(format!("{:016x}", rand::random::<u64>()));
            std::fs::create_dir_all(&dir).unwrap();
            let cookie: [u8; COOKIE_LENGTH] = rand::random();
            let path = dir.join(COOKIE_FILE_NAME);
            std::fs::write(&path, cookie).unwrap();
            (path, cookie_hex(&cookie))
        }

        /// A stand-in for `neptune-defi` that takes one connection, hands
        /// the hello it reads to the test, and then writes `replies`, one per
        /// line, and closes the connection.
        async fn fake_defi(replies: Vec<String>) -> (SocketAddr, tokio::task::JoinHandle<Hello>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let (read, mut write) = stream.into_split();
                let line = BufReader::new(read)
                    .lines()
                    .next_line()
                    .await
                    .unwrap()
                    .unwrap();
                let FromPlugin::Hello(hello) = serde_json::from_str(&line).unwrap();
                for reply in replies {
                    write
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                }
                hello
            });
            (address, task)
        }

        fn json(message: &ToPlugin) -> String {
            serde_json::to_string(message).unwrap()
        }

        fn welcome() -> ToPlugin {
            ToPlugin::Welcome(Welcome {
                protocol: PROTOCOL_VERSION,
                rpc: "127.0.0.1:9797".parse().unwrap(),
            })
        }

        /// The hello carries the cookie from the file in hex, the plugin's
        /// name and its subscriptions; after the welcome come notifications
        /// and lag notices, in order, and then the end of the connection.
        #[tokio::test]
        async fn a_welcomed_plugin_receives_what_is_sent_until_the_end() {
            let (cookie_path, cookie) = cookie_file();
            let notification = Notification {
                kind: Kind::Tx,
                id: rand::random(),
            };
            let (address, server) = fake_defi(vec![
                json(&welcome()),
                json(&ToPlugin::Notification(notification)),
                json(&ToPlugin::Lagged(5)),
            ])
            .await;

            let mut connection = connect(address, &cookie_path, "test", vec![Kind::Tx])
                .await
                .unwrap();

            assert_eq!(
                Hello {
                    name: "test".to_owned(),
                    protocol: PROTOCOL_VERSION,
                    cookie,
                    subscribe: vec![Kind::Tx],
                },
                server.await.unwrap()
            );
            assert_eq!(
                "127.0.0.1:9797".parse::<SocketAddr>().unwrap(),
                connection.rpc()
            );
            assert_eq!(
                Some(Event::Notification(notification)),
                connection.next().await.unwrap()
            );
            assert_eq!(Some(Event::Lagged(5)), connection.next().await.unwrap());
            assert_eq!(None, connection.next().await.unwrap());
        }

        #[tokio::test]
        async fn a_refusal_is_an_error_carrying_the_reason() {
            let (cookie_path, _) = cookie_file();
            let (address, _) =
                fake_defi(vec![json(&ToPlugin::Refused("wrong cookie".to_owned()))]).await;

            let result = connect(address, &cookie_path, "test", vec![]).await;

            assert!(
                matches!(result, Err(ConnectError::Refused(reason)) if reason == "wrong cookie")
            );
        }

        /// Anything but a welcome first, and anything but a notification or a
        /// lag notice after it, breaks the protocol.
        #[tokio::test]
        async fn a_message_out_of_place_is_a_protocol_error() {
            let (cookie_path, _) = cookie_file();
            for replies in [
                vec![],
                vec!["nonsense".to_owned()],
                vec![json(&ToPlugin::Lagged(1))],
            ] {
                let (address, _) = fake_defi(replies.clone()).await;
                let result = connect(address, &cookie_path, "test", vec![]).await;
                assert!(
                    matches!(result, Err(ConnectError::Protocol(_))),
                    "{replies:?}"
                );
            }

            for second in [json(&welcome()), "nonsense".to_owned()] {
                let (address, _) = fake_defi(vec![json(&welcome()), second.clone()]).await;
                let mut connection = connect(address, &cookie_path, "test", vec![])
                    .await
                    .unwrap();
                assert!(
                    matches!(connection.next().await, Err(ConnectError::Protocol(_))),
                    "{second}"
                );
            }
        }

        #[tokio::test]
        async fn a_missing_cookie_file_or_listener_is_an_io_error() {
            let (address, _) = fake_defi(vec![json(&welcome())]).await;
            let missing = std::env::temp_dir().join("neptune-defi-connect-tests/no-such-cookie");
            let result = connect(address, &missing, "test", vec![]).await;
            assert!(matches!(result, Err(ConnectError::Io(_))));

            let (cookie_path, _) = cookie_file();
            let unused = std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let result = connect(unused, &cookie_path, "test", vec![]).await;
            assert!(matches!(result, Err(ConnectError::Io(_))));
        }
    }
}
