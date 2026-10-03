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
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

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
}
