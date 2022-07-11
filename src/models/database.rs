use anyhow::{bail, Result};
use db_key::Key;
use leveldb::{database::Database, kv::KV, options::ReadOptions};
use std::{fmt, net::IpAddr};

use super::blockchain::{
    block::{block_header::BlockHeader, block_height::BlockHeight, Block},
    digest::{keyable_digest::KeyableDigest, Hashable},
};

pub struct BlockDatabases {
    pub block_height_to_hash: Database<BlockHeight>,
    pub block_hash_to_block: Database<KeyableDigest>,
    pub latest_block_header: Database<DatabaseUnit>,
}

pub struct PeerDatabases {
    pub peer_standings: Database<KeyableIpAddress>,
}

// We have to implement `Debug` for `Databases` as the `State` struct
// contains a database object, and `State` is used as input argument
// to multiple functions where logging is enabled with the `instrument`
// attributes from the `tracing` crate, and this requires all input
// arguments to the function to implement the `Debug` trait as this
// info is written on all logging events.
impl fmt::Debug for BlockDatabases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}

impl fmt::Debug for PeerDatabases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DatabaseUnit();
impl Key for DatabaseUnit {
    fn from_u8(_key: &[u8]) -> Self {
        DatabaseUnit()
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        f(&[])
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeyableIpAddress(IpAddr);

impl Key for KeyableIpAddress {
    fn from_u8(key: &[u8]) -> Self {
        // Here, we can probably parse the byte slice as a socket address.
        // try to parse the host as a regular IP address first
        let as_string = match std::str::from_utf8(key) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };
        let socket_address: IpAddr = as_string
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse to socket address. Got: {}", as_string));

        Self(socket_address)
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        // The conversion to byte array is just a conversion to a string
        // and then a conversion to bytes. Not optimal, but it shouldn't
        // be relevant to optimize this.
        // The same IPv6 address can be represented with multiple different strings,
        // but the standard library's `Display` implementation guarantees to write
        // the IP to a canonical form. See this comment on the `Display` implementation
        // on the `Ipv6Addr` type:
        // Write an Ipv6Addr, conforming to the canonical style described by
        // [RFC 5952](https://tools.ietf.org/html/rfc5952).
        let as_string: String = self.0.to_string();
        let as_bytes: Vec<u8> = as_string.into();
        f(&as_bytes)
    }
}

impl From<IpAddr> for KeyableIpAddress {
    fn from(sa: IpAddr) -> Self {
        Self(sa)
    }
}

impl From<KeyableIpAddress> for IpAddr {
    fn from(sa: KeyableIpAddress) -> Self {
        sa.0
    }
}

impl BlockDatabases {
    /// Given a mutex lock on the database, return the latest block
    pub fn get_latest_block(
        databases: tokio::sync::MutexGuard<BlockDatabases>,
    ) -> Result<Option<Block>> {
        let bytes_opt: Option<Vec<u8>> = databases
            .latest_block_header
            .get(ReadOptions::new(), DatabaseUnit())
            .expect("Failed to get latest block info on init");
        let block_header_res: Option<BlockHeader> = bytes_opt.map(|bts| {
            bincode::deserialize(&bts).expect("Failed to deserialize latest block info")
        });
        let block_header = match block_header_res {
            None => return Ok(None),
            Some(bh) => bh,
        };

        let block_bytes: Option<Vec<u8>> = databases
            .block_hash_to_block
            .get::<KeyableDigest>(ReadOptions::new(), block_header.hash().into())?;
        let block: Block = match block_bytes {
            None => {
                bail!("Database entry for block_hash_to_block must be set for block header found in latest_block_header");
            }
            Some(bytes) => bincode::deserialize(&bytes)
                .expect("Failed to deserialize block from block_hash_to_block"),
        };

        Ok(Some(block))
    }
}

#[cfg(test)]
mod keyable_socket_tests {
    use super::*;

    #[test]
    fn slice_array_conversion_test() {
        // Test for IPV4
        let sa0: IpAddr = "127.0.0.1".parse().unwrap();
        let sa0: KeyableIpAddress = sa0.into(); // shadowing is not all bad :)
        let vec = sa0.as_slice(|elem| elem.to_owned());
        let sa0_restored: KeyableIpAddress = KeyableIpAddress::from_u8(&vec);
        assert_eq!(
            sa0, sa0_restored,
            "Converting to and from slice must be identity operation."
        );

        // Test for IPV6
        let sa1: IpAddr = "1fff:0:a88:85a3::ac1f".parse().unwrap();
        let sa1: KeyableIpAddress = sa1.into();
        let vec = sa1.as_slice(|elem| elem.to_owned());
        let sa1_restored: KeyableIpAddress = KeyableIpAddress::from_u8(&vec);
        assert_eq!(
            sa1, sa1_restored,
            "Converting to and from slice must be identity operation."
        );

        // Test for non-canonical representation of IPV6
        let sa2: IpAddr = "2001:0db8:0000:0000:0000:ff00:0042:8329".parse().unwrap();
        let sa2: KeyableIpAddress = sa2.into();
        let vec = sa2.as_slice(|elem| elem.to_owned());
        let sa2_restored: KeyableIpAddress = KeyableIpAddress::from_u8(&vec);
        assert_eq!(
            sa2, sa2_restored,
            "Converting to and from slice must be identity operation."
        );
    }

    #[test]
    fn equality_test() {
        let sa0: IpAddr = "51.15.139.238".parse().unwrap();
        let sa0: KeyableIpAddress = sa0.into();
        let sa1: IpAddr = "51.15.139.238".parse().unwrap();
        let sa1: KeyableIpAddress = sa1.into();
        assert_eq!(sa0, sa1);

        let sa2: IpAddr = "2001:0db8:0000:0000:0000:ff00:0042:8329".parse().unwrap();
        let sa2: KeyableIpAddress = sa2.into();
        assert_ne!(sa2, sa1);
    }
}
