use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::SystemTime;

#[derive(Debug)]
pub struct Peer {
    pub address: SocketAddr,
    pub banscore: u8,
    pub inbound: bool,
    pub last_seen: SystemTime,
    pub version: String,
}
