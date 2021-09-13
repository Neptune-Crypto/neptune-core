use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeData {
    // The `extra_values` field makes it possible to add data here in a backwards-compatible
    // manner.
    pub extra_values: HashMap<String, String>,
    pub listen_addr: Option<SocketAddr>,
    pub testnet: bool,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerMessage {
    Handshake((Vec<u8>, HandshakeData)),
    NewBlock(u32),
    NewTransaction(i32),
    PeerListRequest,
    PeerListResponse(Vec<SocketAddr>),
    Bye,
}

#[derive(Clone, Debug)]
pub enum FromMainMessage {
    NewBlock(u32),
    NewTransaction(i32),
}

#[derive(Clone, Debug)]
pub enum ToMainMessage {
    NewBlock(u32),
    NewTransaction(i32),
}
