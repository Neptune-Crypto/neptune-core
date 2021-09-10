use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerMessage {
    MagicValue((Vec<u8>, String)),
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
