use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerMessage {
    MagicValue(Vec<u8>),
    NewBlock(u32),
    NewTransaction(i32),
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
