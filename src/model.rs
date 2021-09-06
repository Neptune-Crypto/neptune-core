use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    MagicValue(Vec<u8>),
    NewBlock(u32),
    NewTransaction(i32),
}
