use crate::api::export::Utxo;

pub struct Lustration {
    aocl_leaf_index: u64,
    utxo: Utxo,
    sender_randomness: Digest,
    receiver_preimage: Digest,
}
