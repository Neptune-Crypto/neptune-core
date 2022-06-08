use serde::{Deserialize, Serialize};
use twenty_first::{
    amount::u32s::U32s,
    shared_math::b_field_element::BFieldElement,
    util_types::mutator_set::{
        removal_record::RemovalRecord, transfer_ms_membership_proof::TransferMsMembershipProof,
    },
};

use super::shared::Hash;

pub const AMOUNT_SIZE_FOR_U32: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    amount: U32s<AMOUNT_SIZE_FOR_U32>,
    public_key_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<(Utxo, TransferMsMembershipProof<Hash>, RemovalRecord<Hash>)>,
    pub outputs: Vec<Utxo>,
    pub public_scripts: Vec<Vec<u8>>,
    pub fee: U32s<AMOUNT_SIZE_FOR_U32>,
    pub timestamp: BFieldElement,
}
