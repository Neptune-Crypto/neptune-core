use super::super::shared::Hash;
use super::utxo::Utxo;
use mutator_set_tf::util_types::mutator_set::{
    removal_record::RemovalRecord, transfer_ms_membership_proof::TransferMsMembershipProof,
};
use secp256k1::ecdsa;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DevNetInput {
    pub utxo: Utxo,
    pub membership_proof: TransferMsMembershipProof<Hash>,
    pub removal_record: RemovalRecord<Hash>,
    pub signature: ecdsa::Signature,
}

impl Eq for DevNetInput {}
