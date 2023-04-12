use std::time::Duration;

use crate::{models::blockchain::block::Block, Hash};
use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use serde::{Deserialize, Serialize};
use twenty_first::{shared_math::tip5::Digest, util_types::storage_schema::RustyValue};

use crate::models::blockchain::transaction::utxo::Utxo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredUtxo {
    pub utxo: Utxo,

    // if we have a membership proof, which block is it synced to?
    pub sync_digest: Digest,

    // we might not have a membership proof
    pub membership_proof: Option<MsMembershipProof<Hash>>,

    // hash of the block, if any, in which this UTXO was spent
    pub spent_in_block: Option<(Digest, Duration)>,

    // hash of the block, if any, in which this UTXO was confirmed
    pub confirmed_in_block: Option<(Digest, Duration)>,
}

impl MonitoredUtxo {
    pub fn new(utxo: Utxo) -> Self {
        Self {
            utxo,
            sync_digest: Digest::default(),
            membership_proof: None,
            spent_in_block: None,
            confirmed_in_block: None,
        }
    }

    // determine whether the attached membership proof is synced to the given block
    pub fn is_synced_to(&self, block: &Block) -> bool {
        self.sync_digest == block.hash
    }
}

impl From<RustyValue> for MonitoredUtxo {
    fn from(value: RustyValue) -> Self {
        bincode::deserialize(&value.0).expect(
            "failed to deserialize database object to monitored utxo; database seems corrupted",
        )
    }
}

impl From<MonitoredUtxo> for RustyValue {
    fn from(value: MonitoredUtxo) -> Self {
        RustyValue(bincode::serialize(&value).expect("Totally nonsensical that serialize can fail, but that is how the interface has been defined."))
    }
}
