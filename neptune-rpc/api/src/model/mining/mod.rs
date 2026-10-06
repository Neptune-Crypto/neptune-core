pub mod template;

use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::model::common::RpcBFieldElements;

/// A transaction's primitive witness, encoded. It is everything needed to
/// prove the transaction, secrets included, so it belongs only on calls to
/// the caller's own node.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcPrimitiveWitness(RpcBFieldElements);

impl From<&PrimitiveWitness> for RpcPrimitiveWitness {
    fn from(witness: &PrimitiveWitness) -> Self {
        Self(witness.encode().into())
    }
}

impl TryFrom<RpcPrimitiveWitness> for PrimitiveWitness {
    type Error = String;

    fn try_from(witness: RpcPrimitiveWitness) -> Result<Self, Self::Error> {
        PrimitiveWitness::decode(&witness.0.0)
            .map(|witness| *witness)
            .map_err(|e| e.to_string())
    }
}
