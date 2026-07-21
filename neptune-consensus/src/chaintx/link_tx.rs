use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::link_kernel::LinkKernel;
use super::link_witness::LinkWitness;
use crate::transaction::validity::neptune_proof::NeptuneProof;

/// The proof backing a [`LinkTx`].
///
/// This is the transaction-chaining analog of
/// [`TransactionProof`](crate::transaction::transaction_proof::TransactionProof).
/// It has two variants rather than three: the link pipeline has no proof-
/// collection stage.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum LinkTxProof {
    /// The raw witness. Exposes secrets (spending keys); must not be shared.
    Witness(LinkWitness),
    /// A link proof: the output of one of `Forge`/`Chain`/`Update`/`Cast`. Does
    /// not expose secrets and can be shared with peers.
    Proof(NeptuneProof),
}

impl LinkTxProof {
    pub fn is_witness(&self) -> bool {
        matches!(self, Self::Witness(_))
    }

    pub fn is_proof(&self) -> bool {
        matches!(self, Self::Proof(_))
    }
}

/// A chained transaction: a [`LinkKernel`] together with the [`LinkTxProof`]
/// that backs it.
///
/// This is the transaction-chaining analog of the legacy
/// [`Transaction`](crate::transaction::Transaction), and spans the same
/// lifecycle: it starts witness-backed ([`LinkTxProof::Witness`]) and becomes
/// proof-backed ([`LinkTxProof::Proof`]) once `Forge` runs.
///
/// A `LinkTx` whose `kernel.thruputs` is non-empty is *unresolved*: not yet
/// block-eligible. It becomes block-borne only after `Fix` sends it to a legacy
/// SingleProof-backed `Transaction`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct LinkTx {
    pub kernel: LinkKernel,
    pub proof: LinkTxProof,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

    use super::*;

    #[test]
    fn witness_and_proof_backed_construct_and_clone_eq() {
        let witness_backed = LinkTx {
            kernel: LinkKernel::empty(),
            proof: LinkTxProof::Witness(LinkWitness::empty()),
        };
        let proof_backed = LinkTx {
            kernel: LinkKernel::empty(),
            proof: LinkTxProof::Proof(NeptuneProof::from(vec![BFieldElement::new(1); 5])),
        };

        assert!(witness_backed.proof.is_witness());
        assert!(proof_backed.proof.is_proof());
        assert_eq!(witness_backed, witness_backed.clone());
        assert_eq!(proof_backed, proof_backed.clone());
        assert_ne!(witness_backed.proof, proof_backed.proof);
    }

    #[test]
    fn link_tx_proof_bfield_codec_round_trip() {
        for proof in [
            LinkTxProof::Witness(LinkWitness::empty()),
            LinkTxProof::Proof(NeptuneProof::from(vec![BFieldElement::new(42); 5])),
        ] {
            let decoded = *LinkTxProof::decode(&proof.encode()).unwrap();
            assert_eq!(proof, decoded);
        }
    }
}
