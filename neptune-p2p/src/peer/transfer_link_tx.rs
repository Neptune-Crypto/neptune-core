use anyhow::bail;
use neptune_consensus::chaintx::link_kernel::LinkKernel;
use neptune_consensus::chaintx::link_tx::LinkTx;
use neptune_consensus::chaintx::link_tx::LinkTxProof;
use neptune_consensus::transaction::validity::neptune_proof::NeptuneProof;
use serde::Deserialize;
use serde::Serialize;

/// For transferring proved link transactions between peers.
///
/// This type exists to ensure that a link transaction supported by
/// [`LinkTxProof::Witness`] is never shared between peers, as this would leak
/// secret keys and lead to loss of funds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferLinkTx {
    pub kernel: LinkKernel,
    pub proof: NeptuneProof,
}

impl TryFrom<&LinkTx> for TransferLinkTx {
    type Error = anyhow::Error;

    fn try_from(value: &LinkTx) -> Result<Self, Self::Error> {
        let LinkTxProof::Proof(proof) = &value.proof else {
            bail!("Cannot share witness-backed link transaction, as this would leak secret data")
        };

        Ok(Self {
            kernel: value.kernel.to_owned(),
            proof: proof.to_owned(),
        })
    }
}

impl From<TransferLinkTx> for LinkTx {
    fn from(value: TransferLinkTx) -> Self {
        Self {
            kernel: value.kernel,
            proof: LinkTxProof::Proof(value.proof),
        }
    }
}
