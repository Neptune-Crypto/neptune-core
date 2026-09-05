use get_size2::GetSize;
use num_bigint::BigInt;
use num_rational::BigRational;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::link_kernel::LinkKernel;
use super::link_primitive_witness::LinkPrimitiveWitness;
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
    Witness(Box<LinkPrimitiveWitness>),
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

#[cfg(test)]
impl LinkTxProof {
    /// Proptest strategy producing both variants: a witness-backed proof (via
    /// [`LinkPrimitiveWitness::arbitrary_strategy`]) or a proof-backed one.
    pub fn arbitrary_strategy() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::prelude::Strategy;
        use proptest_arbitrary_interop::arb;

        proptest::prop_oneof![
            LinkPrimitiveWitness::arbitrary_strategy()
                .prop_map(|lw| LinkTxProof::Witness(Box::new(lw))),
            arb::<NeptuneProof>().prop_map(LinkTxProof::Proof),
        ]
        .boxed()
    }
}

/// A chained transaction: a [`LinkKernel`] together with the [`LinkTxProof`]
/// that backs it.
///
/// This is the transaction-chaining analog of the single-proof
/// [`Transaction`](crate::transaction::Transaction), and spans the same
/// lifecycle: it starts witness-backed ([`LinkTxProof::Witness`]) and becomes
/// proof-backed ([`LinkTxProof::Proof`]) once `Forge` runs.
///
/// A `LinkTx` whose `kernel.thruputs` is non-empty is *unresolved*: not yet
/// block-eligible. It becomes block-borne only after `Fix` sends it to a
/// SingleProof-backed `Transaction`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct LinkTx {
    pub kernel: LinkKernel,
    pub proof: LinkTxProof,
}

impl LinkTx {
    /// Calculates a fraction representing the fee-density, defined as:
    /// `transaction_fee/transaction_size`.
    pub fn fee_density(&self) -> BigRational {
        let link_tx_as_bytes = bincode::serialize(&self).unwrap();
        let link_tx_size = BigInt::from(link_tx_as_bytes.get_size());
        let link_tx_fee = self.kernel.kernel.fee.to_nau();
        BigRational::new_raw(link_tx_fee.into(), link_tx_size)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prop_assert_eq;
    use proptest::prop_assert_ne;
    use test_strategy::proptest;

    use super::*;

    /// Exactly one of the two variant predicates holds.
    #[proptest]
    fn proof_is_witness_xor_proof(
        #[strategy(LinkTxProof::arbitrary_strategy())] proof: LinkTxProof,
    ) {
        prop_assert_ne!(proof.is_witness(), proof.is_proof());
    }

    #[proptest]
    fn link_tx_proof_bfield_codec_round_trip(
        #[strategy(LinkTxProof::arbitrary_strategy())] proof: LinkTxProof,
    ) {
        let decoded = *LinkTxProof::decode(&proof.encode()).unwrap();
        prop_assert_eq!(proof, decoded);
    }

    #[proptest]
    fn fee_density_decreases_with_proof_size(
        #[strategy(proptest_arbitrary_interop::arb())] link_kernel: LinkKernel,
    ) {
        use proptest::prop_assert;

        use crate::transaction::transaction_kernel::TransactionKernelModifier;
        use crate::transaction::validity::neptune_proof::NeptuneProof;
        use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

        let kernel = LinkKernel {
            kernel: TransactionKernelModifier::default()
                .fee(NativeCurrencyAmount::coins(1))
                .modify(link_kernel.kernel),
            thruputs: link_kernel.thruputs,
        };
        let small = LinkTx {
            kernel: kernel.clone(),
            proof: LinkTxProof::Proof(NeptuneProof::invalid()),
        };
        let large = LinkTx {
            kernel,
            proof: LinkTxProof::Proof(NeptuneProof::invalid_with_size(1 << 15)),
        };

        prop_assert!(large.fee_density() < small.fee_density());
    }
}
