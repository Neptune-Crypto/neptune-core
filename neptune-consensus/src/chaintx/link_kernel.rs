use get_size2::GetSize;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use strum::VariantArray;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::MerkleTree;

use crate::transaction::transaction_kernel::TransactionKernel;

/// The kernel of a chained transaction (`LinkTx`).
///
/// A `LinkKernel` composes a [`TransactionKernel`] with a list of
/// *thruputs*: [`AdditionRecord`]s that are simultaneously an *unconfirmed*
/// input to this transaction and an output of a predecessor in the transaction
/// chain. The wrapped kernel is reused verbatim -- same fields, same MAST leafs
/// -- so the view of the type script is exactly a single-proof transaction.
///
/// The thruputs are carried as one extra MAST leaf beside the existing kernel
/// leafs (see [`LinkKernelField`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct LinkKernel {
    pub kernel: TransactionKernel,
    pub thruputs: Vec<AdditionRecord>,
}

/// MAST leaf positions of a [`LinkKernel`].
///
/// The first eight variants mirror `TransactionKernelField` exactly, so the
/// transaction-kernel fields keep their leaf positions; `Thruputs` is the one extra
/// leaf. (The drift guard `link_kernel_field_mirrors_transaction_kernel_field`
/// asserts this alignment.)
#[derive(VariantArray, Debug, Clone, EnumCount, Copy, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum LinkKernelField {
    Inputs,
    Outputs,
    Announcements,
    Fee,
    Coinbase,
    Timestamp,
    MutatorSetHash,
    MergeBit,
    Thruputs,
}

impl HasDiscriminant for LinkKernelField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl MastHash for LinkKernel {
    type FieldEnum = LinkKernelField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let mut sequences = self.kernel.mast_sequences();
        sequences.push(self.thruputs.encode());
        sequences
    }
}

/// The right child of the MAST root of a [`LinkKernel`] whose thruputs are
/// empty.
///
/// A `LinkKernel`'s nine leafs pad to sixteen, and its first eight are exactly
/// the wrapped [`TransactionKernel`]'s -- eight being already a power of two, so
/// nothing pads in between. The left child of the `LinkKernel` root is therefore
/// the transaction kernel's MAST root itself, and the right child holds nothing
/// but the `Thruputs` leaf and padding:
///
/// ```text
/// lkmh = hash_pair(txkmh, no_thruputs_subtree_root())      (thruputs == [])
/// ```
///
/// which is what lets [`Cast`](super::cast::Cast) bind a divined `txkmh` to the
/// `lkmh` it is claimed against with a single hash instead of a subtree. Pinned
/// by `mast_hash_pairs_the_kernel_root_with_the_thruputs_subtree`.
pub(crate) fn no_thruputs_subtree_root() -> Digest {
    let mut leafs = vec![Tip5::hash_varlen(&Vec::<AdditionRecord>::new().encode())];
    leafs.resize(
        1 << <TransactionKernel as MastHash>::MAST_HEIGHT,
        Digest::default(),
    );

    MerkleTree::sequential_new(&leafs).unwrap().root()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prop_assert_eq;
    use proptest::prop_assert_ne;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::transaction::transaction_kernel::TransactionKernelField;

    /// The transaction-kernel fields must keep their MAST leaf positions, *i.e.*,
    /// the first eight `LinkKernelField` variants line up with
    /// `TransactionKernelField`.
    #[test]
    fn link_kernel_field_mirrors_transaction_kernel_field() {
        assert_eq!(
            TransactionKernelField::COUNT + 1,
            LinkKernelField::COUNT,
            "LinkKernel adds exactly one leaf"
        );
        for (txk_field, link_field) in TransactionKernelField::VARIANTS
            .iter()
            .zip(LinkKernelField::VARIANTS.iter())
        {
            assert_eq!(txk_field.discriminant(), link_field.discriminant());
            assert_eq!(txk_field.to_string(), link_field.to_string());
        }
        assert_eq!(
            TransactionKernelField::COUNT,
            LinkKernelField::Thruputs.discriminant(),
            "thruputs is the extra trailing leaf"
        );
    }

    /// The wrapped kernel's leafs are reused verbatim and thruputs is appended
    /// to this list of leafs.
    #[proptest]
    fn mast_sequences_reuse_kernel_leafs_and_append_thruputs(#[strategy(arb())] link: LinkKernel) {
        let kernel_seqs = link.kernel.mast_sequences();
        let link_seqs = link.mast_sequences();

        prop_assert_eq!(kernel_seqs.len() + 1, link_seqs.len());
        prop_assert_eq!(kernel_seqs.as_slice(), &link_seqs[..kernel_seqs.len()]);
        prop_assert_eq!(&link.thruputs.encode(), link_seqs.last().unwrap());
    }

    /// The MAST root of a thruput-less [`LinkKernel`] is its transaction
    /// kernel's root paired with a constant.
    ///
    /// `Cast` stands on this: it divines `txkmh`, hashes it with
    /// [`no_thruputs_subtree_root`], and compares against the `lkmh` it is
    /// claimed under -- one hash in place of a subtree, and the empty thruputs
    /// come for free, being baked into the constant. Should the leaf order or
    /// the padding ever change, this is what fails.
    #[proptest]
    fn mast_hash_pairs_the_kernel_root_with_the_thruputs_subtree(
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let link = LinkKernel {
            kernel,
            thruputs: std::vec![],
        };

        prop_assert_eq!(
            link.mast_hash(),
            Tip5::hash_pair(link.kernel.mast_hash(), no_thruputs_subtree_root())
        );
    }

    /// Thruputs are bound into the MAST hash: appending a thruput changes the hash.
    #[proptest]
    fn thruputs_affect_mast_hash(
        #[strategy(arb())] link: LinkKernel,
        #[strategy(arb())] extra: AdditionRecord,
    ) {
        let mut appended = link.clone();
        appended.thruputs.push(extra);
        prop_assert_ne!(link.mast_hash(), appended.mast_hash());
    }

    #[proptest]
    fn bfield_codec_round_trip(#[strategy(arb())] link: LinkKernel) {
        let decoded = *LinkKernel::decode(&link.encode()).unwrap();
        prop_assert_eq!(link, decoded);
    }
}
