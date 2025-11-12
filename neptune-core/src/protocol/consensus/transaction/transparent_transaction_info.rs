use std::collections::HashSet;

use itertools::Itertools;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use tasm_lib::triton_vm::prelude::BFieldCodec;

use crate::api::export::Announcement;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transparent_input::TransparentInput;
use crate::protocol::consensus::transaction::utxo_triple::UtxoTriple;

/// A struct containing the UTXOs and all information needed to reproduce the
/// `RemovalRecord`s (or at least, the `AbsoluteIndexSet`s) and the
/// `AdditionRecord`s for the transaction in which they are consumed and
/// produced.
#[derive(Debug, Clone, BFieldCodec)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct TransparentTransactionInfo {
    pub inputs: Vec<TransparentInput>,
    pub outputs: Vec<UtxoTriple>,
}

impl TransparentTransactionInfo {
    /// Construct a new `TransparentTransactionDetails` object from the given
    /// inputs and outputs.
    pub fn new(inputs: Vec<TransparentInput>, outputs: Vec<UtxoTriple>) -> Self {
        Self { inputs, outputs }
    }

    /// Convert the `TransparentTransactionDetails` object into an
    /// [`Announcement`].
    pub fn to_announcement(&self) -> Announcement {
        Announcement {
            message: self.encode(),
        }
    }

    /// Try and interpret the [`Announcement`] as a
    /// `TransparentTransactionDetails`.
    pub fn try_from_announcement(
        announcement: &Announcement,
    ) -> Result<Self, <Self as BFieldCodec>::Error> {
        Ok(*Self::decode(&announcement.message)?)
    }

    /// Validate the `TransparentTransactionDetails` relative to a given
    /// [`TransactionKernel`].
    ///
    /// Specifically, verify that all the associated `AdditionRecord`s and
    /// `AbsoluteIndexSet`s induced by the `TransparentTransactionDetails`
    /// are present in the [`TransactionKernel`].
    pub fn validate(&self, transaction_kernel: &TransactionKernel) -> bool {
        let addition_records_from_self = self
            .outputs
            .iter()
            .map(|utxo_triple| utxo_triple.addition_record())
            .collect_vec();
        let absolute_index_sets_from_self = self
            .inputs
            .iter()
            .map(|transparent_input| transparent_input.absolute_index_set())
            .collect_vec();

        let addition_records_in_transaction = transaction_kernel
            .outputs
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let all_addition_records_are_present = addition_records_from_self
            .iter()
            .all(|ar| addition_records_in_transaction.contains(ar));

        let absolute_index_sets_in_transaction = transaction_kernel
            .inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices)
            .collect::<HashSet<_>>();
        let all_absolute_index_sets_are_present = absolute_index_sets_from_self
            .iter()
            .all(|ais| absolute_index_sets_in_transaction.contains(ais));

        all_addition_records_are_present && all_absolute_index_sets_are_present
    }
}

impl Distribution<TransparentTransactionInfo> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TransparentTransactionInfo {
        let num_inputs = rng.random_range(0..10);
        let num_outputs = rng.random_range(0..10);
        let inputs = (0..num_inputs).map(|_| rng.random()).collect_vec();
        let outputs = (0..num_outputs).map(|_| rng.random()).collect_vec();
        TransparentTransactionInfo { inputs, outputs }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;

    impl From<&PrimitiveWitness> for TransparentTransactionInfo {
        fn from(primitive_witness: &PrimitiveWitness) -> Self {
            let transparent_inputs = primitive_witness
                .input_utxos
                .utxos
                .iter()
                .cloned()
                .zip(primitive_witness.input_membership_proofs.iter().clone())
                .map(|(utxo, msmp)| TransparentInput {
                    utxo,
                    aocl_leaf_index: msmp.aocl_leaf_index,
                    sender_randomness: msmp.sender_randomness,
                    receiver_preimage: msmp.receiver_preimage,
                })
                .collect_vec();
            let transparent_outputs = primitive_witness
                .output_utxos
                .utxos
                .iter()
                .cloned()
                .zip(primitive_witness.output_sender_randomnesses.iter().copied())
                .zip(primitive_witness.output_receiver_digests.iter().copied())
                .map(|((utxo, sender_randomness), receiver_digest)| UtxoTriple {
                    utxo,
                    sender_randomness,
                    receiver_digest,
                })
                .collect_vec();
            TransparentTransactionInfo::new(transparent_inputs, transparent_outputs)
        }
    }

    #[proptest(cases = 10)]
    fn correlated_transparent_transaction_info_validates(
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2))]
        primitive_witness: PrimitiveWitness,
    ) {
        let transparent_transaction_info = TransparentTransactionInfo::from(&primitive_witness);
        let transaction_kernel = primitive_witness.kernel;
        prop_assert!(transparent_transaction_info.validate(&transaction_kernel));
    }

    #[proptest(cases = 5)]
    fn uncorrelated_transparent_transaction_info_does_not_validate(
        #[strategy(0usize..5)] _num_inputs: usize,
        #[filter(#_num_inputs + #_num_outputs >= 1)]
        #[strategy(0usize..5)]
        _num_outputs: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2))]
        primitive_witness_a: PrimitiveWitness,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2))]
        primitive_witness_b: PrimitiveWitness,
    ) {
        let transparent_transaction_info = TransparentTransactionInfo::from(&primitive_witness_a);
        let transaction_kernel = primitive_witness_b.kernel;
        prop_assert!(!transparent_transaction_info.validate(&transaction_kernel));
    }

    #[proptest(cases = 10)]
    fn can_decode_announcement(
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2))]
        primitive_witness: PrimitiveWitness,
    ) {
        let transparent_transaction_info = TransparentTransactionInfo::from(&primitive_witness);
        let announcement = transparent_transaction_info.to_announcement();
        let info_again = TransparentTransactionInfo::try_from_announcement(&announcement).unwrap();
        prop_assert_eq!(transparent_transaction_info, info_again);
    }

    #[proptest]
    fn cannot_decode_arbitrary_announcement(#[strategy(arb())] announcement: Announcement) {
        prop_assert!(TransparentTransactionInfo::try_from_announcement(&announcement).is_err());
    }
}
