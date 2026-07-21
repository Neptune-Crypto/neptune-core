use get_size2::GetSize;
use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::link_kernel::LinkKernel;
use crate::transaction::lock_script::LockScriptAndWitness;
use crate::transaction::primitive_witness::SaltedUtxos;
use crate::type_scripts::TypeScriptAndWitness;

/// The raw witness for a chained transaction, consumed by `Forge` to produce a
/// link proof. It is the transaction-chaining analog of
/// [`PrimitiveWitness`](crate::transaction::primitive_witness::PrimitiveWitness):
/// it exposes secret data (spending keys) and must never be broadcast.
///
/// # Confirmed inputs vs. thruputs
///
/// A chained transaction has two kinds of inputs:
///
/// - **Confirmed inputs** are UTXOs already in the mutator set. They are spent
///   the legacy way: each has a [`RemovalRecord`](neptune_mutator_set::removal_record::RemovalRecord)
///   in `kernel.kernel.inputs` and a membership proof in
///   [`input_membership_proofs`](Self::input_membership_proofs).
/// - **Thruputs** are UTXOs that are outputs of a *predecessor* in the chain and
///   are not yet confirmed. Each is an [`AdditionRecord`](neptune_mutator_set::addition_record::AdditionRecord)
///   in `kernel.thruputs`. A thruput is committed exactly like an output --
///   `commit(utxo, sender_randomness, receiver_digest)` -- so it carries
///   output-style commitment randomness (see
///   [`thruput_sender_randomnesses`](Self::thruput_sender_randomnesses) /
///   [`thruput_receiver_digests`](Self::thruput_receiver_digests)) rather than a
///   mutator-set membership proof. `Forge` does *not* match a thruput against a
///   real predecessor output; that happens later, at cut-through in `Chain`.
///
/// The type-script-facing [`input_utxos`](Self::input_utxos) list is the
/// concatenation `confirmed_inputs || thruputs`, so `NativeCurrency` and
/// `TimeLock` (or other type scripts) see a legacy transaction and count both
/// kinds of inputs toward the input balance. The partition boundary is
/// `input_membership_proofs.len()`: the first that-many entries are confirmed
/// inputs, and the remaining `kernel.thruputs.len()` are thruputs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct LinkWitness {
    /// Confirmed input UTXOs followed by thruput UTXOs -- the combined,
    /// type-script-facing input list. The first `input_membership_proofs.len()`
    /// entries are confirmed inputs; the remaining `kernel.thruputs.len()` are
    /// thruputs.
    pub input_utxos: SaltedUtxos,

    /// Mutator-set membership proofs for the confirmed inputs only. Its length
    /// is the number of confirmed inputs and marks the confirmed/thruput
    /// partition boundary in `input_utxos`.
    pub input_membership_proofs: Vec<MsMembershipProof>,

    /// Sender randomnesses for the thruput inputs, parallel to
    /// `kernel.thruputs`.
    pub thruput_sender_randomnesses: Vec<Digest>,

    /// Receiver digests for the thruput inputs, parallel to `kernel.thruputs`.
    /// `commit(thruput_utxo, sender_randomness, receiver_digest)` must equal
    /// the matching addition record in `kernel.thruputs`.
    pub thruput_receiver_digests: Vec<Digest>,

    /// Lock scripts for every input -- confirmed inputs *and* thruputs -- since
    /// both appear in `input_utxos` and must be unlocked to be spent.
    pub lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,

    /// Type scripts for the token types across all inputs and outputs.
    pub type_scripts_and_witnesses: Vec<TypeScriptAndWitness>,

    pub output_utxos: SaltedUtxos,
    pub output_sender_randomnesses: Vec<Digest>,
    pub output_receiver_digests: Vec<Digest>,

    /// The mutator set the confirmed inputs are members of.
    pub mutator_set_accumulator: MutatorSetAccumulator,

    /// The chained-transaction kernel this witness attests to; carries the
    /// thruput addition records.
    pub kernel: LinkKernel,
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl LinkWitness {
    /// Proptest strategy for a structurally-varied `LinkWitness`.
    ///
    /// Built from a valid [`PrimitiveWitness`](crate::transaction::primitive_witness::PrimitiveWitness)
    /// (whose confirmed inputs become this witness's confirmed inputs), plus a
    /// handful of arbitrary thruputs appended to `input_utxos` and
    /// `kernel.thruputs`. The thruput commitments are *not* consistent with a
    /// real predecessor -- this generates well-formed values for encode/decode
    /// and field-shape tests, not necessarily *valid* ones.
    pub fn arbitrary_strategy() -> proptest::strategy::BoxedStrategy<Self> {
        use neptune_mutator_set::addition_record::AdditionRecord;
        use proptest::collection::vec;
        use proptest::prelude::Strategy;
        use proptest_arbitrary_interop::arb;

        use crate::transaction::primitive_witness::PrimitiveWitness;
        use crate::transaction::utxo::Utxo;

        let thruputs = vec(
            (
                arb::<Utxo>(),
                arb::<Digest>(),
                arb::<Digest>(),
                arb::<AdditionRecord>(),
            ),
            0..=3,
        );
        (
            PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1),
            thruputs,
        )
            .prop_map(|(pw, thruputs)| {
                let mut input_utxos = pw.input_utxos;
                let mut sender_randomnesses = vec![];
                let mut receiver_digests = vec![];
                let mut addition_records = vec![];
                for (utxo, sender_randomness, receiver_digest, addition_record) in thruputs {
                    input_utxos.utxos.push(utxo);
                    sender_randomnesses.push(sender_randomness);
                    receiver_digests.push(receiver_digest);
                    addition_records.push(addition_record);
                }
                Self {
                    input_utxos,
                    input_membership_proofs: pw.input_membership_proofs,
                    thruput_sender_randomnesses: sender_randomnesses,
                    thruput_receiver_digests: receiver_digests,
                    lock_scripts_and_witnesses: pw.lock_scripts_and_witnesses,
                    type_scripts_and_witnesses: pw.type_scripts_and_witnesses,
                    output_utxos: pw.output_utxos,
                    output_sender_randomnesses: pw.output_sender_randomnesses,
                    output_receiver_digests: pw.output_receiver_digests,
                    mutator_set_accumulator: pw.mutator_set_accumulator,
                    kernel: LinkKernel {
                        kernel: pw.kernel,
                        thruputs: addition_records,
                    },
                }
            })
            .boxed()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use test_strategy::proptest;

    use super::*;

    #[proptest]
    fn bfield_codec_round_trip(
        #[strategy(LinkWitness::arbitrary_strategy())] witness: LinkWitness,
    ) {
        let decoded = *LinkWitness::decode(&witness.encode()).unwrap();
        assert_eq!(witness, decoded);
    }
}
