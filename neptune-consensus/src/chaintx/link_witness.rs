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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn bfield_codec_round_trip() {
        let witness = LinkWitness {
            input_utxos: SaltedUtxos::empty(),
            input_membership_proofs: vec![],
            thruput_sender_randomnesses: vec![],
            thruput_receiver_digests: vec![],
            lock_scripts_and_witnesses: vec![],
            type_scripts_and_witnesses: vec![],
            output_utxos: SaltedUtxos::empty(),
            output_sender_randomnesses: vec![],
            output_receiver_digests: vec![],
            mutator_set_accumulator: MutatorSetAccumulator::default(),
            kernel: LinkKernel::empty(),
        };
        let decoded = *LinkWitness::decode(&witness.encode()).unwrap();
        assert_eq!(witness, decoded);
    }
}
