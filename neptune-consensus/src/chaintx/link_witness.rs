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
    /// Build a *valid* `LinkWitness` from a valid `PrimitiveWitness` by
    /// reclassifying the last `num_thruputs` of its inputs from confirmed
    /// inputs into thruputs.
    ///
    /// A thruput is type-script-identical to a confirmed input (both live in
    /// `input_utxos` and count toward the input balance); only the backing
    /// record differs (an `AdditionRecord` in `kernel.thruputs` instead of a
    /// `RemovalRecord` + membership proof). So a valid `PrimitiveWitness` with
    /// `n + k` inputs *is* a valid `LinkWitness` with `n` confirmed inputs and
    /// `k` thruputs, with no re-balancing: `input_utxos`, the type-script
    /// witnesses, and the mutator set carry over unchanged. Each reclassified
    /// input reuses its own membership-proof randomness, so its thruput
    /// addition record is the canonical mutator-set commitment of that UTXO.
    ///
    /// Panics if `pw` has fewer than `num_thruputs` inputs.
    pub fn from_primitive_witness(
        pw: crate::transaction::primitive_witness::PrimitiveWitness,
        num_thruputs: usize,
    ) -> Self {
        use itertools::Itertools;
        use neptune_mutator_set::commit;
        use tasm_lib::prelude::Tip5;

        use crate::transaction::transaction_kernel::TransactionKernelProxy;
        use crate::type_scripts::known_type_scripts::match_type_script_and_generate_witness;

        let num_inputs = pw.input_membership_proofs.len();
        assert!(
            num_thruputs <= num_inputs,
            "cannot reclassify {num_thruputs} thruputs from a witness with {num_inputs} inputs"
        );
        let num_confirmed = num_inputs - num_thruputs;

        let mut thruput_sender_randomnesses = vec![];
        let mut thruput_receiver_digests = vec![];
        let mut thruputs = vec![];
        for (utxo, mp) in pw.input_utxos.utxos[num_confirmed..]
            .iter()
            .zip(&pw.input_membership_proofs[num_confirmed..])
        {
            let sender_randomness = mp.sender_randomness;
            let receiver_digest = mp.receiver_preimage.hash();
            thruputs.push(commit(Tip5::hash(utxo), sender_randomness, receiver_digest));
            thruput_sender_randomnesses.push(sender_randomness);
            thruput_receiver_digests.push(receiver_digest);
        }

        // Drop the reclassified inputs' removal records from the kernel.
        let mut proxy = TransactionKernelProxy::from(pw.kernel);
        proxy.inputs.truncate(num_confirmed);
        let kernel = proxy.into_kernel();

        // Type scripts see this (truncated) kernel, so their mast auth paths
        // must be regenerated against it -- truncating the `inputs` leaf moved
        // the kernel mast root. (Mirror of `update_with_new_ms_data`.)
        let type_scripts_and_witnesses = pw
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| {
                match_type_script_and_generate_witness(
                    tsaw.program.hash(),
                    kernel.clone(),
                    pw.input_utxos.clone(),
                    pw.output_utxos.clone(),
                )
                .expect("type script hash should be known")
            })
            .collect_vec();

        Self {
            input_utxos: pw.input_utxos, // unchanged: confirmed || thruput
            input_membership_proofs: pw.input_membership_proofs[..num_confirmed].to_vec(),
            thruput_sender_randomnesses,
            thruput_receiver_digests,
            lock_scripts_and_witnesses: pw.lock_scripts_and_witnesses,
            type_scripts_and_witnesses,
            output_utxos: pw.output_utxos,
            output_sender_randomnesses: pw.output_sender_randomnesses,
            output_receiver_digests: pw.output_receiver_digests,
            mutator_set_accumulator: pw.mutator_set_accumulator,
            kernel: LinkKernel { kernel, thruputs },
        }
    }

    /// Proptest strategy for a structurally-varied, *valid* `LinkWitness`:
    /// reclassify the tail of a valid `PrimitiveWitness`'s inputs as thruputs
    /// (see [`from_primitive_witness`](Self::from_primitive_witness)).
    pub fn arbitrary_strategy() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::prelude::Strategy;

        use crate::transaction::primitive_witness::PrimitiveWitness;

        (
            PrimitiveWitness::arbitrary_with_size_numbers(Some(4), 2, 1),
            0usize..=2,
        )
            .prop_map(|(pw, num_thruputs)| Self::from_primitive_witness(pw, num_thruputs))
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
