use get_size2::GetSize;
use itertools::Itertools;
use neptune_mutator_set::commit;
use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tracing::warn;

use std::collections::HashMap;

use super::link_kernel::LinkKernel;
use crate::transaction::lock_script::LockScriptAndWitness;
use crate::transaction::primitive_witness::SaltedUtxos;
use crate::transaction::primitive_witness::WitnessValidationError;
use crate::transaction::utxo::Utxo;
use crate::type_scripts::known_type_scripts;
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

impl LinkWitness {
    /// Verify a chained transaction directly from its witness -- the Rust
    /// reference predicate for `Forge`, analogous to
    /// [`PrimitiveWitness::validate`](crate::transaction::primitive_witness::PrimitiveWitness::validate).
    ///
    /// Confirmed inputs are removal records and therefore validated against the
    /// mutator set. Thruputs are addition records and therefore only checked
    /// for commitment-consistency.
    pub async fn validate(&self) -> Result<(), WitnessValidationError> {
        let num_confirmed = self.input_membership_proofs.len();
        let num_thruputs = self.kernel.thruputs.len();

        // 1. Cardinality: |input_utxos| == |confirmed| + |thruputs|, and the
        //    thruput randomnesses run parallel to the thruput addition records.
        if self.input_utxos.utxos.len() != num_confirmed + num_thruputs
            || self.thruput_sender_randomnesses.len() != num_thruputs
            || self.thruput_receiver_digests.len() != num_thruputs
        {
            let error = WitnessValidationError::CardinalityMismatch {
                input_utxos: self.input_utxos.utxos.len(),
                confirmed: num_confirmed,
                thruputs: num_thruputs,
            };
            warn!("{error}");
            return Err(error);
        }

        // 2. Every input -- confirmed and thruput -- must be unlocked.
        for lock_script_and_witness in &self.lock_scripts_and_witnesses {
            let lock_script = lock_script_and_witness.program.clone();
            let secret_input = lock_script_and_witness.nondeterminism();
            let public_input = Tip5::hash(self).reversed().encode().into();

            let result = tokio::task::spawn_blocking(move || {
                VM::run(lock_script, public_input, secret_input)
            })
            .await;
            let Ok(run_res) = result else {
                let error =
                    WitnessValidationError::Failed("Failed to spawn lock-script task.".into());
                warn!("{error}");
                return Err(error);
            };
            if run_res.is_err() {
                let error = WitnessValidationError::InvalidLockScript(
                    lock_script_and_witness.program.hash(),
                );
                warn!("{error}");
                return Err(error);
            }
        }

        // 3. Confirmed inputs: verify each membership proof and collect the
        //    removal record it implies. (Checked against the kernel below, in
        //    the same order as `PrimitiveWitness::validate`.) Only the confirmed
        //    inputs are members of the mutator set; thruputs are handled below.
        let mut witnessed_removal_records = vec![];
        for (input_utxo, membership_proof) in self.input_utxos.utxos[..num_confirmed]
            .iter()
            .zip_eq(&self.input_membership_proofs)
        {
            let item = Tip5::hash(input_utxo);
            if !self.mutator_set_accumulator.verify(item, membership_proof) {
                let error = WitnessValidationError::InvalidMembershipProof {
                    witness_mutator_set_accumulator_hash: self.mutator_set_accumulator.hash(),
                    kernel_mutator_set_hash: self.kernel.kernel.mutator_set_hash,
                };
                warn!("{error}");
                return Err(error);
            }
            witnessed_removal_records
                .push(self.mutator_set_accumulator.drop(item, membership_proof));
        }

        // 4. Type scripts run unchanged over the combined input list, against
        //    the inner (legacy) kernel's mast hash.
        let required_type_script_hashes = Utxo::type_script_hashes(
            self.output_utxos
                .utxos
                .iter()
                .chain(&self.input_utxos.utxos),
        );
        let type_script_dictionary = self
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| (tsaw.program.hash(), tsaw.program.clone()))
            .collect::<HashMap<_, _>>();
        if type_script_dictionary.len() > required_type_script_hashes.len() {
            let error = WitnessValidationError::TooManyTypeScriptWitnesses {
                expected: required_type_script_hashes.len(),
                got: type_script_dictionary.len(),
            };
            warn!("{error}");
            return Err(error);
        }
        if let Some(missing) = required_type_script_hashes
            .iter()
            .find(|tsh| !type_script_dictionary.contains_key(tsh))
        {
            let error = WitnessValidationError::MissingTypeScriptWitness {
                type_script_hash: *missing,
                type_script_name: known_type_scripts::typescript_name(*missing).to_owned(),
            };
            warn!("{error}");
            return Err(error);
        }
        for (j, type_script_hash) in required_type_script_hashes.iter().enumerate() {
            let type_script = type_script_dictionary[type_script_hash].clone();
            let nondeterminism = self.type_scripts_and_witnesses[j].nondeterminism();
            let public_input: PublicInput = [
                self.kernel.kernel.mast_hash(),
                Tip5::hash(&self.input_utxos),
                Tip5::hash(&self.output_utxos),
            ]
            .into_iter()
            .flat_map(|d| d.reversed().values())
            .collect::<Vec<_>>()
            .into();

            let result = tokio::task::spawn_blocking(move || {
                VM::run(type_script, public_input, nondeterminism)
            })
            .await;
            let Ok(run_res) = result else {
                let error =
                    WitnessValidationError::Failed("Failed to spawn type-script task.".into());
                warn!("{error}");
                return Err(error);
            };
            if let Err(vm_error) = run_res {
                let error = WitnessValidationError::InvalidTypeScript {
                    type_script_hash: *type_script_hash,
                    type_script_name: known_type_scripts::typescript_name(*type_script_hash)
                        .to_owned(),
                    vm_error: vm_error.to_string(),
                };
                warn!("{error}");
                return Err(error);
            }
        }

        // 5. Removal records derived from the confirmed inputs must match the
        //    kernel's inputs (as in `PrimitiveWitness::validate`, after the type
        //    scripts), and each thruput's canonical commitment must match its
        //    addition record -- the addition-record analog of that check.
        //    (`Forge` does not match a thruput against a predecessor output;
        //    that is `Chain`'s job.)
        if witnessed_removal_records != self.kernel.kernel.inputs {
            let error = WitnessValidationError::RemovalRecordsMismatch {
                witnessed_removal_records,
                kernel_removal_records: self.kernel.kernel.inputs.clone(),
            };
            warn!("{error}");
            return Err(error);
        }
        for (i, thruput_utxo) in self.input_utxos.utxos[num_confirmed..].iter().enumerate() {
            let addition_record = commit(
                Tip5::hash(thruput_utxo),
                self.thruput_sender_randomnesses[i],
                self.thruput_receiver_digests[i],
            );
            if addition_record != self.kernel.thruputs[i] {
                let error = WitnessValidationError::ThruputCommitmentMismatch { index: i };
                warn!("{error}");
                return Err(error);
            }
        }

        // 6. Mutator set consistency, no merge bit, no coinbase.
        if self.mutator_set_accumulator.hash() != self.kernel.kernel.mutator_set_hash {
            let error = WitnessValidationError::MutatorSetMismatch {
                witness_mutator_set_hash: self.mutator_set_accumulator.hash(),
                transaction_mutator_set_hash: self.kernel.kernel.mutator_set_hash,
            };
            warn!("{error}");
            return Err(error);
        }
        if self.kernel.kernel.merge_bit {
            let error = WitnessValidationError::MergeBitSet;
            warn!("{error}");
            return Err(error);
        }
        if self.kernel.kernel.coinbase.is_some() {
            let error = WitnessValidationError::CoinbaseSet;
            warn!("{error}");
            return Err(error);
        }

        Ok(())
    }
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
    use proptest::prop_assert;
    use proptest::strategy::BoxedStrategy;
    use test_strategy::proptest;

    use super::*;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::type_scripts::time_lock::TimeLockWitness;
    use crate::type_scripts::TypeScriptWitness;

    /// Base `PrimitiveWitness` strategy: fixed input count (so a poke that needs
    /// a specific confirmed/thruput split always applies), everything else
    /// random. `None` inputs produces a coinbase transaction.
    fn pw_strategy(num_inputs: Option<usize>) -> BoxedStrategy<PrimitiveWitness> {
        PrimitiveWitness::arbitrary_with_size_numbers(num_inputs, 2, 1)
    }

    #[proptest]
    fn bfield_codec_round_trip(
        #[strategy(LinkWitness::arbitrary_strategy())] witness: LinkWitness,
    ) {
        let decoded = *LinkWitness::decode(&witness.encode()).unwrap();
        assert_eq!(witness, decoded);
    }

    // ------------------------------------------------------------------ positive

    /// Lifting a *valid* `PrimitiveWitness` at any thruput count yields a valid
    /// `LinkWitness` -- for free, off any legacy strategy.
    #[proptest(cases = 5, async = "tokio")]
    async fn lift_preserves_validity(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
        #[strategy(0usize..=4)] num_thruputs: usize,
    ) {
        let result = LinkWitness::from_primitive_witness(pw, num_thruputs)
            .validate()
            .await;
        prop_assert!(result.is_ok(), "{result:?}");
    }

    /// With every input reclassified (0 confirmed), balance holds only because
    /// thruputs are counted toward the input sum.
    #[proptest(cases = 5, async = "tokio")]
    async fn all_thruputs_is_valid(#[strategy(pw_strategy(Some(2)))] pw: PrimitiveWitness) {
        let witness = LinkWitness::from_primitive_witness(pw, 2);
        prop_assert!(witness.input_membership_proofs.is_empty());
        let result = witness.validate().await;
        prop_assert!(result.is_ok(), "{result:?}");
    }

    // -------------------------------------------- coverage gap (mirrors legacy)

    /// `validate()` does not check lock-script *coverage* against the inputs;
    /// that binding is `Forge`/`CollectLockScripts`'s job, and
    /// `PrimitiveWitness::validate` has the same gap. Pin it so no one writes a
    /// test expecting `validate()` to catch a missing/extra lock script.
    #[proptest(cases = 5, async = "tokio")]
    async fn missing_or_extra_lock_script_is_not_caught(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
    ) {
        let mut missing = LinkWitness::from_primitive_witness(pw.clone(), 2);
        missing.lock_scripts_and_witnesses.pop();
        prop_assert!(missing.validate().await.is_ok());

        let mut extra = LinkWitness::from_primitive_witness(pw, 2);
        let dup = extra.lock_scripts_and_witnesses[0].clone();
        extra.lock_scripts_and_witnesses.push(dup);
        prop_assert!(extra.validate().await.is_ok());
    }

    // ---------------------------------------------------------- negative: cardinality

    #[proptest(cases = 5, async = "tokio")]
    async fn extra_input_utxo_fails_cardinality(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
    ) {
        let mut w = LinkWitness::from_primitive_witness(pw, 2);
        let dup = w.input_utxos.utxos[0].clone();
        w.input_utxos.utxos.push(dup);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::CardinalityMismatch { .. })
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn short_thruput_randomness_fails_cardinality(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
    ) {
        let mut w = LinkWitness::from_primitive_witness(pw, 2);
        w.thruput_sender_randomnesses.pop();
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::CardinalityMismatch { .. })
        ));
    }

    // ---------------------------------------------------------- negative: lock script

    #[proptest(cases = 5, async = "tokio")]
    async fn bad_lock_script_witness_fails(#[strategy(pw_strategy(Some(2)))] pw: PrimitiveWitness) {
        let mut w = LinkWitness::from_primitive_witness(pw, 1);
        let program = LockScriptAndWitness::genaddr_like_hash_lock_from_seed(Tip5::hash(
            &BFieldElement::new(2),
        ))
        .program;
        let wrong_witness = LockScriptAndWitness::genaddr_like_hash_lock_from_seed(Tip5::hash(
            &BFieldElement::new(3),
        ))
        .nondeterminism();
        w.lock_scripts_and_witnesses[0] =
            LockScriptAndWitness::new_with_nondeterminism(program, wrong_witness);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::InvalidLockScript(_))
        ));
    }

    // ---------------------------------------------------------- negative: mutator set

    #[proptest(cases = 5, async = "tokio")]
    async fn bad_mutator_set_accumulator_fails(
        #[strategy(pw_strategy(Some(2)))] pw: PrimitiveWitness,
    ) {
        let mut w = LinkWitness::from_primitive_witness(pw, 1);
        w.mutator_set_accumulator = MutatorSetAccumulator::default();
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::InvalidMembershipProof { .. })
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn mutator_set_hash_mismatch_is_rejected(
        #[strategy(pw_strategy(Some(4)))] mut pw: PrimitiveWitness,
    ) {
        // Overwrite the kernel's stored mutator-set-hash *leaf* while leaving
        // `mutator_set_accumulator` untouched, so the accumulator's real hash no
        // longer equals the hash the kernel claims. `from_primitive_witness`
        // carries the poked leaf through verbatim (it never recomputes it) and
        // rebuilds the type scripts against it, so the type-script checks still
        // pass and validation reaches the final `accumulator.hash() ==
        // kernel.mutator_set_hash` comparison, which now fails.
        pw.kernel = TransactionKernelModifier::default()
            .mutator_set_hash(Digest::default())
            .modify(pw.kernel);
        let w = LinkWitness::from_primitive_witness(pw, 2);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::MutatorSetMismatch { .. })
        ));
    }

    // ---------------------------------------------------------- negative: type scripts

    #[proptest(cases = 5, async = "tokio")]
    async fn unbalanced_output_fails_type_script(
        #[strategy(pw_strategy(Some(4)))] mut pw: PrimitiveWitness,
    ) {
        let inflated = pw.output_utxos.utxos[0].get_native_currency_amount()
            + NativeCurrencyAmount::coins(1);
        pw.output_utxos.utxos[0] =
            pw.output_utxos.utxos[0].new_with_native_currency_amount(inflated);
        let w = LinkWitness::from_primitive_witness(pw, 2);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::InvalidTypeScript { .. })
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn fee_too_big_fails_type_script(
        #[strategy(pw_strategy(Some(4)))] mut pw: PrimitiveWitness,
    ) {
        pw.kernel = TransactionKernelModifier::default()
            .fee(pw.kernel.fee + NativeCurrencyAmount::coins(1))
            .modify(pw.kernel);
        let w = LinkWitness::from_primitive_witness(pw, 2);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::InvalidTypeScript { .. })
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn missing_type_script_witness_fails(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
    ) {
        let mut w = LinkWitness::from_primitive_witness(pw, 2);
        w.type_scripts_and_witnesses.remove(0);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::MissingTypeScriptWitness { .. })
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn too_many_type_script_witnesses_fails(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
    ) {
        let mut w = LinkWitness::from_primitive_witness(pw, 2);
        let extra = TimeLockWitness::new(
            w.kernel.kernel.clone(),
            w.input_utxos.clone(),
            w.output_utxos.clone(),
        )
        .type_script_and_witness();
        w.type_scripts_and_witnesses.push(extra);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::TooManyTypeScriptWitnesses { .. })
        ));
    }

    // ----------------------------------------------- negative: kernel-record consistency

    #[proptest(cases = 5, async = "tokio")]
    async fn swapped_removal_records_fail(#[strategy(pw_strategy(Some(3)))] mut pw: PrimitiveWitness) {
        // 3 inputs, lift 1 => 2 confirmed; swap their removal records so the
        // kernel disagrees with what the membership proofs imply.
        let mut inputs = pw.kernel.inputs.clone();
        inputs.swap(0, 1);
        pw.kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(pw.kernel);
        let w = LinkWitness::from_primitive_witness(pw, 1);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::RemovalRecordsMismatch { .. })
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn tampered_thruput_addition_record_fails(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
    ) {
        let mut w = LinkWitness::from_primitive_witness(pw, 2);
        w.kernel.thruputs[0].canonical_commitment = Digest::default();
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::ThruputCommitmentMismatch { index: 0 })
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn tampered_thruput_randomness_fails(
        #[strategy(pw_strategy(Some(4)))] pw: PrimitiveWitness,
    ) {
        let mut w = LinkWitness::from_primitive_witness(pw, 2);
        w.thruput_sender_randomnesses[0] = Digest::default();
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::ThruputCommitmentMismatch { index: 0 })
        ));
    }

    // -------------------------------------------- negative: merge bit / coinbase

    #[proptest(cases = 5, async = "tokio")]
    async fn merge_bit_is_rejected(
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers_and_merge_bit(Some(4), 2, 1, true))]
        pw: PrimitiveWitness,
    ) {
        let w = LinkWitness::from_primitive_witness(pw, 2);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::MergeBitSet)
        ));
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn coinbase_kernel_is_rejected(#[strategy(pw_strategy(None))] pw: PrimitiveWitness) {
        let w = LinkWitness::from_primitive_witness(pw, 0);
        assert!(matches!(
            w.validate().await,
            Err(WitnessValidationError::CoinbaseSet)
        ));
    }
}
