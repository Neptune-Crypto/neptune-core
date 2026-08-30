//! Fixtures for the transaction-chaining pipeline, shared by the `chaintx`
//! tests and the `chaintx` benchmark.
//!
//! A benchmark is an external crate, so nothing under a `#[cfg(test)] mod
//! tests` is reachable from one. These constructors live here rather than in
//! `chain.rs` for that reason alone: the tests that own them and the benchmark
//! that measures them have to build the *same* fixture, or the numbers describe
//! a pipeline nobody tests.

use std::ops::Range;

use itertools::Itertools;
use neptune_mutator_set::commit;
use proptest::strategy::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use super::forge::ForgeWitness;
use super::link_primitive_witness::LinkPrimitiveWitness;
use super::link_proof::LinkProof;
use super::link_tx::LinkTx;
use super::link_tx::LinkTxProof;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::proof_abstractions::triton_vm_job_queue::vm_job_queue;
use crate::proof_abstractions::SecretWitness;
use crate::transaction::primitive_witness::PrimitiveWitness;
use crate::transaction::primitive_witness::SaltedUtxos;
use crate::transaction::transaction_kernel::TransactionKernelProxy;
use crate::type_scripts::known_type_scripts::match_type_script_and_generate_witness;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// The predecessor that resolves the successor's inputs `range`, over the
/// same mutator set.
///
/// It spends exactly those UTXOs and pays them straight back out with the
/// very randomness their membership proofs carry -- so its addition records
/// are, element for element, the commitments those inputs became when
/// [`LinkPrimitiveWitness::from_primitive_witness`] turned them into
/// thruputs. Balanced by construction (same UTXOs in and out, zero fee), so
/// no re-balancing is needed.
///
/// A range rather than a count because the successor's thruputs need not
/// all come from the same predecessor: see `thruputs_resolve_in_two_stages`.
/// `range` must sit inside the tail `from_primitive_witness` reclassifies, or
/// the "predecessor" resolves an input the successor still holds as confirmed
/// and nothing cuts through.
pub fn predecessor_resolving(
    successor_pw: &PrimitiveWitness,
    range: Range<usize>,
) -> LinkPrimitiveWitness {
    LinkPrimitiveWitness::from_primitive_witness(predecessor_resolving_pw(successor_pw, range), 0)
}

/// [`predecessor_resolving`], stopping one step short.
///
/// The predecessor as a plain [`PrimitiveWitness`], which is what it takes to
/// prove it into a `SingleProof`-backed transaction -- the shape `Weld` takes
/// as its first operand, and the one thing the `LinkPrimitiveWitness` it is
/// otherwise wrapped in cannot be proven into.
pub fn predecessor_resolving_pw(
    successor_pw: &PrimitiveWitness,
    range: Range<usize>,
) -> PrimitiveWitness {
    // The UTXOs the successor will hold as thruputs, together with the
    // randomness that commits them.
    let utxos = successor_pw.input_utxos.utxos[range.clone()].to_vec();
    let membership_proofs = successor_pw.input_membership_proofs[range.clone()].to_vec();
    let sender_randomnesses = membership_proofs
        .iter()
        .map(|mp| mp.sender_randomness)
        .collect_vec();
    let receiver_digests = membership_proofs
        .iter()
        .map(|mp| mp.receiver_preimage.hash())
        .collect_vec();

    // The predecessor: spend exactly those UTXOs, and pay them back out
    // with the same randomness.
    let mutator_set_accumulator = successor_pw.mutator_set_accumulator.clone();
    let salted_utxos = SaltedUtxos::new_with_rng(utxos.clone(), &mut StdRng::seed_from_u64(0));
    let inputs = utxos
        .iter()
        .zip(&membership_proofs)
        .map(|(utxo, mp)| mutator_set_accumulator.drop(Tip5::hash(utxo), mp))
        .collect_vec();
    let outputs = utxos
        .iter()
        .zip(&sender_randomnesses)
        .zip(&receiver_digests)
        .map(|((utxo, sr), rd)| commit(Tip5::hash(utxo), *sr, *rd))
        .collect_vec();
    let predecessor_kernel = TransactionKernelProxy {
        inputs,
        outputs,
        announcements: vec![],
        fee: NativeCurrencyAmount::coins(0),
        coinbase: None,
        timestamp: successor_pw.kernel.timestamp,
        mutator_set_hash: mutator_set_accumulator.hash(),
        merge_bit: false,
    }
    .into_kernel();
    let type_scripts_and_witnesses = successor_pw
        .type_scripts_and_witnesses
        .iter()
        .map(|tsaw| {
            match_type_script_and_generate_witness(
                tsaw.program.hash(),
                predecessor_kernel.clone(),
                salted_utxos.clone(),
                salted_utxos.clone(),
            )
            .expect("type script hash should be known")
        })
        .collect_vec();
    PrimitiveWitness {
        input_utxos: salted_utxos.clone(),
        input_membership_proofs: membership_proofs,
        lock_scripts_and_witnesses: successor_pw.lock_scripts_and_witnesses[range].to_vec(),
        type_scripts_and_witnesses,
        output_utxos: salted_utxos,
        output_sender_randomnesses: sender_randomnesses,
        output_receiver_digests: receiver_digests,
        mutator_set_accumulator,
        kernel: predecessor_kernel,
    }
}

/// A predecessor/successor pair over one mutator set: the successor's
/// thruputs are exactly the predecessor's outputs, so chaining them cuts
/// through every one.
pub fn chainable_link_primitive_witnesses(
    successor_pw: PrimitiveWitness,
    num_thruputs: usize,
) -> (LinkPrimitiveWitness, LinkPrimitiveWitness) {
    let num_inputs = successor_pw.input_utxos.utxos.len();
    assert!(num_thruputs <= num_inputs);

    let predecessor = predecessor_resolving(&successor_pw, num_inputs - num_thruputs..num_inputs);

    (
        predecessor,
        LinkPrimitiveWitness::from_primitive_witness(successor_pw, num_thruputs),
    )
}

/// [`chainable_link_primitive_witnesses`] over a fixed fixture.
///
/// Deterministic on purpose: the tests that reach the recursion have to
/// `Forge` their operands, and a fixture that moved between runs would mean
/// a fresh claim, hence a fresh proof, every time. The mock-proof negatives
/// draw at random instead -- they pay no proving cost, so there is nothing
/// to amortize and everything to gain.
pub fn deterministic_chainable_link_primitive_witnesses(
    num_inputs: usize,
    num_thruputs: usize,
) -> (LinkPrimitiveWitness, LinkPrimitiveWitness) {
    let successor_pw = deterministic_primitive_witness(num_inputs);

    chainable_link_primitive_witnesses(successor_pw, num_thruputs)
}

/// The fixed `PrimitiveWitness` the chaintx fixtures are drawn from:
/// `num_inputs` inputs, two outputs, one announcement.
pub fn deterministic_primitive_witness(num_inputs: usize) -> PrimitiveWitness {
    let mut test_runner = TestRunner::deterministic();
    PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), 2, 1)
        .new_tree(&mut test_runner)
        .unwrap()
        .current()
}

/// One successor funded entirely by `num_predecessors` predecessors, one
/// thruput apiece.
///
/// This is the shape the throughput claim is about: `num_predecessors + 1`
/// separate interactions over one mutator set, every thruput resolved by
/// exactly one partner, so chaining them all cuts through everything and the
/// result is `Fix`-eligible. The successor holds no confirmed inputs at all --
/// a normal shape here, see the "zero confirmed inputs" invariant in
/// `chaintx/TODO.md`.
///
/// Chain them in any order; each `Chain` cancels the one (output, thruput)
/// pair its predecessor contributes.
pub fn fan_in_link_primitive_witnesses(
    num_predecessors: usize,
) -> (Vec<LinkPrimitiveWitness>, LinkPrimitiveWitness) {
    let successor_pw = deterministic_primitive_witness(num_predecessors);
    let predecessors = (0..num_predecessors)
        .map(|i| predecessor_resolving(&successor_pw, i..i + 1))
        .collect_vec();
    let successor = LinkPrimitiveWitness::from_primitive_witness(successor_pw, num_predecessors);

    (predecessors, successor)
}

/// Forge a link primitive witness into a proof-backed [`LinkTx`].
///
/// No locks may be held when executing this, as this takes a long time to
/// execute.
pub async fn forge(lpw: &LinkPrimitiveWitness, single_proof_digest: Digest) -> LinkTx {
    let witness = ForgeWitness::produce(
        lpw,
        single_proof_digest,
        vm_job_queue(),
        TritonVmProofJobOptions::default(),
    )
    .await
    .unwrap();
    let proof = LinkProof
        .prove(
            witness.claim(),
            witness.nondeterminism(),
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap();

    LinkTx {
        kernel: lpw.kernel.clone(),
        proof: LinkTxProof::Proof(proof),
    }
}
