use std::sync::OnceLock;

use tasm_lib::library::Library;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::triton_vm::prelude::*;

use super::chain::Chain;
use super::forge::Forge;
use super::link_proof_witness::DISCRIMINANT_FOR_CHAIN;
use super::link_proof_witness::DISCRIMINANT_FOR_FORGE;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// No branch of the `LinkProof` program ran: the discriminant found in memory
/// matched none of them.
///
/// Unreachable while [`INVALID_WITNESS_DISCRIMINANT_ERROR`] rejects everything
/// but a branch's own value; it is the backstop against a dispatch bug, not
/// against a malformed witness.
pub(crate) const NO_BRANCH_TAKEN_ERROR: i128 = 1_000_530;

/// The witness in memory leads with a discriminant that names no branch.
///
/// Checked up front rather than left to [`NO_BRANCH_TAKEN_ERROR`]: the branches
/// signal "taken" by leaving `-1` in the discriminant's slot, so a witness that
/// *claims* `-1` would otherwise sail through the dispatcher untouched.
pub(crate) const INVALID_WITNESS_DISCRIMINANT_ERROR: i128 = 1_000_531;

/// The MAST leaf a [`LinkKernel`](super::link_kernel::LinkKernel) must carry at
/// [`LinkKernelField::Coinbase`](super::link_kernel::LinkKernelField::Coinbase).
///
/// A `LinkTx` is never a coinbase transaction, so the leaf is a constant and a
/// branch authenticates it directly rather than reading a coinbase out of its
/// witness -- which asserts the field's value at the same time, since only one
/// preimage hashes to it.
///
/// Lives here, not on any one branch: *every* branch owes this assertion on the
/// kernel it produces, and branches that recurse rely on it holding for their
/// operands by induction rather than re-checking it.
pub(super) fn no_coinbase_leaf() -> Digest {
    Tip5::hash(&Option::<NativeCurrencyAmount>::None)
}

/// The MAST leaf a [`LinkKernel`](super::link_kernel::LinkKernel) must carry at
/// [`LinkKernelField::MergeBit`](super::link_kernel::LinkKernelField::MergeBit).
///
/// The merge bit marks a transaction that has been through `Merge`, which is a
/// legacy-pipeline operation; nothing in the chain pipeline sets it, and
/// `Chain` is not a `Merge`. Same constant-leaf treatment, and the same
/// obligation on every branch, as [`no_coinbase_leaf`].
pub(super) fn merge_bit_false_leaf() -> Digest {
    Tip5::hash(&false)
}

/// `LinkProof`: the consensus program backing a
/// [`LinkTx`](super::link_tx::LinkTx).
///
/// The transaction-chaining analog of
/// [`SingleProof`](crate::transaction::validity::single_proof::SingleProof),
/// and structured the same way: a thin dispatcher over the branches of
/// [`LinkProofWitness`](super::link_proof_witness::LinkProofWitness), each of
/// which is a [`BasicSnippet`] that establishes the same claim by a different
/// route. `Forge` is the entry point and `Chain` combines two link
/// transactions; `Update` and `Cast` follow.
///
/// The dispatcher hands each branch `[own_program_digest] [lkmh] *witness disc`
/// and expects `[own_program_digest] [scratch] *witness -1` back. A branch that
/// does not recurse into `LinkProof` -- `Forge` -- simply leaves the digest
/// buried; the dispatcher pops it.
///
/// The claim is `{ program: LinkProof, input: [lkmh] }`. It gains the
/// `SingleProof` program digest as a second input when `Cast` lands -- that
/// parameter is what breaks the `Fix`/`Cast` circular dependency; see the
/// design note in `chaintx/TODO.md`.
#[derive(Debug, Copy, Clone)]
pub struct LinkProof;

impl TritonProgram for LinkProof {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();

        // `Forge` must be imported first. Four of its `kmalloc`s have to land at
        // the same addresses as `RemovalRecordsIntegrity`'s (it inlines that
        // program's confirmed-input loop verbatim; see
        // `forge_confirmed_loop_matches_rri`), which holds only as long as
        // nothing allocates ahead of them. Every other branch -- `Chain` below,
        // and any future one -- imports *after* this one.
        let forge_branch = library.import(Box::new(Forge));
        let chain_branch = library.import(Box::new(Chain));

        // Sum the per-branch equality flags: exactly one may be set. Extend with
        // `dup n push {DISCRIMINANT_FOR_X} eq` + one more `add` per branch.
        let verify_discriminant_has_legal_value = triton_asm!(
            // _ disc

            dup 0
            push {DISCRIMINANT_FOR_FORGE}
            eq
            // _ disc (disc == forge)

            dup 1
            push {DISCRIMINANT_FOR_CHAIN}
            eq
            // _ disc (disc == forge) (disc == chain)

            add
            // _ disc (disc == forge || disc == chain)

            assert error_id {INVALID_WITNESS_DISCRIMINANT_ERROR}
            // _ disc
        );

        let main = triton_asm! {
            // Read own program digest.
            dup 15 dup 15 dup 15 dup 15 dup 15
            hint own_program_digest = stack[0..5]
            // _ [own_program_digest]

            read_io {Digest::LEN}
            hint link_kernel_mast_hash = stack[0..5]
            // _ [own_program_digest] [lkmh]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ [own_program_digest] [lkmh] *link_proof_witness

            read_mem 1 addi 1 swap 1
            hint discriminant = stack[0]
            hint link_proof_witness = stack[1]
            // _ [own_program_digest] [lkmh] *link_proof_witness discriminant

            {&verify_discriminant_has_legal_value}
            // _ [own_program_digest] [lkmh] *link_proof_witness discriminant

            /* match discriminant */
            dup 0 push {DISCRIMINANT_FOR_FORGE} eq
            skiz call {forge_branch}

            dup 0 push {DISCRIMINANT_FOR_CHAIN} eq
            skiz call {chain_branch}
            // _ [own_program_digest] [lkmh] *link_proof_witness discriminant

            // a discriminant of -1 indicates that some branch was executed
            push -1
            eq
            assert error_id {NO_BRANCH_TAKEN_ERROR}
            // _ [own_program_digest] [dispatcher_scratch] *link_proof_witness

            // The digest slot belongs to the dispatcher, and it is scratch: a
            // branch may leave anything there (`Forge` leaves the inner kernel
            // root, having reused the slot once `lkmh` went dead). Nothing may
            // read it -- it is popped here unexamined. Should a check ever need
            // `lkmh` after dispatch, stash it in a `kmalloc` *here*, once, for
            // every branch; do not make branches hand it back, which would put
            // the burden -- and the chance of handing back the wrong digest --
            // on each of them.
            pop 1 pop 5 pop 5
            // _

            halt
        };

        let code = triton_asm!(
            {&main}
            {&library.all_imports()}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use tasm_lib::twenty_first::bfe_array;
    use tasm_lib::twenty_first::bfe_vec;

    use super::*;
    use crate::chaintx::chain::tests::chain_branch_source;
    use crate::chaintx::forge::tests::forge_branch_source;
    use crate::chaintx::link_proof_witness::LinkProofWitnessMemory;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::tests::test_program_snapshot;

    impl TritonProgramSpecification for LinkProof {
        fn source(&self) {
            let own_program_digest: Digest = tasm::own_program_digest();
            let lkmh: Digest = tasm::tasmlib_io_read_stdin___digest();

            match tasm::decode_from_memory::<LinkProofWitnessMemory>(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            ) {
                LinkProofWitnessMemory::Forge(witness) => forge_branch_source(lkmh, *witness),
                LinkProofWitnessMemory::Chain(witness) => {
                    chain_branch_source(own_program_digest, lkmh, *witness)
                }
            }
        }
    }

    /// A discriminant no branch claims must halt the program, not fall through
    /// it. Mirrors `SingleProof`'s `invalid_discriminant_crashes_execution`.
    #[test]
    fn invalid_discriminant_crashes_execution() {
        let public_input = PublicInput::new(bfe_vec![0, 0, 0, 0, 0]);
        for illegal_discriminant in bfe_array![-1, 2, 3, 1u64 << 40] {
            let memory: HashMap<_, _> = [(
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                illegal_discriminant,
            )]
            .into_iter()
            .collect();
            let nondeterminism = NonDeterminism::default().with_ram(memory);

            LinkProof
                .test_assertion_failure(
                    public_input.clone(),
                    nondeterminism,
                    &[INVALID_WITNESS_DISCRIMINANT_ERROR],
                )
                .unwrap();
        }
    }

    test_program_snapshot!(
        LinkProof,
        "f2e0b3a98ad5e10c8acfb96236957b68b9f154cf4d9a3a9fbb1b58518bb508c6931eefbe4ccf0d1a"
    );
}
