use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use crate::consensus_rule_set::ConsensusRuleSet;
use crate::transaction::validity::tasm::claims::new_claim::NewClaim;

/// Build the claim `{ program, input: [lkmh] || [D], output: [D] }` that a
/// `LinkProof` establishes.
///
/// The transaction-chaining analog of
/// [`GenerateSingleProofClaim`](crate::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim),
/// differing only in that a `LinkProof` claim carries a second digest: the
/// `SingleProof` program digest `D`, which indexes the whole `LinkProof` family
/// and is what breaks the `Fix`/`Cast` circular dependency. Like its sibling it
/// takes the program digest at runtime rather than hardcoding one -- `Chain`
/// passes `own_program_digest()`.
///
/// `D` is not taken on the stack, because it is not a per-claim value: the
/// caller reads it off the public input once and stashes it where every branch
/// reads it from, so this snippet reads it from that same address rather than
/// have callers ferry it around. `lkmh` differs per operand and has no such
/// home, so it stays a stack argument.
///
/// Lives in `chaintx` rather than beside its sibling so that no Rust edge
/// `chaintx -> transaction::validity::single_proof` exists: that acyclicity is
/// the point of promoting `D` to a claim parameter in the first place.
#[derive(Debug, Copy, Clone)]
pub(crate) struct GenerateLinkProofClaim {
    /// Where the caller stashed `D`. See [`LinkProof`](super::link_proof::LinkProof).
    pub(crate) single_proof_digest_address: BFieldElement,
}

impl BasicSnippet for GenerateLinkProofClaim {
    fn parameters(&self) -> Vec<(DataType, String)> {
        let link_kernel_mast_hash = (DataType::Digest, "link_kernel_mast_hash".to_string());
        let program_digest = (DataType::Digest, "link_proof_program_digest".to_string());

        vec![link_kernel_mast_hash, program_digest]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "link_proof_claim".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_chaintx_generate_link_proof_claim".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_claim = library.import(Box::new(NewClaim::new(ConsensusRuleSet::HardforkDelta)));

        // Copy a digest into the claim's *input*, where digests are held
        // *reversed*: the copies are pushed top-word-first so that the deepest
        // word ends up on top, since `write_mem` lays the top of the stack down
        // at the lowest address. `top_word_depth` is where the digest's first
        // word sits; each `dup` shifts the rest down by one, hence the stride.
        let write_reversed_digest = |top_word_depth: usize, pointer_depth: usize| {
            let dups = (0..Digest::LEN)
                .flat_map(|i| triton_asm!(dup { top_word_depth + 2 * i }))
                .collect_vec();
            triton_asm!(
                {&dups}
                dup {pointer_depth + Digest::LEN}
                write_mem {Digest::LEN}
            )
        };

        // Same, into a `Digest` *field*, which is held as it lies. Every `dup`
        // is at the same depth -- each one pushes a word and shifts the next
        // one into place -- so the copies come off deepest-word-first and the
        // top word lands on top, where `write_mem` sends it to the lowest
        // address: the encoding's own order. `deepest_word_depth` is where the
        // digest's *last* word sits; the pointer is `pick`ed, not `dup`ed,
        // being dead afterwards.
        let write_digest_field = |deepest_word_depth: usize| {
            let dups = (0..Digest::LEN)
                .flat_map(|_| triton_asm!(dup { deepest_word_depth }))
                .collect_vec();
            triton_asm!(
                {&dups}
                pick {Digest::LEN}
                write_mem {Digest::LEN}
                pop 1
            )
        };

        triton_asm!(
            // BEFORE: _ [lkmh; 5] [program_digest; 5]
            // AFTER:  _ *claim
            {self.entrypoint()}:
            push {2 * Digest::LEN}
            push {Digest::LEN}
            call {new_claim}
            // _ [lkmh; 5] [program_digest; 5] *claim *output *input *program_digest

            // `D` goes into the output first: it needs no stack digest, and
            // spending `*output` here is what keeps `lkmh` within `dup` range
            // below. The output holds the digest as it lies, unreversed.
            pick 2
            // _ [lkmh; 5] [program_digest; 5] *claim *input *program_digest *output

            push {self.single_proof_digest_address}
            read_mem {Digest::LEN}
            pop 1
            // _ ... *claim *input *program_digest *output [single_proof_digest; 5]

            pick {Digest::LEN}
            write_mem {Digest::LEN}
            pop 1
            // _ [lkmh; 5] [program_digest; 5] *claim *input *program_digest

            // `program_digest`'s deepest word is under `*claim`, `*input` and
            // the digest's own four other words.
            {&write_digest_field(2 + Digest::LEN)}
            // _ [lkmh; 5] [program_digest; 5] *claim *input

            // and `lkmh`'s first word is under `*claim`, `*input` and all of
            // `program_digest`. Its last `dup` reaches depth 15 exactly, which
            // is why `*output` had to go.
            {&write_reversed_digest(2 + Digest::LEN, 0)}
            // _ [lkmh; 5] [program_digest; 5] *claim *input (*input + 5)

            swap 1
            pop 1
            // _ [lkmh; 5] [program_digest; 5] *claim (*input + 5)

            // `D`, read from where the dispatcher put the public input.
            push {self.single_proof_digest_address}
            read_mem {Digest::LEN}
            pop 1
            // _ [lkmh; 5] [program_digest; 5] *claim (*input+5) [single_proof_digest; 5]

            {&write_reversed_digest(0, Digest::LEN)}
            // _ [lkmh; 5] [program_digest; 5] *claim (*input+5) [spd; 5] (*input + 10)

            pop 1
            pop {Digest::LEN}
            pop 1
            // _ [lkmh; 5] [program_digest; 5] *claim

            swap {2 * Digest::LEN}
            pop {Digest::LEN}
            pop {Digest::LEN}
            // _ *claim

            return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use rand::prelude::StdRng;
    use rand::Rng;
    use tasm_lib::library::STATIC_MEMORY_FIRST_ADDRESS;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::rust_shadowing_helper_functions;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::algorithm::Algorithm;
    use tasm_lib::traits::algorithm::AlgorithmInitialState;
    use tasm_lib::traits::algorithm::ShadowedAlgorithm;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;
    use tasm_lib::triton_vm::proof::Claim;

    use super::*;

    /// The address a first `Digest`-sized `kmalloc` yields -- which is what `D`
    /// gets in `LinkProof`, being allocated ahead of every branch import.
    fn single_proof_digest_address() -> BFieldElement {
        STATIC_MEMORY_FIRST_ADDRESS
    }

    fn snippet() -> GenerateLinkProofClaim {
        GenerateLinkProofClaim {
            single_proof_digest_address: single_proof_digest_address(),
        }
    }

    impl Algorithm for GenerateLinkProofClaim {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            _: &NonDeterminism,
        ) -> Result<(), RustShadowError> {
            fn pop_digest(stack: &mut Vec<BFieldElement>) -> Digest {
                Digest::new([
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                    stack.pop().unwrap(),
                ])
            }

            let program_digest = pop_digest(stack);
            let mast_hash = pop_digest(stack);
            let base =
                self.single_proof_digest_address - bfe!(u64::try_from(Digest::LEN).unwrap() - 1);
            let single_proof_digest = Digest::new(std::array::from_fn(|i| {
                memory[&(base + bfe!(u64::try_from(i).unwrap()))]
            }));

            let input = [mast_hash, single_proof_digest]
                .into_iter()
                .flat_map(|digest| digest.reversed().values())
                .collect_vec();
            let claim = Claim::new(program_digest)
                .with_input(input)
                .with_output(single_proof_digest.values().to_vec());
            let claim_pointer =
                rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(memory);
            encode_to_memory(memory, claim_pointer, &claim);
            stack.push(claim_pointer);

            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            _: Option<BenchmarkCase>,
        ) -> AlgorithmInitialState {
            let mut rng: StdRng = rand::prelude::SeedableRng::from_seed(seed);

            let mut stack = self.init_stack_for_isolated_run();
            for _ in 0..2 {
                stack.extend(rng.random::<Digest>().reversed().values());
            }

            // stand in for the dispatcher, which is what writes this slot
            let mut memory = HashMap::default();
            let base =
                self.single_proof_digest_address - bfe!(u64::try_from(Digest::LEN).unwrap() - 1);
            encode_to_memory(&mut memory, base, &rng.random::<Digest>());

            AlgorithmInitialState {
                stack,
                nondeterminism: NonDeterminism::default().with_ram(memory),
            }
        }
    }

    #[test]
    fn rust_and_tasm_agree() {
        ShadowedAlgorithm::new(snippet()).test()
    }
}
