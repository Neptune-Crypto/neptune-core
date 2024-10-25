use tasm_lib::field;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;

use crate::models::proof_abstractions::tasm::builtins::verify_stark;
use crate::models::proof_abstractions::tasm::builtins::{self as tasmlib};
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

use super::appendix_witness::AppendixWitness;

/// Verifies that all claims listed in the appendix are true.
///
/// The witness for this program is [`AppendixWitness`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockProgram;

impl ConsensusProgram for BlockProgram {
    fn source(&self) {
        let block_body_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let block_witness: AppendixWitness = tasmlib::decode_from_memory(start_address);
        let claims: Vec<Claim> = block_witness.claims;
        let proofs: Vec<Proof> = block_witness.proofs;

        let mut i = 0;
        while i < claims.len() {
            assert_eq!(
                claims[i].input,
                block_body_digest.reversed().values().to_vec()
            );
            verify_stark(Stark::default(), &claims[i], &proofs[i]);
            i += 1;
        }

        tasmlib::tasmlib_io_write_to_stdout___encoding(claims);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let block_witness_field_claims = field!(AppendixWitness::claims);
        let block_witness_field_proofs = field!(AppendixWitness::proofs);

        let verify_all_claims_loop = "verify_all_claims_loop".to_string();

        let verify_all_claims_function = triton_asm! {
            // INVARIANT: _ [bbd] *claim[i]_si *proof[i]_si N i
            {verify_all_claims_loop}:

                // terminate if done
                dup 1 dup 1 eq skiz return

                // verify (claim, proof) pair
                dup 3 addi 1 dup 3 addi 1
                // _ [bbd] *claim[i]_si *proof[i]_si N i claim proof

                call {stark_verify}
                // _ [bbd] *claim[i]_si *proof[i]_si N i

                // update pointers and counter
                pick 3 read_mem 1 addi 1 add
                // _ [bbd] *proof[i]_si N i *claim[i+1]_si

                pick 3 read_mem 1 addi 1 add
                // _ [bbd] N i *claim[i+1]_si *proof[i+1]_si

                pick 3
                pick 3 addi 1
                // _ [bbd] *claim[i+1]_si *proof[i+1]_si N (i+1)

                recurse
        };

        triton_asm! {
            // _

            read_io 5
            // _ [block_body_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint block_witness_ptr = stack[0]
            // _ [bbd] *w

            dup 0 {&block_witness_field_claims}
            hint claims = stack[0]
            swap 1 {&block_witness_field_proofs}
            hint proofs = stack[1]
            // _ [bbd] *claims *proofs

            dup 1 read_mem 1 pop 1
            // _ [bbd] *claims *proofs N

            pick 2 addi 1
            pick 2 addi 1
            pick 2
            // [bbd] *claim[0] *proof[0] N

            push 0
            // [bbd] *claim[0] *proof[0] N 0

            call {verify_all_claims_loop}

            halt

            {&verify_all_claims_function}
            {&library.all_imports()}
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use tasm_lib::triton_vm::vm::PublicInput;

    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::SecretWitness;

    use super::*;

    #[test]
    fn block_program_halts_gracefully() {
        let block_primitive_witness = deterministic_block_primitive_witness();
        let block_body_mast_hash_as_input = PublicInput::new(
            block_primitive_witness
                .body()
                .mast_hash()
                .reversed()
                .values()
                .to_vec(),
        );

        let appendix_witness = AppendixWitness::produce(block_primitive_witness);
        let block_program_nondeterminism = appendix_witness.nondeterminism();
        let rust_result = BlockProgram
            .run_rust(
                &block_body_mast_hash_as_input,
                block_program_nondeterminism.clone(),
            )
            .unwrap();
        let tasm_result = BlockProgram
            .run_tasm(&block_body_mast_hash_as_input, block_program_nondeterminism)
            .unwrap();

        assert_eq!(rust_result, tasm_result);
    }
}
