use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;

use super::appendix_witness::AppendixWitness;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::BlockAppendix;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::builtins::verify_stark;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

/// Verifies that all claims listed in the appendix are true.
///
/// The witness for this program is [`AppendixWitness`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockProgram;

impl BlockProgram {
    pub(crate) fn claim(block_body: &BlockBody, appendix: &BlockAppendix) -> Claim {
        Claim::new(Self.hash())
            .with_input(block_body.mast_hash().reversed().values().to_vec())
            .with_output(appendix.claims_as_output())
    }

    pub(crate) fn verify(block_body: &BlockBody, appendix: &BlockAppendix, proof: &Proof) -> bool {
        let claim = Self::claim(block_body, appendix);
        triton_vm::verify(Stark::default(), &claim, proof)
    }
}

impl ConsensusProgram for BlockProgram {
    fn source(&self) {
        let _block_body_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let block_witness: AppendixWitness = tasmlib::decode_from_memory(start_address);
        let claims: Vec<Claim> = block_witness.claims;
        let proofs: Vec<Proof> = block_witness.proofs;

        let mut i = 0;
        while i < claims.len() {
            tasmlib::tasmlib_io_write_to_stdout___digest(Tip5::hash(&claims[i]));
            verify_stark(Stark::default(), &claims[i], &proofs[i]);

            i += 1;
        }
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let block_witness_field_claims = field!(AppendixWitness::claims);
        let block_witness_field_proofs = field!(AppendixWitness::proofs);

        let hash_varlen = library.import(Box::new(HashVarlen));
        let print_claim_hash = triton_asm!(
            // _ *claim[i]_si

            read_mem 1
            addi 2
            // _ claim[i]_si *claim[i]

            dup 0
            place 2
            place 1
            // _ *claim[i] *claim[i] claim[i]_si

            call {hash_varlen}
            // _ *claim[i] [hash(claim)]

            write_io {Digest::LEN}
            // _ *claim[i]
        );

        let verify_all_claims_loop = "verify_all_claims_loop".to_string();

        let verify_all_claims_function = triton_asm! {
            // INVARIANT: _ [bbd] *claim[i]_si *proof[i]_si N i
            {verify_all_claims_loop}:

                // terminate if done
                dup 1 dup 1 eq skiz return

                dup 3
                // _ [bbd] *claim[i]_si *proof[i]_si N i *claim[i]_si

                {&print_claim_hash}
                // _ [bbd] *claim[i]_si *proof[i]_si N i *claim[i]

                dup 3 addi 1
                // _ [bbd] *claim[i]_si *proof[i]_si N i *claim[i] *proof[i]

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
            // _ [bbd] *claim[0] *proof[0] N

            push 0
            // _ [bbd] *claim[0] *proof[0] N 0

            call {verify_all_claims_loop}
            // _ [bbd] *claim[0] *proof[0] N N

            pop 4
            pop 5
            // _

            halt

            {&verify_all_claims_function}
            {&library.all_imports()}
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use itertools::Itertools;
    use tasm_lib::triton_vm::vm::PublicInput;
    use tracing_test::traced_test;

    use super::*;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::SecretWitness;

    #[traced_test]
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
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let appendix_witness = rt
            .block_on(AppendixWitness::produce(
                block_primitive_witness,
                &TritonVmJobQueue::dummy(),
            ))
            .unwrap();

        let block_program_nondeterminism = appendix_witness.nondeterminism();
        let rust_output = BlockProgram
            .run_rust(
                &block_body_mast_hash_as_input,
                block_program_nondeterminism.clone(),
            )
            .unwrap();
        let tasm_output = BlockProgram
            .run_tasm(&block_body_mast_hash_as_input, block_program_nondeterminism)
            .unwrap();

        assert_eq!(rust_output, tasm_output);

        let expected_output = appendix_witness
            .claims()
            .iter()
            .flat_map(|appendix_claim| Tip5::hash(appendix_claim).values().to_vec())
            .collect_vec();
        assert_eq!(expected_output, tasm_output);
    }
}
