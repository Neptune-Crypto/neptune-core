use strum::EnumCount;
use tasm_lib::field;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::PublicInput;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;

use crate::models::blockchain::block::block_body::BlockBodyField;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins::{self as tasmlib};
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;

use super::block_primitive_witness::BlockPrimitiveWitness;

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub(crate) struct TransactionIsValidWitness {
    single_proof: Proof,
    mast_path_txk: Vec<Digest>,
    txk_mast_hash: Digest,
}

impl From<BlockPrimitiveWitness> for TransactionIsValidWitness {
    fn from(mut block_primitive_witness: BlockPrimitiveWitness) -> Self {
        let mast_path = block_primitive_witness
            .body()
            .mast_path(BlockBodyField::Transaction);
        let TransactionProof::SingleProof(single_proof) = block_primitive_witness.transaction.proof
        else {
            panic!("cannot make a block whose transaction is not supported by a single proof");
        };
        let mast_root = block_primitive_witness.transaction.kernel.mast_hash();
        Self {
            single_proof,
            mast_path_txk: mast_path,
            txk_mast_hash: mast_root,
        }
    }
}

impl SecretWitness for TransactionIsValidWitness {
    fn standard_input(&self) -> PublicInput {
        self.txk_mast_hash.reversed().values().to_vec().into()
    }

    fn program(&self) -> Program {
        Program::new(&TransactionIsValid.code())
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::new([]);

        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );
        nondeterminism
            .digests
            .extend_from_slice(&self.mast_path_txk);

        let claim = Claim::new(SingleProof.hash())
            .with_input(self.txk_mast_hash.reversed().values().to_vec());
        StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
            &mut nondeterminism,
            &self.single_proof,
            &claim,
        );

        nondeterminism
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TransactionIsValid;

impl ConsensusProgram for TransactionIsValid {
    fn source(&self) {
        let block_body_mast_hash: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let witness: TransactionIsValidWitness = tasmlib::decode_from_memory(start_address);

        tasmlib::tasmlib_hashing_merkle_verify(
            block_body_mast_hash,
            BlockBodyField::Transaction as u32,
            witness.txk_mast_hash,
            BlockBodyField::COUNT.next_power_of_two().ilog2(),
        );

        let claim = Claim::new(SingleProof.hash())
            .with_input(witness.txk_mast_hash.reversed().values().to_vec());
        tasmlib::verify_stark(Stark::default(), &claim, &witness.single_proof);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let merkle_verify = library.import(Box::new(MerkleVerify));
        let witness_field_txkmh = field!(TransactionIsValidWitness::transaction_kernel_mast_hash);
        let witness_field_single_proof = field!(TransactionIsValidWitness::single_proof);
        let authenticate_txkmh = triton_asm! {
            // _ [bbmh] *witness

            push {BlockBodyField::COUNT.next_power_of_two().ilog2()}
            push {BlockBodyField::Transaction as u32}
            pick 2

            {&witness_field_txkmh}
            addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
            // _ [bbmh] height index [txkmh]

            call {merkle_verify}
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&witness_field_txkmh}
            addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
            // _ [txkmh]
        };

        let push_single_proof_program_digest = {
            let [d0, d1, d2, d3, d4] = SingleProof.hash().values();
            triton_asm! {
                push {d4}
                push {d3}
                push {d2}
                push {d1}
                push {d0}
            }
        };

        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        triton_asm! {
            // _

            read_io 5
            // _ [block_body_mast_hash]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint tx_is_valid_witness = stack[0]
            // _ [bbmh] *witness

            {&authenticate_txkmh}
            // _ [txkmh]

            {&push_single_proof_program_digest}
            // _ [txkmh] [single_proof_program_digest]

            call {generate_single_proof_claim}
            // _ *claim

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&witness_field_single_proof}
            // _ *claim *proof

            call {stark_verify}
            // _

            halt
        }
    }
}

#[cfg(test)]
mod test {
    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;

    use super::*;

    #[test]
    fn transaction_is_valid_halts_gracefully() {
        let mut block_primitive_witness = deterministic_block_primitive_witness();
        let block_body_mast_hash = block_primitive_witness.body().mast_hash();
        let transaction_is_valid_witness = TransactionIsValidWitness::from(block_primitive_witness);

        let input = block_body_mast_hash.reversed().values().to_vec().into();
        let nondeterminism = transaction_is_valid_witness.nondeterminism();
        let rust_result = TransactionIsValid
            .run_rust(&input, nondeterminism.clone())
            .unwrap();
        let tasm_result = TransactionIsValid.run_tasm(&input, nondeterminism).unwrap();

        assert_eq!(rust_result, tasm_result);
    }
}
