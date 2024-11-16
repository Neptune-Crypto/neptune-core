use std::sync::OnceLock;

use strum::EnumCount;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
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
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::PublicInput;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;

use super::block_primitive_witness::BlockPrimitiveWitness;
use crate::models::blockchain::block::block_body::BlockBodyField;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins::{self as tasmlib};
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub(crate) struct TransactionIsValidWitness {
    single_proof: Proof,
    mast_path_txk: Vec<Digest>,
    txk_mast_hash: Digest,
    block_body_mast_hash: Digest,
}

impl From<BlockPrimitiveWitness> for TransactionIsValidWitness {
    fn from(block_primitive_witness: BlockPrimitiveWitness) -> Self {
        let block_body = block_primitive_witness.body();
        let mast_path_txk = block_body.mast_path(BlockBodyField::TransactionKernel);
        let TransactionProof::SingleProof(single_proof) =
            &block_primitive_witness.transaction.proof
        else {
            panic!("cannot make a block whose transaction is not supported by a single proof");
        };
        let txk_mast_hash = block_body.transaction_kernel.mast_hash();
        let block_body_mast_hash = block_body.mast_hash();
        Self {
            single_proof: single_proof.to_owned(),
            mast_path_txk,
            txk_mast_hash,
            block_body_mast_hash,
        }
    }
}

impl SecretWitness for TransactionIsValidWitness {
    fn standard_input(&self) -> PublicInput {
        self.block_body_mast_hash
            .reversed()
            .values()
            .to_vec()
            .into()
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

        let claim = SingleProof::claim(self.txk_mast_hash);
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

impl TransactionIsValid {
    pub(crate) fn claim(block_body_mast_hash: Digest) -> Claim {
        let input = block_body_mast_hash.reversed().values().to_vec();

        Claim::new(Self.hash()).with_input(input)
    }
}

impl ConsensusProgram for TransactionIsValid {
    /// Get the program hash digest.
    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }

    fn source(&self) {
        let block_body_mast_hash: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let witness: TransactionIsValidWitness = tasmlib::decode_from_memory(start_address);

        tasmlib::tasmlib_hashing_merkle_verify(
            block_body_mast_hash,
            BlockBodyField::TransactionKernel as u32,
            Tip5::hash_varlen(&witness.txk_mast_hash.encode()),
            BlockBodyField::COUNT.next_power_of_two().ilog2(),
        );

        let claim = SingleProof::claim(witness.txk_mast_hash);
        tasmlib::verify_stark(Stark::default(), &claim, &witness.single_proof);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let merkle_verify = library.import(Box::new(MerkleVerify));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let witness_field_txkmh = field!(TransactionIsValidWitness::txk_mast_hash);
        let witness_field_single_proof = field!(TransactionIsValidWitness::single_proof);
        let authenticate_txkmh = triton_asm! {
            // _ [bbmh] *witness

            push {BlockBodyField::COUNT.next_power_of_two().ilog2()}
            push {BlockBodyField::TransactionKernel as u32}
            pick 2

            {&witness_field_txkmh}
            // _ [bbmh] height index *txkmh

            push {Digest::LEN}
            call {hash_varlen}
            // _ [bbmh] height index [txkmh_as_leaf]

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

        let main = triton_asm! {
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
        };

        let imports = library.all_imports();
        triton_asm! {
            {&main}
            {&imports}
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;

    #[test]
    fn transaction_is_valid_halts_gracefully() {
        let block_primitive_witness = deterministic_block_primitive_witness();
        let transaction_is_valid_witness = TransactionIsValidWitness::from(block_primitive_witness);
        let input = transaction_is_valid_witness.standard_input();
        let nondeterminism = transaction_is_valid_witness.nondeterminism();
        let rust_result = TransactionIsValid
            .run_rust(&input, nondeterminism.clone())
            .unwrap();
        let tasm_result = TransactionIsValid.run_tasm(&input, nondeterminism).unwrap();

        assert_eq!(rust_result, tasm_result);
    }
}
