use strum::EnumCount;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::TasmObject;
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
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins::tasmlib_hashing_merkle_verify;
use crate::models::proof_abstractions::tasm::builtins::verify_stark;
use crate::models::proof_abstractions::tasm::builtins::{self as tasmlib};
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;

use super::block_primitive_witness::BlockPrimitiveWitness;

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub(crate) struct TransactionIsValidWitness {
    transaction_kernel: TransactionKernel,
    single_proof: Proof,
    body_mast_path: Vec<Digest>,
    body_mast_root: Digest,
}

impl From<BlockPrimitiveWitness> for TransactionIsValidWitness {
    fn from(mut block_primitive_witness: BlockPrimitiveWitness) -> Self {
        let mast_path = block_primitive_witness
            .body()
            .mast_path(BlockBodyField::Transaction);
        let mast_root = block_primitive_witness.body().mast_hash();
        let TransactionProof::SingleProof(single_proof) = block_primitive_witness.transaction.proof
        else {
            panic!("cannot make a block whose transaction is not supported by a single proof");
        };
        Self {
            transaction_kernel: block_primitive_witness.transaction.kernel,
            single_proof,
            body_mast_path: mast_path,
            body_mast_root: mast_root,
        }
    }
}

impl SecretWitness for TransactionIsValidWitness {
    fn standard_input(&self) -> PublicInput {
        self.body_mast_root.reversed().values().to_vec().into()
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
            .extend_from_slice(&self.body_mast_path);

        let claim = Claim::new(SingleProof.hash()).with_input(
            self.transaction_kernel
                .mast_hash()
                .reversed()
                .values()
                .to_vec(),
        );
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
        let transaction_kernel_mast_hash: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let witness: TransactionIsValidWitness = tasmlib::decode_from_memory(start_address);

        tasmlib_hashing_merkle_verify(
            witness.body_mast_root,
            BlockBodyField::Transaction as u32,
            transaction_kernel_mast_hash,
            BlockBodyField::COUNT.next_power_of_two().ilog2(),
        );

        let claim = Claim::new(SingleProof.hash())
            .with_input(transaction_kernel_mast_hash.reversed().values().to_vec());
        verify_stark(Stark::default(), &claim, &witness.single_proof);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
