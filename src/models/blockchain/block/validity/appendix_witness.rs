use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::PublicInput;
use tasm_lib::Digest;

use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction::Transaction;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;

use super::block_program::BlockProgram;

/// All information necessary to efficiently produce a proof for a block.
///
/// This is the witness for the [`BlockProgram`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub(crate) struct AppendixWitness {
    block_body_hash: Digest,
    pub(crate) claims: Vec<Claim>,
    pub(crate) proofs: Vec<Proof>,
}

impl AppendixWitness {
    pub(crate) fn new(block_body: &BlockBody, claims: Vec<Claim>, proofs: Vec<Proof>) -> Self {
        Self {
            block_body_hash: block_body.mast_hash(),
            claims,
            proofs,
        }
    }

    pub(crate) fn claims(&self) -> Vec<Claim> {
        self.claims.clone()
    }

    pub(crate) fn produce(
        block_body: BlockBody,
        predecessor_block: &Block,
        transaction: &Transaction,
    ) -> AppendixWitness {
        todo!()
    }
}

impl SecretWitness for AppendixWitness {
    fn standard_input(&self) -> PublicInput {
        self.block_body_hash.reversed().values().into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        self.claims().encode()
    }

    fn program(&self) -> Program {
        Program::new(&BlockProgram.code())
    }

    fn nondeterminism(&self) -> NonDeterminism {
        todo!()
    }
}
