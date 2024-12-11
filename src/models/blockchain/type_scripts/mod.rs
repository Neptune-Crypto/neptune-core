pub mod known_type_scripts;
pub mod native_currency;
pub mod neptune_coins;
pub mod time_lock;

use std::collections::HashMap;
use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;

use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use native_currency::NativeCurrency;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::prelude::Digest;

use super::transaction::primitive_witness::SaltedUtxos;
use super::transaction::transaction_kernel::TransactionKernel;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::prove_consensus_program;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::Hash;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScript {
    program: Program,
}

// Standard hash needed for filtering out duplicates.
impl StdHash for TypeScript {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.encode(), state);
    }
}

impl From<Vec<LabelledInstruction>> for TypeScript {
    fn from(instrs: Vec<LabelledInstruction>) -> Self {
        Self::new(Program::new(&instrs))
    }
}

impl From<&[LabelledInstruction]> for TypeScript {
    fn from(instrs: &[LabelledInstruction]) -> Self {
        Self::new(Program::new(instrs))
    }
}

impl TypeScript {
    pub fn new(program: Program) -> Self {
        Self { program }
    }

    #[cfg(test)]
    pub fn hash(&self) -> Digest {
        self.program.hash()
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    pub fn native_currency() -> Self {
        Self::new(NativeCurrency.program())
    }
}

pub trait TypeScriptWitness {
    fn new(
        transaction_kernel: TransactionKernel,
        salted_input_utxos: SaltedUtxos,
        salted_output_utxos: SaltedUtxos,
    ) -> Self;
    fn transaction_kernel(&self) -> TransactionKernel;
    fn salted_input_utxos(&self) -> SaltedUtxos;
    fn salted_output_utxos(&self) -> SaltedUtxos;
    fn type_script_and_witness(&self) -> TypeScriptAndWitness;
    fn type_script_standard_input(&self) -> PublicInput {
        PublicInput::new(
            [
                self.transaction_kernel().mast_hash().reversed().values(),
                Hash::hash(&self.salted_input_utxos()).reversed().values(),
                Hash::hash(&self.salted_output_utxos()).reversed().values(),
            ]
            .concat()
            .to_vec(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScriptAndWitness {
    pub program: Program,
    nd_tokens: Vec<BFieldElement>,
    nd_memory: Vec<(BFieldElement, BFieldElement)>,
    nd_digests: Vec<Digest>,
}

impl From<TypeScriptAndWitness> for TypeScript {
    fn from(type_script_and_witness: TypeScriptAndWitness) -> Self {
        Self::new(type_script_and_witness.program)
    }
}

impl From<&TypeScriptAndWitness> for TypeScript {
    fn from(type_script_and_witness: &TypeScriptAndWitness) -> Self {
        Self::new(type_script_and_witness.program.clone())
    }
}

impl TypeScriptAndWitness {
    pub fn new_with_nondeterminism(program: Program, witness: NonDeterminism) -> Self {
        Self {
            program,
            nd_memory: witness.ram.into_iter().collect(),
            nd_tokens: witness.individual_tokens,
            nd_digests: witness.digests,
        }
    }

    pub fn new(program: Program) -> Self {
        Self {
            program,
            nd_memory: vec![],
            nd_tokens: vec![],
            nd_digests: vec![],
        }
    }

    pub fn new_with_tokens(program: Program, tokens: Vec<BFieldElement>) -> Self {
        Self {
            program,
            nd_memory: vec![],
            nd_tokens: tokens,
            nd_digests: vec![],
        }
    }

    pub fn nondeterminism(&self) -> NonDeterminism {
        NonDeterminism::new(self.nd_tokens.clone())
            .with_digests(self.nd_digests.clone())
            .with_ram(self.nd_memory.iter().cloned().collect::<HashMap<_, _>>())
    }

    pub fn halts_gracefully(
        &self,
        txk_mast_hash: Digest,
        salted_inputs_hash: Digest,
        salted_outputs_hash: Digest,
    ) -> bool {
        let standard_input = [txk_mast_hash, salted_inputs_hash, salted_outputs_hash]
            .into_iter()
            .flat_map(|d| d.reversed().values().to_vec())
            .collect_vec();
        let public_input = PublicInput::new(standard_input);

        VM::run(self.program.clone(), public_input, self.nondeterminism()).is_ok()
    }

    /// Assuming the type script halts gracefully, prove it.
    pub(crate) async fn prove(
        &self,
        txk_mast_hash: Digest,
        salted_inputs_hash: Digest,
        salted_outputs_hash: Digest,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Proof> {
        let input = [txk_mast_hash, salted_inputs_hash, salted_outputs_hash]
            .into_iter()
            .flat_map(|d| d.reversed().values())
            .collect_vec();
        let claim = Claim::new(self.program.hash()).with_input(input);
        prove_consensus_program(
            self.program.clone(),
            claim,
            self.nondeterminism(),
            triton_vm_job_queue,
            proof_job_options,
        )
        .await
    }
}

impl<'a> Arbitrary<'a> for TypeScriptAndWitness {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let program = Program::arbitrary(u)?;
        let tokens = Digest::arbitrary(u)?.reversed().values().to_vec();
        Ok(TypeScriptAndWitness::new_with_tokens(program, tokens))
    }
}

impl std::hash::Hash for TypeScriptAndWitness {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.program.instructions.hash(state);
        self.nd_tokens.hash(state);
        self.nd_memory.hash(state);
        self.nd_digests.hash(state);
    }
}
