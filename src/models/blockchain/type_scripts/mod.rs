use crate::{
    models::proof_abstractions::{
        mast_hash::MastHash,
        tasm::program::{prove_consensus_program, ConsensusProgram},
    },
    Hash,
};
use arbitrary::Arbitrary;
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    hash::{Hash as StdHash, Hasher as StdHasher},
};
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        prelude::BFieldElement,
        program::{NonDeterminism, Program, PublicInput},
        proof::{Claim, Proof},
    },
    twenty_first::{
        math::bfield_codec::BFieldCodec, util_types::algebraic_hasher::AlgebraicHasher,
    },
    Digest,
};

use self::native_currency::NativeCurrency;

use super::transaction::{primitive_witness::SaltedUtxos, transaction_kernel::TransactionKernel};

pub mod native_currency;
pub mod neptune_coins;
pub mod time_lock;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct TypeScript {
    pub program: Program,
}

// Standard hash needed for filtering out duplicates.
impl StdHash for TypeScript {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.program.instructions.hash(state);
    }
}

impl From<Vec<LabelledInstruction>> for TypeScript {
    fn from(instrs: Vec<LabelledInstruction>) -> Self {
        Self {
            program: Program::new(&instrs),
        }
    }
}

impl From<&[LabelledInstruction]> for TypeScript {
    fn from(instrs: &[LabelledInstruction]) -> Self {
        Self {
            program: Program::new(instrs),
        }
    }
}

impl TypeScript {
    pub fn new(program: Program) -> Self {
        Self { program }
    }

    pub fn hash(&self) -> Digest {
        self.program.hash::<Hash>()
    }

    pub fn native_currency() -> Self {
        Self {
            program: NativeCurrency.program(),
        }
    }
}

pub trait TypeScriptWitness {
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
        Self {
            program: type_script_and_witness.program,
        }
    }
}

impl From<&TypeScriptAndWitness> for TypeScript {
    fn from(type_script_and_witness: &TypeScriptAndWitness) -> Self {
        Self {
            program: type_script_and_witness.program.clone(),
        }
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
        self.program
            .run(
                public_input,
                NonDeterminism::new(self.nd_tokens.clone())
                    .with_digests(self.nd_digests.clone())
                    .with_ram(self.nd_memory.iter().cloned().collect::<HashMap<_, _>>()),
            )
            .is_ok()
    }

    /// Assuming the type script halts gracefully, prove it.
    pub fn prove(
        &self,
        txk_mast_hash: Digest,
        salted_inputs_hash: Digest,
        salted_outputs_hash: Digest,
    ) -> Proof {
        let input = [txk_mast_hash, salted_inputs_hash, salted_outputs_hash]
            .into_iter()
            .flat_map(|d| d.reversed().values())
            .collect_vec();
        let claim = Claim::new(self.program.hash::<Hash>()).with_input(input);
        prove_consensus_program(self.program.clone(), claim, self.nondeterminism())
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
