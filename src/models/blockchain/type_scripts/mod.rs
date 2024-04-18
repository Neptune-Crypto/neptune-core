use crate::{
    models::consensus::{mast_hash::MastHash, tasm::program::ConsensusProgram, ValidationLogic},
    Hash,
};
use get_size::GetSize;
use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        program::{Program, PublicInput},
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

pub trait TypeScriptWitness: ValidationLogic {
    fn transaction_kernel(&self) -> TransactionKernel;
    fn salted_input_utxos(&self) -> SaltedUtxos;
    fn salted_output_utxos(&self) -> SaltedUtxos;

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
