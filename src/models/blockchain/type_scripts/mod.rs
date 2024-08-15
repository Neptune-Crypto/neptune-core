pub mod native_currency;
pub mod neptune_coins;
pub mod time_lock;

use get_size::GetSize;
use native_currency::NativeCurrency;
use serde::Deserialize;
use serde::Serialize;
use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::Program;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use tasm_lib::Digest;

use crate::models::consensus::mast_hash::MastHash;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::models::consensus::ValidationLogic;
use crate::Hash;

use super::transaction::primitive_witness::SaltedUtxos;
use super::transaction::transaction_kernel::TransactionKernel;

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
