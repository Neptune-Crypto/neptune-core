use std::panic::{catch_unwind, RefUnwindSafe};

use itertools::Itertools;
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        program::{NonDeterminism, Program},
    },
    twenty_first::math::b_field_element::BFieldElement,
    Digest,
};

use crate::models::blockchain::shared::Hash;

use super::environment;

pub enum ConsensusError {
    RustShadowPanic(String),
}

/// A `ConsensusProgram` represents the logic at a terminal (atomic) node of the
/// abstract syntax tree.
pub trait ConsensusProgram
where
    Self: RefUnwindSafe,
{
    /// The canonical reference source code for the consensus program, written in the
    /// subset of rust that the tasm-lang compiler understands. To run this program, call
    /// [`run`][`run`], which spawns a new thread, boots the environment, and executes
    /// the program.
    fn source(&self);

    /// A derivative of source, in Triton-assembler (tasm) rather than rust. Either
    /// produced automatically or hand-optimized.
    fn code(&self) -> Vec<LabelledInstruction>;

    /// Get the program as a `Program` object rather than as a list of `LabelledInstruction`s.
    fn program(&self) -> Program {
        Program::new(&self.code())
    }

    /// Get the program hash digest.
    fn hash(&self) -> Digest {
        self.program().hash::<Hash>()
    }

    /// Run the source program natively in rust, but with the emulated TritonVM
    /// environment for input, output, nondeterminism, and program digest.
    fn run(
        &self,
        input: &[BFieldElement],
        nondeterminism: NonDeterminism,
    ) -> Result<Vec<BFieldElement>, ConsensusError> {
        println!(
            "Running consensus program with input: {}",
            input.iter().map(|b| b.value()).join(",")
        );
        let emulation_result = catch_unwind(|| {
            environment::init(self.hash(), input, nondeterminism);
            self.source();
            environment::PUB_OUTPUT.take()
        });
        match emulation_result {
            Ok(result) => Result::Ok(result),
            Err(e) => Result::Err(ConsensusError::RustShadowPanic(format!("{:?}", e))),
        }
    }
}
