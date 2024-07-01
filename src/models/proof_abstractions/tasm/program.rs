use std::panic::{catch_unwind, RefUnwindSafe};

use itertools::Itertools;
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        program::{NonDeterminism, Program, PublicInput},
    },
    twenty_first::math::b_field_element::BFieldElement,
    Digest,
};

use crate::models::blockchain::shared::Hash;

use super::environment;

#[derive(Debug, Clone)]
pub enum ConsensusError {
    RustShadowPanic(String),
}

/// A `ConsensusProgram` represents the logic subprogram for transaction or
/// block validity.
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
        input: &PublicInput,
        nondeterminism: NonDeterminism,
    ) -> Result<Vec<BFieldElement>, ConsensusError> {
        println!(
            "Running consensus program with input: {}",
            input.individual_tokens.iter().map(|b| b.value()).join(",")
        );
        let program_digest = catch_unwind(|| self.hash()).unwrap_or_default();
        let emulation_result = catch_unwind(|| {
            environment::init(program_digest, &input.individual_tokens, nondeterminism);
            self.source();
            environment::PUB_OUTPUT.take()
        });
        match emulation_result {
            Ok(result) => Result::Ok(result),
            Err(e) => Result::Err(ConsensusError::RustShadowPanic(format!("{:?}", e))),
        }
    }
}
