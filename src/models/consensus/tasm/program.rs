use std::panic::catch_unwind;

use itertools::Itertools;
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction, program::{NonDeterminism, Program}
    },
    twenty_first::shared_math::b_field_element::BFieldElement,
    Digest,
};

use crate::models::blockchain::shared::Hash;

use super::environment;

pub enum ConsensusError {
    RustShadowPanic(String)
}

pub trait ConsensusProgram {
    /// The canonical reference source code for the consensus program, written in the
    /// subset of rust that the tasm-lang compiler understands. To run this program, call
    /// [`run`][`run`], which spawns a new thread, boots the environment, and executes
    /// the program.
    fn source();

    /// A derivative of source, in Triton-assembler (tasm) rather than rust. Either
    /// produced automatically or hand-optimized.
    fn code() -> Vec<LabelledInstruction>;

    /// Get the program hash digest.
    fn hash() -> Digest {
        Program::new(&Self::code()).hash::<Hash>()
    }

    /// Run the source program natively in rust, but with the emulated TritonVM
    /// environment for input, output, nondeterminism, and program digest.
    fn run(
        input: &[BFieldElement],
        nondeterminism: NonDeterminism<BFieldElement>,
    ) -> Result<Vec<BFieldElement>, ConsensusError> {
        println!("Running consensus program with input: {}", input.iter().map(|b|b.value()).join(","));
        match catch_unwind(||
            {
                environment::init(input, nondeterminism);
                Self::source();
                environment::PUB_OUTPUT.take()
            }) {
                Ok(result) => Result::Ok(result),
                Err(e) => {
                    Result::Err(ConsensusError::RustShadowPanic(format!("{:?}", e)))
                },
            }
    }
}
