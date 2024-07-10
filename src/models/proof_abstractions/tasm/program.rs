use std::panic::{catch_unwind, RefUnwindSafe};

use itertools::Itertools;
use tasm_lib::{
    maybe_write_debuggable_program_to_disk,
    snippet_bencher::{write_benchmarks, BenchmarkCase, BenchmarkResult, NamedBenchmarkResult},
    triton_vm::{
        self,
        error::InstructionError,
        instruction::LabelledInstruction,
        program::{NonDeterminism, Program, PublicInput},
        proof::{Claim, Proof},
        stark::Stark,
        vm::VMState,
    },
    twenty_first::math::b_field_element::BFieldElement,
    Digest,
};

use crate::models::blockchain::shared::Hash;

use super::environment;

#[derive(Debug, Clone)]
pub enum ConsensusError {
    RustShadowPanic(String),
    TritonVMPanic(String, InstructionError),
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
    fn run_rust(
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

    /// Use Triton VM to run the tasm code.
    fn run_tasm(
        &self,
        input: &PublicInput,
        nondeterminism: NonDeterminism,
    ) -> Result<Vec<BFieldElement>, ConsensusError> {
        let program = self.program();
        let init_vm_state = VMState::new(&program, input.clone(), nondeterminism.clone());
        maybe_write_debuggable_program_to_disk(&program, &init_vm_state);
        let result = program.run(input.clone(), nondeterminism);
        match result {
            Ok(output) => Ok(output),
            Err(error) => {
                println!("VM State:\n{}\n\n", error);
                Err(ConsensusError::TritonVMPanic(
                    format!("Triton VM failed.\nVMState:\n{}", error),
                    error.source,
                ))
            }
        }
    }

    /// Run the program and generate a proof for it, assuming running halts
    /// gracefully.
    fn prove(&self, claim: &Claim, nondeterminism: NonDeterminism) -> Proof {
        triton_vm::prove(Stark::default(), &claim, &self.program(), nondeterminism).unwrap()
    }
}
