use std::panic::{catch_unwind, RefUnwindSafe};

use itertools::Itertools;
use tasm_lib::{
    maybe_write_debuggable_program_to_disk,
    triton_vm::{
        error::InstructionError,
        instruction::LabelledInstruction,
        program::{NonDeterminism, Program, PublicInput},
        proof::{Claim, Proof},
        vm::VMState,
    },
    twenty_first::math::b_field_element::BFieldElement,
    Digest,
};

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
    Self: RefUnwindSafe + Clone,
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
        self.program().hash()
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
    ///
    /// If we are in the test environment, try reading it from disk. And if it
    /// not there, generate it and store it to disk.
    ///
    /// This method is a thin wrapper around [`prove_consensus_program`], which
    /// does the same but for arbitrary programs.
    fn prove(&self, claim: &Claim, nondeterminism: NonDeterminism) -> Proof {
        prove_consensus_program(self.program(), claim.clone(), nondeterminism)
    }
}

/// Run the program and generate a proof for it, assuming the Triton VM run
/// halts gracefully.
///
/// If we are in a test environment, try reading it from disk. If it is not
/// there, generate it and store it to disk.
///
/// This method works for arbitrary programs, including ones that do not
/// implement trait [`ConsensusProgram`].
///
// Currently, only lock scripts and type scripts fit that description. It may be
// worthwhile to investigate whether they can be made to implement
// ConsensusProgram.
pub fn prove_consensus_program(
    program: Program,
    claim: Claim,
    nondeterminism: NonDeterminism,
) -> Proof {
    assert_eq!(program.hash(), claim.program_digest);
    #[cfg(test)]
    let proof = test::load_proof_or_produce_and_save(
        claim.clone(),
        program.clone(),
        nondeterminism.clone(),
    );
    #[cfg(not(test))]
    let proof = tasm_lib::triton_vm::prove(
        tasm_lib::triton_vm::stark::Stark::default(),
        &claim,
        &program,
        nondeterminism.clone(),
    )
    .unwrap();

    let vm_output = program.run(PublicInput::new(claim.input.clone()), nondeterminism);
    assert!(vm_output.is_ok());
    assert_eq!(claim.program_digest, program.hash());
    assert_eq!(claim.output, vm_output.unwrap());

    proof
}

#[cfg(test)]
pub mod test {
    use std::{
        fs::{create_dir_all, File},
        io::{stdout, Read, Write},
        path::{Path, PathBuf},
    };

    use crate::triton_vm::program::NonDeterminism;
    use crate::triton_vm::stark::Stark;
    use itertools::Itertools;
    use std::time::SystemTime;
    use tasm_lib::triton_vm;
    use tasm_lib::{
        triton_vm::{
            prelude::BFieldElement,
            program::Program,
            proof::{Claim, Proof},
        },
        twenty_first::util_types::algebraic_hasher::AlgebraicHasher,
    };

    use crate::models::blockchain::shared::Hash;

    /// Derive a file name from the claim
    fn proof_filename(claim: Claim) -> String {
        Hash::hash(
            &[
                Hash::hash(&claim.input),
                claim.program_digest,
                Hash::hash(&claim.output),
            ]
            .into_iter()
            .flat_map(|d| d.values())
            .collect_vec(),
        )
        .to_hex()
    }

    /// Tries to load a proof for the claim from the test_data directory
    fn load_proof_if_available(claim: Claim) -> Option<Proof> {
        let name = proof_filename(claim);
        let mut path = PathBuf::new();
        path.push("test_data");
        path.push(Path::new(&name).with_extension("proof"));
        let Ok(mut input_file) = File::open(path.clone()) else {
            println!(
                "cannot open file '{}' -- might not exist",
                path.to_string_lossy()
            );
            return None;
        };
        let mut file_contents = vec![];
        if input_file.read_to_end(&mut file_contents).is_err() {
            println!("cannot read file '{}'", path.to_string_lossy());
            return None;
        }
        let mut proof_data = vec![];
        for ch in file_contents.chunks(8) {
            if let Ok(eight_bytes) = TryInto::<[u8; 8]>::try_into(ch) {
                proof_data.push(BFieldElement::new(u64::from_be_bytes(eight_bytes)));
            } else {
                println!("cannot cast chunk to eight bytes");
                return None;
            }
        }
        let proof = Proof(proof_data);
        Some(proof)
    }

    /// Call Triton VM prover to produce a proof and save it to disk.
    fn produce_and_save_proof(
        claim: Claim,
        program: Program,
        nondeterminism: NonDeterminism,
    ) -> Proof {
        let name = proof_filename(claim.clone());
        let mut path = PathBuf::new();
        path.push("test_data");
        create_dir_all(&path).expect("cannot create 'test_data' directory");
        path.push(Path::new(&name).with_extension("proof"));

        let proof = triton_vm::prove(Stark::default(), &claim, &program, nondeterminism)
            .expect("cannot produce proof");

        let proof_data = proof
            .0
            .iter()
            .copied()
            .flat_map(|b| b.value().to_be_bytes())
            .collect_vec();
        let mut output_file = File::create(&path).expect("cannot open file for writing");
        output_file
            .write_all(&proof_data)
            .expect("cannot write to file");

        proof
    }

    /// Load a proof for the claim if it exists; otherwise, run the prover and
    /// save it before returning it.
    pub fn load_proof_or_produce_and_save(
        claim: Claim,
        program: Program,
        nondeterminism: NonDeterminism,
    ) -> Proof {
        let name = proof_filename(claim.clone());
        match load_proof_if_available(claim.clone()) {
            Some(proof) => {
                println!(" - Loaded proof from disk: {name}.");
                proof
            }
            None => {
                print!(" - Proving ... ");
                stdout().flush().expect("could not flush terminal");
                let tick = SystemTime::now();
                let proof = produce_and_save_proof(claim, program, nondeterminism);
                let duration = SystemTime::now().duration_since(tick).unwrap();
                println!(
                    "success! Proof time: {:?}. Proof stored to disk: {name}",
                    duration
                );
                proof
            }
        }
    }
}
