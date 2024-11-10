//! implements a triton-vm-job-queue job for proving
//! consensus programs.
//!
//! These proofs take a lot of time, cpu, and memory to
//! create. As such, only one should execute at a time
//! or even the beefiest of today's hardware might run out
//! of resources.
//!
//! The queue is used to ensure that only one triton-vm
//! program can execute at a time.
#[cfg(not(test))]
use std::process::Stdio;
#[cfg(not(test))]
use tokio::io::AsyncWriteExt;

use crate::job_queue::traits::Job;
use crate::job_queue::traits::JobResult;
#[cfg(test)]
use crate::models::proof_abstractions::tasm::program::test;
use crate::models::proof_abstractions::Claim;
use crate::models::proof_abstractions::NonDeterminism;
use crate::models::proof_abstractions::Program;
use crate::tasm_lib::maybe_write_debuggable_program_to_disk;
use crate::triton_vm::proof::Proof;
use crate::triton_vm::vm::VMState;
use crate::triton_vm::vm::VM;

#[derive(Debug)]
pub struct ConsensusProgramProverJobResult(pub Proof);
impl JobResult for ConsensusProgramProverJobResult {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl From<&ConsensusProgramProverJobResult> for Proof {
    fn from(v: &ConsensusProgramProverJobResult) -> Self {
        v.0.to_owned()
    }
}

#[derive(Debug, Clone)]
pub struct ConsensusProgramProverJob {
    pub program: Program,
    pub claim: Claim,
    pub nondeterminism: NonDeterminism,
}

impl ConsensusProgramProverJob {
    async fn prove(&self) -> Proof {
        match self.prove_worker().await {
            Ok(p) => p,
            Err(e) => panic!("Proving job failed with error: {:?}", e),
        }
    }

    /// Run the program and generate a proof for it, assuming the Triton VM run
    /// halts gracefully.
    ///
    /// If we are in a test environment, try reading it from disk. If it is not
    /// there, generate it and store it to disk.
    async fn prove_worker(&self) -> anyhow::Result<Proof> {
        assert_eq!(self.program.hash(), self.claim.program_digest);

        let init_vm_state = VMState::new(
            &self.program,
            self.claim.input.clone().into(),
            self.nondeterminism.clone(),
        );
        maybe_write_debuggable_program_to_disk(&self.program, &init_vm_state);

        // run program in VM
        //
        // for now this seems to run fast enough it does not need to be in a spawn-blocking
        // or even in external process.  But we use ScopeDurationLogger to log a warning
        // if a slower run is encountered.
        let vm_output = {
            let _ =
                crate::ScopeDurationLogger::new_with_threshold(&crate::macros::fn_name!(), 0.00001);

            VM::run(
                &self.program,
                self.claim.input.clone().into(),
                self.nondeterminism.clone(),
            )
        };
        assert!(vm_output.is_ok());
        assert_eq!(self.claim.program_digest, self.program.hash());
        assert_eq!(self.claim.output, vm_output?);

        #[cfg(test)]
        {
            Ok(test::load_proof_or_produce_and_save(
                &self.claim,
                self.program.clone(),
                self.nondeterminism.clone(),
            ))
        }
        #[cfg(not(test))]
        {
            self.prove_out_of_process().await
        }
    }

    /// runs triton-vm prover out of process.
    ///
    /// input is sent via stdin, output is received via stdout.
    /// stderr is ignored.
    ///
    /// The prover executable is triton-vm-prover.  Presently
    /// it must be in $PATH.
    ///
    /// todo: figure out how to exec correct executable for
    /// release, debug, etc.
    ///
    /// parameters claim, program, nondeterminism are passed as
    /// json strings.
    ///
    /// the result is a [Proof], which is bincode serialized.
    ///
    /// The process result is only read if exit code is 0.
    /// A non-zero exit code or no code results in an error.
    #[cfg(not(test))]
    async fn prove_out_of_process(&self) -> anyhow::Result<Proof> {
        // start child process
        let child_handle = {
            let inputs = [
                serde_json::to_string(&self.claim)?,
                serde_json::to_string(&self.program)?,
                serde_json::to_string(&self.nondeterminism)?,
            ];

            let mut child = tokio::process::Command::new("triton-vm-prover")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?;

            let mut child_stdin = child.stdin.take().expect("should get stdin handle");
            child_stdin.write_all(inputs.join("\n").as_bytes()).await?;

            child
        };

        // read result from child process stdout.
        {
            let op = child_handle.wait_with_output().await?;
            match op.status.code() {
                Some(0) => {
                    let proof = bincode::deserialize(&op.stdout)?;
                    Ok(proof)
                }
                Some(code) => Err(anyhow::anyhow!("prover exited with exit code: {}", code)),
                None => Err(anyhow::anyhow!("prover exited without any exit code")),
            }
        }
    }
}

#[async_trait::async_trait]
impl Job for ConsensusProgramProverJob {
    // see trait doc-comment
    fn is_async(&self) -> bool {
        true
    }

    // see trait doc-comment
    async fn run_async(&self) -> Box<dyn JobResult> {
        Box::new(ConsensusProgramProverJobResult(self.prove().await))
    }
}
