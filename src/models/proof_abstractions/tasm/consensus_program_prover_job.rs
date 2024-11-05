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

use std::process::Stdio;

use serde::Deserialize;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use crate::job_queue::traits::Job;
use crate::job_queue::traits::JobResult;
use crate::job_queue::traits::Synchronicity;
#[cfg(test)]
use crate::models::proof_abstractions::tasm::program::test;
use crate::models::proof_abstractions::Claim;
use crate::models::proof_abstractions::NonDeterminism;
use crate::models::proof_abstractions::Program;
use crate::tasm_lib::maybe_write_debuggable_program_to_disk;
use crate::triton_vm::proof::Proof;
use crate::triton_vm::vm::VMState;
use crate::triton_vm::vm::VM;

#[derive(Debug, Deserialize, Serialize)]
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
    /// Run the program and generate a proof for it, assuming the Triton VM run
    /// halts gracefully.
    ///
    /// If we are in a test environment, try reading it from disk. If it is not
    /// there, generate it and store it to disk.
    fn prove(&self) -> Proof {
        assert_eq!(self.program.hash(), self.claim.program_digest);

        let init_vm_state = VMState::new(
            &self.program,
            self.claim.input.clone().into(),
            self.nondeterminism.clone(),
        );
        maybe_write_debuggable_program_to_disk(&self.program, &init_vm_state);

        let vm_output = VM::run(
            &self.program,
            self.claim.input.clone().into(),
            self.nondeterminism.clone(),
        );
        assert!(vm_output.is_ok());
        assert_eq!(self.claim.program_digest, self.program.hash());
        assert_eq!(self.claim.output, vm_output.unwrap());

        #[cfg(test)]
        {
            test::load_proof_or_produce_and_save(
                &self.claim,
                self.program.clone(),
                self.nondeterminism.clone(),
            )
        }
        #[cfg(not(test))]
        {
            tasm_lib::triton_vm::prove(
                tasm_lib::triton_vm::stark::Stark::default(),
                &self.claim,
                &self.program,
                self.nondeterminism.clone(),
            )
            .unwrap()
        }
    }
}

#[async_trait::async_trait]
impl Job for ConsensusProgramProverJob {
    type ResultType = ConsensusProgramProverJobResult;

    fn synchronicity(&self) -> Synchronicity {
        Synchronicity::Process
    }

    async fn process(&self) -> tokio::process::Child {
        let claim = serde_json::to_string(&self.claim).unwrap();
        let program = serde_json::to_string(&self.program).unwrap();
        let nondeterminism = serde_json::to_string(&self.nondeterminism).unwrap();

        let mut child = tokio::process::Command::new("triton-vm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let child_stdin = child.stdin.as_mut().unwrap();
        child_stdin.write_all(claim.as_bytes()).await.unwrap();
        child_stdin.write_all(b"\n").await.unwrap();
        child_stdin.write_all(program.as_bytes()).await.unwrap();
        child_stdin.write_all(b"\n").await.unwrap();
        child_stdin
            .write_all(nondeterminism.as_bytes())
            .await
            .unwrap();
        child_stdin.write_all(b"\n").await.unwrap();

        child
    }
}
