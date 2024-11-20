//! Implements a triton-vm-job-queue job for proving
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
use tasm_lib::maybe_write_debuggable_vm_state_to_disk;
#[cfg(not(test))]
use tokio::io::AsyncWriteExt;

use crate::job_queue::traits::Job;
use crate::job_queue::traits::JobResult;
use crate::macros::fn_name;
use crate::macros::log_scope_duration;
#[cfg(test)]
use crate::models::proof_abstractions::tasm::program::test;
use crate::models::proof_abstractions::Claim;
use crate::models::proof_abstractions::NonDeterminism;
use crate::models::proof_abstractions::Program;
use crate::triton_vm::proof::Proof;
use crate::triton_vm::vm::VMState;

/// represents an error running a [ProverJob]
#[derive(Debug, thiserror::Error)]
pub enum ProverJobError {
    #[error("triton-vm program complexity limit exceeded. result: {result}, limit: {limit}")]
    ProofComplexityLimitExceeded { limit: u32, result: u32 },

    #[error("external proving process failed")]
    TritonVmProverFailed(#[from] VmProcessError),
}

/// represents an error invoking external prover process
///
/// provides additional details for [JobError::TritonVmProverFailed]
#[derive(Debug, thiserror::Error)]
pub enum VmProcessError {
    #[error("parameter serialization failed")]
    ParameterSerializationFailed(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("stdin unavailable")]
    StdinUnavailable,

    #[error("result deserialization failed")]
    ResultDeserializationFailed(#[from] Box<bincode::ErrorKind>),

    #[error("proving process returned non-zero exit code: {0}")]
    NonZeroExitCode(i32),

    // note: on unix an exit with no code indicates the process
    // ended because of a signal, but this is not the case in
    // windows, so cannot be relied upon. There doesn't appear to
    // be any good cross-platform heuristic to determine if a process
    // ended normally or was killed.
    //
    // *if* we could determine the process was externally killed then
    // it would be reasonable to retry the job.
    #[error("proving process did not return any exit code")]
    NoExitCode,
}

#[derive(Debug)]
pub struct ProverJobResult(pub Result<Proof, ProverJobError>);
impl JobResult for ProverJobResult {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
impl From<Box<ProverJobResult>> for Result<Proof, ProverJobError> {
    fn from(v: Box<ProverJobResult>) -> Self {
        (*v).0
    }
}

#[derive(Debug, Clone, Default, Copy)]
pub(crate) struct ProverJobSettings {
    pub(crate) max_log2_padded_height_for_proofs: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct ProverJob {
    pub program: Program,
    pub claim: Claim,
    pub nondeterminism: NonDeterminism,
    pub job_settings: ProverJobSettings,
}

impl ProverJob {
    /// Run the program and generate a proof for it, assuming the Triton VM run
    /// halts gracefully.
    ///
    /// If we are in a test environment, try reading it from disk. If it is not
    /// there, generate it and store it to disk.
    async fn prove(&self) -> Result<Proof, ProverJobError> {
        assert_eq!(self.program.hash(), self.claim.program_digest);

        let mut vm_state = VMState::new(
            self.program.clone(),
            self.claim.input.clone().into(),
            self.nondeterminism.clone(),
        );
        maybe_write_debuggable_vm_state_to_disk(&vm_state);

        // run program in VM
        //
        // this is sometimes fast enough for async, but other times takes 1+ seconds.
        // As such we run it in spawn-blocking. Eventually it might make sense
        // to move into the external process.
        vm_state = {
            let join_result = tokio::task::spawn_blocking(move || {
                log_scope_duration!(fn_name!() + "::vm_state.run()");
                let r = vm_state.run();
                (vm_state, r)
            })
            .await;

            let (vm_state_moved, run_result) = match join_result {
                Ok(r) => r,
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(e) if e.is_cancelled() => {
                    panic!("VM::run() task was cancelled unexpectedly. error: {e}")
                }
                Err(e) => panic!("unexpected error from VM::run() spawn-blocking task. {e}"),
            };

            if let Err(e) = run_result {
                panic!("Triton VM should halt gracefully.\nError: {e}\n\n{vm_state_moved}");
            }
            vm_state_moved
        };
        assert_eq!(self.claim.program_digest, self.program.hash());
        assert_eq!(self.claim.output, vm_state.public_output);

        tracing::debug!("job settings: {:?}", self.job_settings);

        let padded_height = vm_state.cycle_count.next_power_of_two();
        match self.job_settings.max_log2_padded_height_for_proofs {
            Some(limit) if 2u32.pow(limit.into()) < padded_height => {
                return Err(ProverJobError::ProofComplexityLimitExceeded {
                    result: padded_height,
                    limit: 2u32.pow(limit.into()),
                })
            }
            _ => {}
        }

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
            // todo: perhaps we should retry once if process exits
            // with non-zero or no exit code.
            Ok(self.prove_out_of_process().await?)
        }
    }

    /// runs triton-vm prover out of process.
    ///
    /// input is sent via stdin, output is received via stdout.
    /// stderr is ignored.
    ///
    /// The prover executable is triton-vm-prover. Presently
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
    async fn prove_out_of_process(&self) -> Result<Proof, VmProcessError> {
        // start child process
        let child_handle = {
            let inputs = [
                serde_json::to_string(&self.claim)?,
                serde_json::to_string(&self.program)?,
                serde_json::to_string(&self.nondeterminism)?,
            ];

            let mut child = tokio::process::Command::new(Self::path_to_triton_vm_prover()?)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null()) // ignore stderr
                .spawn()?;

            let mut child_stdin = child.stdin.take().ok_or(VmProcessError::StdinUnavailable)?;
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
                Some(code) => Err(VmProcessError::NonZeroExitCode(code)),

                None => Err(VmProcessError::NoExitCode),
            }
        }
    }

    /// obtains path to triton-vm-prover executable
    ///
    /// triton-vm-prover must reside in the same directory as neptune-core.
    /// This enables debug build of neptune-core to invoke debug build of triton-vm-prover.
    /// Also works for release build, and for a package/distribution.
    ///
    /// note: we do not verify that the path exists. That will occur anyway
    /// when triton-vm-prover is executed.
    #[cfg(not(test))]
    fn path_to_triton_vm_prover() -> Result<std::path::PathBuf, std::io::Error> {
        let mut exe_path = std::env::current_exe()?;
        exe_path.set_file_name("triton-vm-prover");
        Ok(exe_path)
    }
}

#[async_trait::async_trait]
impl Job for ProverJob {
    // see trait doc-comment
    // except there is no trait doc-comment
    fn is_async(&self) -> bool {
        true
    }

    // see trait doc-comment
    async fn run_async(&self) -> Box<dyn JobResult> {
        Box::new(ProverJobResult(self.prove().await))
    }
}
