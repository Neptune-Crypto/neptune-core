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

#[derive(Debug, Clone, thiserror::Error)]
pub enum JobError {
    #[error("triton-vm program complexity limit exceeded.  result: {result},  limit: {limit}")]
    ProofComplexityLimitExceeded { limit: u32, result: u32 },

    // note: this should be #[from VmProcessError].
    // however JobError must be clonable and VmProcessError is
    // not easily clonable, so this is a compromise.
    #[error("external proving process failed")]
    TritonVmProverFailed(String),
}

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

    #[error("proving process did not return any exit code")]
    NoExitCode,
}

#[derive(Debug)]
pub struct ConsensusProgramProverJobResult(pub Result<Proof, JobError>);
impl JobResult for ConsensusProgramProverJobResult {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl From<&ConsensusProgramProverJobResult> for Result<Proof, JobError> {
    fn from(v: &ConsensusProgramProverJobResult) -> Self {
        v.0.clone()
    }
}

#[derive(Debug, Clone, Default, Copy)]
pub(crate) struct JobSettings {
    pub(crate) max_log2_padded_height_for_proofs: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct ConsensusProgramProverJob {
    pub program: Program,
    pub claim: Claim,
    pub nondeterminism: NonDeterminism,
    pub job_settings: JobSettings,
}

impl ConsensusProgramProverJob {
    /// Run the program and generate a proof for it, assuming the Triton VM run
    /// halts gracefully.
    ///
    /// If we are in a test environment, try reading it from disk. If it is not
    /// there, generate it and store it to disk.
    async fn prove(&self) -> Result<Proof, JobError> {
        assert_eq!(self.program.hash(), self.claim.program_digest);

        let mut vm_state = VMState::new(
            &self.program,
            self.claim.input.clone().into(),
            self.nondeterminism.clone(),
        );
        maybe_write_debuggable_program_to_disk(&self.program, &vm_state);

        // run program in VM
        //
        // for now this seems to run fast enough it does not need to be in a spawn-blocking
        // or even in external process.  But we use ScopeDurationLogger to log a warning
        // if a slower run is encountered.
        let vm_output = {
            let _ =
                crate::ScopeDurationLogger::new_with_threshold(&crate::macros::fn_name!(), 0.00001);

            if let Err(e) = vm_state.run() {
                panic!("VM run prior to proving should halt gracefully.\n{e}");
            }
            vm_state.public_output
        };
        assert_eq!(self.claim.program_digest, self.program.hash());
        assert_eq!(self.claim.output, vm_output);

        tracing::debug!("job settings: {:?}", self.job_settings);

        let padded_height = vm_state.cycle_count.next_power_of_two();
        match self.job_settings.max_log2_padded_height_for_proofs {
            Some(limit) if 2u32.pow(limit.into()) < padded_height => {
                return Err(JobError::ProofComplexityLimitExceeded {
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
            self.prove_out_of_process()
                .await
                .map_err(|e| JobError::TritonVmProverFailed(e.to_string()))
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

            let mut child_stdin = child
                .stdin
                .take()
                .ok_or_else(|| VmProcessError::StdinUnavailable)?;
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
    /// note: we do not verify that the path exists.  That will occur anyway
    /// when triton-vm-prover is executed.
    #[cfg(not(test))]
    fn path_to_triton_vm_prover() -> Result<std::path::PathBuf, std::io::Error> {
        let mut exe_path = std::env::current_exe()?;
        exe_path.set_file_name("triton-vm-prover");
        Ok(exe_path)
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
