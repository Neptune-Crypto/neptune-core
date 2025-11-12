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
use tasm_lib::triton_vm::error::InstructionError;
#[cfg(not(test))]
use tokio::io::AsyncWriteExt;

use crate::application::config::network::Network;
use crate::application::config::triton_vm_env_vars::TritonVmEnvVars;
use crate::application::job_queue::channels::JobCancelReceiver;
use crate::application::job_queue::traits::Job;
use crate::application::job_queue::JobCompletion;
use crate::application::job_queue::JobResultWrapper;
use crate::macros::fn_name;
use crate::macros::log_scope_duration;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
#[cfg(test)]
use crate::protocol::proof_abstractions::tasm::program::tests;
use crate::protocol::proof_abstractions::Claim;
use crate::protocol::proof_abstractions::NonDeterminism;
use crate::protocol::proof_abstractions::Program;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;
use crate::triton_vm::vm::VMState;

/// Error code from the spawned prover process in the range 200-232 are reserved
/// for communicating that the proof is too big. The error code returned is
/// 200 + the encountered log2 padded height. So guaranteed to be in the range
/// [200-232] where no common error codes live, from what I know.
pub const PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE: i32 = 200;

/// represents an error running a [ProverJob]
#[derive(Debug, thiserror::Error)]
pub enum ProverJobError {
    /// Error code indicating that the processor table is too big. Does not
    /// refer to the actual AET which may still exceed the user-defined limit.
    #[error("triton-vm program complexity limit exceeded. result: {result}, limit: {limit}")]
    ProofComplexityLimitExceeded { limit: u32, result: u32 },

    #[error("external proving process failed: {0}")]
    TritonVmProverFailed(#[from] VmProcessError),

    #[error("machine's capability {capability} is not sufficient to produce proof: {proof_type}")]
    TooWeak {
        capability: TxProvingCapability,
        proof_type: TransactionProofType,
    },
}

/// represents an error invoking external prover process
///
/// provides additional details for [ProverJobError::TritonVmProverFailed]
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

    /// Error code indicating that AET was generated and its padded height too
    /// big.
    #[error("triton-vm program complexity limit exceeded. result: {result}, limit: {limit}")]
    ProofComplexityLimitExceeded { limit: u32, result: u32 },

    // note: on unix an exit with no code indicates the process
    // ended because of a signal, but this is not the case in
    // windows, so cannot be relied upon. There doesn't appear to
    // be any good cross-platform heuristic to determine if a process
    // ended normally or was killed.
    //
    // *if* we could determine the process was externally killed then
    // it would be reasonable to retry the job.
    #[error(
        "out-of-process triton-vm proving job terminated without exit code. \
        Possibly killed by OS. You might not have enough RAM to construct this \
        proof."
    )]
    NoExitCode,

    #[error("Triton VM failed: {0}")]
    TritonVmFailed(InstructionError),
}

enum ProverProcessCompletion {
    Finished(Proof),
    Cancelled,
}
impl From<ProverProcessCompletion> for JobCompletion {
    fn from(ppc: ProverProcessCompletion) -> Self {
        match ppc {
            ProverProcessCompletion::Finished(proof) => ProverJobResult::new(Ok(proof)).into(),
            ProverProcessCompletion::Cancelled => Self::Cancelled,
        }
    }
}
impl From<Result<ProverProcessCompletion, VmProcessError>> for JobCompletion {
    fn from(result: Result<ProverProcessCompletion, VmProcessError>) -> Self {
        match result {
            Ok(ppc) => ppc.into(),
            Err(e) => ProverJobResult::new(Err(e.into())).into(),
        }
    }
}

pub(super) type ProverJobResult = JobResultWrapper<Result<Proof, ProverJobError>>;

#[derive(Debug, Clone)]
pub struct ProverJobSettings {
    pub(crate) max_log2_padded_height_for_proofs: Option<u8>,
    pub(crate) network: Network,
    pub(crate) tx_proving_capability: TxProvingCapability,
    pub(crate) proof_type: TransactionProofType,
    pub triton_vm_env_vars: TritonVmEnvVars,
}

#[cfg(test)]
impl Default for ProverJobSettings {
    fn default() -> Self {
        Self {
            max_log2_padded_height_for_proofs: None,
            network: Network::default(),
            tx_proving_capability: TxProvingCapability::SingleProof,
            proof_type: TxProvingCapability::SingleProof.into(),
            triton_vm_env_vars: TritonVmEnvVars::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProverJob {
    program: Program,
    claim: Claim,
    nondeterminism: NonDeterminism,
    job_settings: ProverJobSettings,
}

impl ProverJob {
    /// instantiate a ProverJob
    pub fn new(
        program: Program,
        claim: Claim,
        nondeterminism: NonDeterminism,
        job_settings: ProverJobSettings,
    ) -> Self {
        Self {
            program,
            claim,
            nondeterminism,
            job_settings,
        }
    }

    // runs program in triton_vm to determine complexity
    //
    // if complexity exceeds setting `max_log2_padded_height_for_proofs`
    // then it is unlikely this hardware will be able to generate the
    // corresponding proof.  In this case a `ProofComplexityLimitExceeded`
    // error is returned.
    async fn check_if_allowed(&self) -> Result<(), ProverJobError> {
        tracing::debug!("job settings: {:?}", self.job_settings);

        let capability = self.job_settings.tx_proving_capability;
        let proof_type = self.job_settings.proof_type;
        if !capability.can_prove(proof_type) {
            return Err(ProverJobError::TooWeak {
                capability,
                proof_type,
            });
        }

        tracing::debug!("executing VM program to determine complexity (padded-height)");

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
                return Err(ProverJobError::TritonVmProverFailed(
                    VmProcessError::TritonVmFailed(e),
                ));
            }
            vm_state_moved
        };
        assert_eq!(self.claim.program_digest, self.program.hash());
        assert_eq!(self.claim.output, vm_state.public_output);

        let padded_height_processor_table = vm_state.cycle_count.next_power_of_two();

        tracing::debug!(
            "VM program execution finished: padded-height (processor table): {}",
            padded_height_processor_table
        );

        match self.job_settings.max_log2_padded_height_for_proofs {
            Some(limit) if 2u32.pow(limit.into()) < padded_height_processor_table => {
                let ph_limit = 2u32.pow(limit.into());

                tracing::warn!(
                    "proof-complexity-limit-exceeded. ({} > {})  The proof will not be generated",
                    padded_height_processor_table,
                    ph_limit
                );

                Err(ProverJobError::ProofComplexityLimitExceeded {
                    result: padded_height_processor_table,
                    limit: ph_limit,
                })
            }
            _ => Ok(()),
        }
    }

    /// Run the program and generate a proof for it, assuming the Triton VM run
    /// halts gracefully.
    ///
    /// If a message is received on the [JobCancelReceiver] channel while
    /// proving, the job will be cancelled.
    ///
    /// panics if job cannot be successfully cancelled.
    ///
    /// If we are in a test environment, try reading it from disk. If it is not
    /// there, generate it and store it to disk.
    async fn prove(&self, rx: JobCancelReceiver) -> JobCompletion {
        // produce mock proofs if network so requires. (ie RegTest)
        if self.job_settings.network.use_mock_proof() {
            let proof = Proof::valid_mock(self.claim.clone());
            return ProverProcessCompletion::Finished(proof).into();
        }

        #[cfg(test)]
        let result = self.prove_for_unit_testing(rx).await;

        #[cfg(not(test))]
        let result = self.prove_out_of_process(rx).await;

        result.into()
    }

    #[cfg(test)]
    async fn prove_for_unit_testing(
        &self,
        mut rx: JobCancelReceiver,
    ) -> Result<ProverProcessCompletion, VmProcessError> {
        let claim = self.claim.clone();
        let program = self.program.clone();
        let nondeterminism = self.nondeterminism.clone();

        let prove_jh = tokio::task::spawn_blocking(move || {
            let proof = tests::load_proof_or_produce_and_save(&claim, program, nondeterminism);
            ProverProcessCompletion::Finished(proof)
        });

        tokio::select! {
            result = prove_jh => Ok(result.unwrap()),
            _ = rx.changed() => {
                tracing::debug!("prover job got cancel message.  cancelling.");
                Ok(ProverProcessCompletion::Cancelled)
            }
        }
    }

    /// runs triton-vm prover out of process.
    ///
    /// This method spawns child process and waits for either:
    ///   1. the child to finish
    ///   2. a job-cancellation message.
    ///
    /// It returns a Result<ProverProcessCompletion, _> indicating:
    ///   1. Ok(Completion) - prover finished successfully (with a Proof)
    ///   2. Ok(Cancelled) - job was cancelled
    ///   3. Err(e) - an error occurred.
    ///
    /// If the job is cancelled while the child process is running then
    /// an attempt is made to kill the child process.  If this attempt
    /// fails, the fn will panic.
    ///
    /// input is sent via stdin, output is received via stdout.
    /// stderr is ignored.
    ///
    /// The prover executable is triton-vm-prover. It must reside
    /// in same directory as neptune-core.
    /// see Self::path_to_triton_vm_prover()
    ///
    /// parameters claim, program, nondeterminism are passed as
    /// json strings.
    ///
    /// the result is a [Proof], which is bincode serialized.
    ///
    /// The process result is only read if exit code is 0.
    /// A non-zero exit code or no code results in an error.
    #[cfg(not(test))]
    async fn prove_out_of_process(
        &self,
        mut rx: JobCancelReceiver,
    ) -> Result<ProverProcessCompletion, VmProcessError> {
        use tokio::io::AsyncBufReadExt;
        use tokio::io::BufReader;

        // start child process
        let mut child = {
            let inputs = [
                serde_json::to_string(&self.claim)?,
                serde_json::to_string(&self.program)?,
                serde_json::to_string(&self.nondeterminism)?,
                serde_json::to_string(&self.job_settings.max_log2_padded_height_for_proofs)?,
                serde_json::to_string(&self.job_settings.triton_vm_env_vars)?,
            ];

            let mut child = tokio::process::Command::new(Self::path_to_triton_vm_prover()?)
                .kill_on_drop(true) // extra insurance.
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            let mut child_stdin = child.stdin.take().ok_or(VmProcessError::StdinUnavailable)?;
            child_stdin.write_all(inputs.join("\n").as_bytes()).await?;

            child
        };

        let child_process_id = match child.id() {
            Some(id) => id.to_string(),
            None => "??".to_string(),
        };

        tracing::debug!("prover job started child process. id: {}", child_process_id);

        // Use std err of spawned process for debugging purposes.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    tracing::debug!("[triton-vm prover]: {line}");
                }
            });
        }

        // see <https://github.com/tokio-rs/tokio/discussions/7132>
        tokio::select! {
            result = process_util::wait_with_output(&mut child) => {
                let output = result?;
                match output.status.code() {
                    Some(0) => {
                        let proof: Proof = bincode::deserialize(&output.stdout)?;
                        tracing::debug!(
                            "Generated proof, with padded height: {}",
                            proof.padded_height()
                                .map(|x| x.to_string())
                                .unwrap_or_else(|e| format!("could not get padded height from proof.\nGot: {e}"))
                        );
                        Ok(ProverProcessCompletion::Finished(proof))
                    }
                    Some(code) => {
                        const LOG2_PADDED_HEIGHT_RANGE: i32 = 32;
                        if (PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE
                            ..=PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE
                                + LOG2_PADDED_HEIGHT_RANGE)
                            .contains(&code)
                        {
                            let limit = self
                                .job_settings
                                .max_log2_padded_height_for_proofs
                                .expect(
                                    "Must have max log2 padded height set if this error reported",
                                )
                                .into();
                            let observed_log_padded_height = (code
                                - PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE)
                                .try_into()
                                .unwrap();
                            Err(VmProcessError::ProofComplexityLimitExceeded {
                                limit,
                                result: observed_log_padded_height,
                            })
                        } else {
                            Err(VmProcessError::NonZeroExitCode(code))
                        }

                    }

                    None => Err(VmProcessError::NoExitCode),
                }
            },

            _ = rx.changed() => {
                tracing::debug!("prover job got cancel message. killing child process. id: {}", child_process_id);
                child.kill().await.expect("external proving process should be killed");
                tracing::debug!("prover job: kill succeeded for child process. id: {},  cancelling job", child_process_id);
                Ok(ProverProcessCompletion::Cancelled)
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

    // we override the default impl of this method in order to kill the external
    // proving job when a job is cancelled.
    //
    // It is not strictly necessary to do so.  We could just rely on the handy
    // tokio::process::Command::kill_on_drop(true) setting, by which the tokio
    // executor kills the process in the background after the child handle is
    // dropped.  However in that case we would not know when or if the process
    // is actually killed.  It can take seconds to kill a prover process, so if
    // another proving job is queued, it could execute the prover process before
    // the current one has finished exiting, which might be problematic in terms
    // of RAM usage.
    //
    // also, just in terms of correctness, the job-queue is meant to serialize
    // jobs one after another, so if aspects of two jobs are ever running at the
    // same time then by definition the code is not correct.
    //
    // The select!() and kill() occur in Self::prove_out_of_process().
    async fn run_async_cancellable(&self, mut rx: JobCancelReceiver) -> JobCompletion {
        // check if allowed, and listen for cancel messages.
        tokio::select!(
            result = self.check_if_allowed() => {
                if let Err(e) = result {
                    return ProverJobResult::new(Err(e)).into()
                }
            }

            _ = rx.changed() => {
                tracing::debug!("prover job got cancel message while checking program complexity");
                return JobCompletion::Cancelled
            }
        );

        // all is well, let's prove!
        self.prove(rx).await // handles cancellation internally
    }
}

// future cleanup: remove this module, when possible.
#[cfg(not(test))]
mod process_util {

    use std::process::Output;

    use tokio::io::AsyncRead;
    use tokio::io::AsyncReadExt;
    use tokio::process::Child;

    // This fn is a slightly modified copy of
    // tokio::process::Child::wait_with_output().
    //
    // As of tokio 1.43.0, Child::wait_with_output() takes `self` argument,
    // which prevents use within a select along with Child::kill().  The docs
    // for Child::kill() demonstrate using a select!() to Child::wait() for a
    // process and optionally kill() it if a message is received.  However,
    // Child::wait_with_output() used in this manner results in a compile error
    // due to the `self` parameter, which differs from `&mut self` that
    // Child::wait() takes.
    //
    // The modified fn below takes `&mut Child` and has some minor mods so it
    // does not rely on internal tokio functions.
    //
    // Links:
    //   A playground demonstrating the compile error:
    //   <https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=a1aaeb3204f62f9369b85d73d7e25c2e>
    //
    //   A playground demonstrating this solution:
    //   <https://play.rust-lang.org/?version=stable&mode=debug&edition=2021&gist=a956940628dd8b0d8bf5d1a546d4a6eb>
    //
    //   A writeup / discussion of the issue:
    //   <https://github.com/tokio-rs/tokio/discussions/7132>
    pub async fn wait_with_output(child: &mut Child) -> tokio::io::Result<Output> {
        async fn read_to_end<A: AsyncRead + Unpin>(
            io: &mut Option<A>,
        ) -> tokio::io::Result<Vec<u8>> {
            let mut vec = Vec::new();
            if let Some(io) = io.as_mut() {
                io.read_to_end(&mut vec).await?;
            }
            Ok(vec)
        }

        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();

        let stdout_fut = read_to_end(&mut stdout_pipe);
        let stderr_fut = read_to_end(&mut stderr_pipe);

        let (status, stdout, stderr) = tokio::try_join!(child.wait(), stdout_fut, stderr_fut)?;

        // Drop happens after `try_join` due to <https://github.com/tokio-rs/tokio/issues/4309>
        drop(stdout_pipe);
        drop(stderr_pipe);

        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}
