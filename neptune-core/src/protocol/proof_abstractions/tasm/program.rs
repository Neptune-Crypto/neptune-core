use std::panic::RefUnwindSafe;
use std::sync::Arc;

use tasm_lib::library::Library;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::error::InstructionError;
use tasm_lib::triton_vm::prelude::*;
use tracing::debug;

use super::prover_job::ProverJob;
use super::prover_job::ProverJobResult;
use super::prover_job::ProverJobSettings;
use crate::api::tx_initiation::builder::proof_builder::ProofBuilder;
use crate::api::tx_initiation::error::CreateProofError;
use crate::application::triton_vm_job_queue::TritonVmJobPriority;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;

#[derive(Debug, Clone)]
pub enum ConsensusError {
    RustShadowPanic(String),
    TritonVMPanic(String, InstructionError),
}

/// A `ConsensusProgram` represents the logic subprogram for transaction or
/// block validity.
///
/// This trait is required for benchmarks, but is not part of the public API.
#[doc(hidden)]
pub trait ConsensusProgram
where
    Self: RefUnwindSafe + std::fmt::Debug,
{
    /// Helps identify all imported Triton assembly snippets.
    /// You probably want to use [`Self::program`].
    // Implemented this way to ensure synchronicity between the library in use
    // and the actual code.
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>);

    /// The Triton VM [`Program`].
    fn program(&self) -> Program {
        let (_, code) = self.library_and_code();
        Program::new(&code)
    }

    /// The [program](Self::program)'s hash [digest](Digest).
    //
    // note: we do not provide a default impl because implementors should cache
    // their Digest with OnceLock.
    fn hash(&self) -> Digest;

    /// Run the program and generate a proof for it, assuming running halts
    /// gracefully.
    ///
    /// If we are in the test environment, try reading it from disk. And if it
    /// not there, generate it and store it to disk.
    ///
    /// This method is a thin wrapper around `prove_consensus_program`, which
    /// does the same but for arbitrary programs.
    //
    // The entire trait is only `pub` to facilitate benchmarks; it is not part of
    // the public API. The suppressed lints below are not nice, but I don't know
    // how else to make it work.
    #[expect(async_fn_in_trait)]
    async fn prove(
        &self,
        claim: Claim,
        nondeterminism: NonDeterminism,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Result<Proof, CreateProofError> {
        ProofBuilder::new()
            .program(self.program())
            .claim(claim)
            .nondeterminism(|| nondeterminism)
            .job_queue(triton_vm_job_queue)
            .proof_job_options(proof_job_options)
            .build()
            .await
    }
}

/// Run the program and generate a proof for it, assuming the Triton VM run
/// halts gracefully.
///
/// Please do not call this directly.  Use TransactionProofBuilder instead
/// which includes logic for building mock proofs if necessary.
///
/// If we are in a test environment, try reading it from disk. If it is not
/// there, generate it and store it to disk.
///
/// This method works for arbitrary programs, including ones that do not
/// implement trait [`ConsensusProgram`].
///
/// The proof is executed as a triton-vm-job-queue job which ensures that
/// no two tasks run the prover simultaneously.
pub(crate) async fn prove_consensus_program(
    program: Program,
    claim: Claim,
    nondeterminism: NonDeterminism,
    triton_vm_job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
) -> Result<Proof, CreateProofError> {
    // regtest mode: just return a mock (empty) Proof
    if proof_job_options.job_settings.network.use_mock_proof() {
        return Ok(Proof::valid_mock(claim));
    }

    // create a triton-vm-job-queue job for generating this proof.
    let job = ProverJob::new(
        program,
        claim,
        nondeterminism,
        proof_job_options.job_settings,
    );

    // queue the job and obtain a job handle.
    let job_handle = triton_vm_job_queue.add_job(job, proof_job_options.job_priority)?;
    tokio::pin!(job_handle);

    let completion = match proof_job_options.cancel_job_rx {
        // fix for issue #348.
        // if we have a cancellation channel from caller then we select on
        // both the channel and job.  If we get a cancel request from the
        // caller, or the channel closes, then we cancel the job
        // which removes it from the job-queue.
        Some(mut cancel_job_rx) => {
            tokio::select! {
                // case: job completion.
                completion = &mut job_handle => completion?,

                // case: sender cancelled, or sender dropped.
                _ = cancel_job_rx.changed() => {
                    debug!("received cancellation request for job: {}.  cancelling.", job_handle.job_id());
                    job_handle.cancel()?;
                    job_handle.await?
                }
            }
        }
        None => job_handle.await?,
    };

    // obtain resulting proof.
    Ok(ProverJobResult::try_from(completion)?.into_inner()?)
}

/// Options for executing the triton-vm proving job
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct TritonVmProofJobOptions {
    /// priority of this job in the job-queue
    ///
    /// used when selecting the next job to run.
    ///
    /// note that if a lower priority job is already running then a higher
    /// priority job still must wait for it to complete.
    pub job_priority: TritonVmJobPriority,

    /// job-specific settings
    pub job_settings: ProverJobSettings,

    /// Cancellation:
    ///
    /// It is possible to cancel a proving-job by:
    ///
    /// 1. create a [tokio::sync::watch] channel and set the receiver in the
    ///    `cancel_job_rx` field.
    ///
    /// 2. call send() on the channel sender to cancel the job.
    pub cancel_job_rx: Option<tokio::sync::watch::Receiver<()>>,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod tests {
    use std::fs::create_dir_all;
    use std::fs::File;
    use std::io::stdout;
    use std::io::Write;
    use std::panic::catch_unwind;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::SystemTime;

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use tasm_lib::triton_vm;
    use tracing::debug;

    use super::*;
    use crate::api::export::Network;
    use crate::application::config::triton_vm_env_vars::TritonVmEnvVars;
    use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
    use crate::protocol::proof_abstractions::tasm::environment;
    use crate::state::transaction::tx_proving_capability::TxProvingCapability;
    use crate::tests::shared::files::test_helper_data_dir;
    use crate::tests::shared::files::try_fetch_file_from_server;
    use crate::tests::shared::files::try_load_file_from_disk;
    use crate::tests::shared_tokio_runtime;
    use crate::triton_vm::stark::Stark;

    impl From<TritonVmJobPriority> for TritonVmProofJobOptions {
        fn from(job_priority: TritonVmJobPriority) -> Self {
            let job_settings = ProverJobSettings {
                tx_proving_capability: TxProvingCapability::SingleProof,
                proof_type: TransactionProofType::SingleProof,
                ..Default::default()
            };
            Self {
                job_priority,
                job_settings,
                cancel_job_rx: None,
            }
        }
    }

    impl TritonVmProofJobOptions {
        pub(crate) fn default_with_network(network: Network) -> Self {
            let job_settings = ProverJobSettings {
                network,
                ..Default::default()
            };
            Self {
                job_settings,
                ..Default::default()
            }
        }
    }

    impl From<(TritonVmJobPriority, Option<u8>)> for TritonVmProofJobOptions {
        fn from(v: (TritonVmJobPriority, Option<u8>)) -> Self {
            let (job_priority, max_log2_padded_height_for_proofs) = v;
            Self {
                job_priority,
                job_settings: ProverJobSettings {
                    max_log2_padded_height_for_proofs,
                    network: Default::default(),
                    tx_proving_capability: TxProvingCapability::SingleProof,
                    proof_type: TransactionProofType::SingleProof,
                    triton_vm_env_vars: TritonVmEnvVars::default(),
                },
                cancel_job_rx: None,
            }
        }
    }

    pub(crate) trait ConsensusProgramSpecification: ConsensusProgram {
        /// The canonical reference source code for the consensus program, written in
        /// the subset of rust that the tasm-lang compiler understands. To run this
        /// program, call [`Self::run_rust`], which spawns a new thread, boots the
        /// environment, and executes the program.
        fn source(&self);

        /// Run the source program natively in rust, but with the emulated TritonVM
        /// environment for input, output, nondeterminism, and program digest.
        fn run_rust(
            &self,
            input: &PublicInput,
            nondeterminism: NonDeterminism,
        ) -> Result<Vec<BFieldElement>, ConsensusError> {
            debug!(
                "Running consensus program with input: {}",
                input.individual_tokens.iter().map(|b| b.value()).join(",")
            );
            let program_digest = catch_unwind(|| self.hash()).unwrap_or_default();
            let emulation_result = catch_unwind(|| {
                environment::init(program_digest, &input.individual_tokens, nondeterminism);
                self.source();
                environment::audit_end_state();
                environment::PUB_OUTPUT.take()
            });

            emulation_result.map_err(|e| ConsensusError::RustShadowPanic(format!("{e:?}")))
        }

        /// Use Triton VM to run the tasm code.
        ///
        /// Only used in tests, since in production, you always need the proofs.
        fn run_tasm(
            &self,
            input: &PublicInput,
            nondeterminism: NonDeterminism,
        ) -> Result<Vec<BFieldElement>, ConsensusError> {
            let mut vm_state = VMState::new(self.program(), input.clone(), nondeterminism.clone());
            tasm_lib::maybe_write_debuggable_vm_state_to_disk(&vm_state);

            let init_stack = vm_state.op_stack.clone();
            if let Err(err) = vm_state.run() {
                let err_str = format!("Triton VM failed.\nError: {err}\nVMState:\n{vm_state}");
                eprintln!("{err_str}");
                return Err(ConsensusError::TritonVMPanic(err_str, err));
            }

            // Do some sanity checks that are likely to catch programming
            // errors in the consensus program. This doesn't catch
            // soundness errors, though, since a valid proof could still be
            // generated even though one of these checks fail.
            assert!(
                vm_state.secret_digests.is_empty(),
                "Secret digest list must be empty after executing consensus program"
            );
            assert!(
                vm_state.secret_individual_tokens.is_empty(),
                "Secret token list must be empty after executing consensus program"
            );
            assert!(
                vm_state.public_input.is_empty(),
                "input must be empty after executing consensus program"
            );
            assert_eq!(&init_stack, &vm_state.op_stack);

            Ok(vm_state.public_output)
        }

        /// `Ok(())` iff the given input & non-determinism triggers the failure of
        /// either the instruction `assert` or `assert_vector`, and if that
        /// instruction's error ID is one of the expected error IDs.
        fn test_assertion_failure(
            &self,
            public_input: PublicInput,
            non_determinism: NonDeterminism,
            expected_error_ids: &[i128],
        ) -> proptest::test_runner::TestCaseResult {
            let fail =
                |reason: String| Err(proptest::test_runner::TestCaseError::Fail(reason.into()));

            let tasm_result = self.run_tasm(&public_input, non_determinism.clone());
            let Err(ConsensusError::TritonVMPanic(_, err)) = tasm_result else {
                return fail("expected a failure in Triton VM, but it halted gracefully".into());
            };

            let (InstructionError::AssertionFailed(err)
            | InstructionError::VectorAssertionFailed(_, err)) = err
            else {
                return fail(format!("expected an assertion failure, but got: {err}"));
            };

            let ids_str = expected_error_ids.iter().join(", ");
            let expected_ids_str = format!("expected an error ID in {{{ids_str}}}");
            let Some(err_id) = err.id else {
                return fail(format!("{expected_ids_str}, but found none"));
            };

            proptest::prop_assert!(
                expected_error_ids.contains(&err_id),
                "{expected_ids_str}, but found {err_id}",
            );

            let rust_result = self.run_rust(&public_input, non_determinism.clone());
            let Err(ConsensusError::RustShadowPanic(_)) = rust_result else {
                return fail("rust shadowing must fail, but did not".into());
            };

            Ok(())
        }
    }

    /// Derive a file name from the claim, includes the extension
    fn proof_filename(claim: &Claim) -> String {
        let base_name = Tip5::hash(claim).to_hex();

        format!("{base_name}.proof")
    }

    fn proof_path(claim: &Claim) -> PathBuf {
        let name = proof_filename(claim);
        let mut path = test_helper_data_dir();
        path.push(Path::new(&name));

        path
    }

    /// Tries to load a proof for the claim from the test data directory
    fn try_load_proof_from_disk(claim: &Claim) -> Option<Proof> {
        let file_path = proof_path(claim);
        let file_contents = try_load_file_from_disk(&file_path)?;

        let mut proof_data = vec![];
        for ch in file_contents.chunks(8) {
            if let Ok(eight_bytes) = TryInto::<[u8; 8]>::try_into(ch) {
                proof_data.push(BFieldElement::new(u64::from_be_bytes(eight_bytes)));
            } else {
                debug!("cannot cast chunk to eight bytes");
                return None;
            }
        }

        let proof = Proof::from(proof_data);
        Some(proof)
    }

    /// First, attempt to load the proof from disk. If it does not exist,
    /// attempt to fetch it online. If that also fails, run the prover and
    /// save the proof before returning it.
    pub(crate) fn load_proof_or_produce_and_save(
        claim: &Claim,
        program: Program,
        nondeterminism: NonDeterminism,
    ) -> Proof {
        let name = proof_filename(claim);
        match try_load_proof_from_disk(claim) {
            Some(proof) => {
                debug!(" - Loaded proof from disk: {name}.");
                assert!(
                    triton_vm::verify(Stark::default(), claim, &proof),
                    "proof loaded from disk is invalid"
                );
                proof
            }
            None => {
                debug!("Proof not found on disk.");
                match try_fetch_and_verify_proof_from_server(claim) {
                    Some(proof) => proof,
                    None => {
                        debug!("Proof not found on proof servers - Proving locally ... ");
                        stdout().flush().expect("could not flush terminal");
                        let tick = SystemTime::now();
                        let proof = produce_and_save_proof(claim, program, nondeterminism);
                        let duration = SystemTime::now().duration_since(tick).unwrap();
                        debug!(
                            "success! Proof time: {:?}. Proof stored to disk: {name}",
                            duration
                        );
                        proof
                    }
                }
            }
        }
    }

    /// Queries known servers for proofs.
    ///
    /// The proof-servers file is located in `proof_servers.txt` test data
    /// directory. It should contain one line per URL, ending in a slash.
    fn try_fetch_and_verify_proof_from_server(claim: &Claim) -> Option<Proof> {
        let filename = proof_filename(claim);
        let (proof, server) = try_fetch_from_server_inner(filename.clone())?;

        if !triton_vm::verify(Stark::default(), claim, &proof) {
            eprintln!("Invalid proof served by {server}. Proof {filename} does not verify.");
            return None;
        }

        let path = proof_path(claim);
        save_proof(&path, &proof);

        Some(proof)
    }

    /// Tries to fetch a proof from a server, does not validate the proof
    ///
    /// If a proof was found, returns it along with the URL of the server
    /// serving the proof. The caller should validate the proof. Does
    /// not store the proof to disk.
    /// TODO: Consider making this async.
    fn try_fetch_from_server_inner(filename: String) -> Option<(Proof, String)> {
        let (file_contents, server) = try_fetch_file_from_server(filename)?;

        let mut proof_data = vec![];
        for ch in file_contents.chunks(8) {
            if let Ok(eight_bytes) = TryInto::<[u8; 8]>::try_into(ch) {
                proof_data.push(BFieldElement::new(u64::from_be_bytes(eight_bytes)));
            } else {
                eprintln!("cannot cast chunk to eight bytes. Server was: {server}");
            }
        }

        let proof = Proof::from(proof_data);
        println!("got proof.");

        Some((proof, server))
    }

    #[apply(shared_tokio_runtime)]
    async fn test_query_proof() {
        // Ensure file exists on machine, in case this machine syncs automatically with proof server
        let program = triton_program!(halt);
        let claim = Claim::about_program(&program);
        prove_consensus_program(
            program,
            claim.clone(),
            NonDeterminism::default(),
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap();

        // Then verify that the proof server has this file
        let filename = proof_filename(&claim);
        let (proof, url) =
            try_fetch_from_server_inner(filename).expect("Expected this proof on the proof server");
        assert!(
            triton_vm::verify(Stark::default(), &claim, &proof),
            "Returned proof from {url} must be valid"
        );
    }

    #[test]
    fn deterministic_proof_is_deterministic() {
        let program = triton_program!(halt);
        let claim = Claim::about_program(&program);
        let nondeterminism = NonDeterminism::default();
        let proof1 = produce_non_zk_deterministic_proof_for_test(
            &claim,
            program.clone(),
            nondeterminism.clone(),
        );
        let proof2 = produce_non_zk_deterministic_proof_for_test(&claim, program, nondeterminism);
        assert_eq!(proof1, proof2, "Deterministic proofs must be deterministic");
    }

    /// Do *not* under any circumstances use this function outside of tests,
    /// since it will leak your secrets!
    fn produce_non_zk_deterministic_proof_for_test(
        claim: &Claim,
        program: Program,
        nondeterminism: NonDeterminism,
    ) -> Proof {
        // Produce deterministic proofs to ensure that proofs are the same over
        // different test runs.
        let stark_prover_seed: [u8; Digest::BYTES] = Tip5::hash(claim).into();
        let stark_prover_seed: [u8; 32] = stark_prover_seed
            .into_iter()
            .take(32)
            .collect_vec()
            .try_into()
            .unwrap();
        let (aet, public_output) =
            VM::trace_execution(program, (&claim.input).into(), nondeterminism.clone())
                .expect("Cannot produce algebraic execution trace");
        assert_eq!(
            public_output, claim.output,
            "Output from execution must match that in claim"
        );

        let stark = Stark::default();
        let prover = Prover::new(stark)
            .set_randomness_seed_which_may_break_zero_knowledge(stark_prover_seed);
        prover
            .prove(claim, &aet)
            .expect("cannot produce proof")
            .into()
    }

    /// Call Triton VM prover to produce a proof and save it to disk.
    fn produce_and_save_proof(
        claim: &Claim,
        program: Program,
        nondeterminism: NonDeterminism,
    ) -> Proof {
        let name = proof_filename(claim);
        let mut path = test_helper_data_dir();
        create_dir_all(&path)
            .unwrap_or_else(|_| panic!("cannot create '{}' directory", path.to_string_lossy()));
        path.push(Path::new(&name));

        let proof = produce_non_zk_deterministic_proof_for_test(claim, program, nondeterminism);

        save_proof(&path, &proof);
        proof
    }

    /// Store a proof to the given file
    fn save_proof(path: &PathBuf, proof: &Proof) {
        let proof_data = proof
            .0
            .iter()
            .copied()
            .flat_map(|b| b.value().to_be_bytes())
            .collect_vec();
        let mut output_file = File::create(path).expect("cannot open file for writing");
        output_file
            .write_all(&proof_data)
            .expect("cannot write to file");
    }

    /// Test for regressions in a consensus program.
    ///
    /// As consensus programs are refactored to improve readability, it is
    /// important to ensure that the program does not actually change. Any such
    /// change would constitute a hard fork.
    ///
    /// This test checks the program's hash against a hardcoded value. If the
    /// program changes and that hardcoded value is not updated in lockstep, the
    /// test will fail.
    ///
    /// Example usage:
    ///
    /// ```
    /// use crate::models::proof_abstractions::tasm::program::test_program_snapshot;
    ///
    /// struct MyProgram;
    ///
    /// impl ConsensusProgram for MyProgram {
    ///     fn library_and_code() ->  (Library, Vec<LabelledInstruction>) {
    ///         /// ...
    ///         (Library::new(), vec![])
    ///     }
    /// }
    ///
    /// #[cfg(test)]
    /// mod test {
    ///     use super::*;
    ///
    ///     test_program_snapshot!(
    ///         MyProgram,
    ///         // snapshot taken from master on 2025-02-11 at 12:00 [commit id]
    ///         "c0f8cbc73a844ab6c3586d8891e29b677a3aa08f25f9aec0f854a72bf2e2f84c2a48c9dd1bbe0a66"
    ///     );
    /// }
    /// ```
    macro_rules! test_program_snapshot {
        ($consensus_program:expr, $hash_hex:literal $(,)?) => {
            #[test]
            fn program_hash_has_not_changed() {
                let old_hash = $hash_hex.to_string();
                let new_hash = $consensus_program.program().hash().to_hex();
                println!("old hash: {old_hash}");
                println!("new hash: {new_hash}");
                assert_eq!(old_hash, new_hash);
            }
        };
    }

    pub(crate) use test_program_snapshot;
}
