use std::panic::catch_unwind;
use std::panic::RefUnwindSafe;

use itertools::Itertools;
use tasm_lib::maybe_write_debuggable_program_to_disk;
use tasm_lib::triton_vm::error::InstructionError;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::triton_vm::vm::VMState;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::Digest;
use tracing::debug;

use super::consensus_program_prover_job::ConsensusProgramProverJob;
use super::consensus_program_prover_job::ConsensusProgramProverJobResult;
use super::environment;
use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::job_queue::triton_vm::TritonVmJobQueue;

#[derive(Debug, Clone)]
pub enum ConsensusError {
    RustShadowPanic(String),
    TritonVMPanic(String, InstructionError),
}

/// A `ConsensusProgram` represents the logic subprogram for transaction or
/// block validity.
pub trait ConsensusProgram
where
    Self: RefUnwindSafe + std::fmt::Debug,
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
        debug!(
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
        let mut vm_state = VMState::new(&program, input.clone(), nondeterminism.clone());
        let init_stack = vm_state.op_stack.clone();
        maybe_write_debuggable_program_to_disk(&program, &vm_state);
        let result = vm_state.run();
        match result {
            Ok(_) => {
                // Do some sanity checks that are likely to catch programming
                // errors in the consensus program. This doesn't catch
                // soundness errors, though, since a valid proof could still be
                // generated even though one of these checks fail.
                assert!(
                    vm_state.secret_digests.is_empty(),
                    "Secret digest list must be empty after executing consensus program"
                );

                assert_eq!(&init_stack, &vm_state.op_stack);

                Ok(vm_state.public_output)
            }
            Err(error) => {
                debug!("VM State:\n{}\n\n", error);
                Err(ConsensusError::TritonVMPanic(
                    format!("Triton VM failed.\nVMState:\n{}", vm_state),
                    error,
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
    #[allow(async_fn_in_trait)] // Trait must be public bc of benchmarks.
    async fn prove(
        &self,
        claim: &Claim,
        nondeterminism: NonDeterminism,
        triton_vm_job_queue: &TritonVmJobQueue,
        priority: TritonVmJobPriority,
    ) -> anyhow::Result<Proof> {
        {
            prove_consensus_program(
                self.program(),
                claim.clone(),
                nondeterminism,
                triton_vm_job_queue,
                priority,
            )
            .await
        }
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
/// The proof is executed as a triton-vm-job-queue job which ensures that
/// no two tasks run the prover simultaneously.
pub(crate) async fn prove_consensus_program(
    program: Program,
    claim: Claim,
    nondeterminism: NonDeterminism,
    triton_vm_job_queue: &TritonVmJobQueue,
    priority: TritonVmJobPriority,
) -> anyhow::Result<Proof> {
    // create a triton-vm-job-queue job for generating this proof.
    let job = ConsensusProgramProverJob {
        program,
        claim,
        nondeterminism,
    };

    // queue the job and await the result.
    // todo: perhaps the priority should (somehow) depend on type of Program?
    let result = triton_vm_job_queue
        .add_job(Box::new(job), priority)
        .await?
        .result()
        .await?;

    // obtain resulting proof.
    let proof: Proof = result
        .as_any()
        .downcast_ref::<ConsensusProgramProverJobResult>()
        .expect("downcast should succeed, else bug")
        .into();
    Ok(proof)
}

#[cfg(test)]
pub mod test {
    use std::fs::create_dir_all;
    use std::fs::File;
    use std::io::stdout;
    use std::io::Read;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;
    use std::time::SystemTime;

    use itertools::Itertools;
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use reqwest::header::HeaderMap;
    use reqwest::header::HeaderValue;
    use reqwest::Url;
    use tasm_lib::triton_vm;
    use tasm_lib::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
    use tracing::debug;
    use tracing::Span;

    use super::*;
    use crate::models::blockchain::shared::Hash;
    use crate::triton_vm::stark::Stark;

    const TEST_DATA_DIR: &str = "test_data";
    const TEST_NAME_HTTP_HEADER_KEY: &str = "Test-Name";

    pub(crate) fn consensus_program_negative_test<T: ConsensusProgram>(
        consensus_program: T,
        input: &PublicInput,
        nondeterminism: NonDeterminism,
        allowed_instruction_errors: &[InstructionError],
    ) {
        let rust_result = consensus_program.run_rust(input, nondeterminism.clone());
        assert!(matches!(
            rust_result.unwrap_err(),
            ConsensusError::RustShadowPanic(_)
        ));

        let tasm_result = consensus_program.run_tasm(input, nondeterminism);
        let instruction_error = match tasm_result {
            Ok(_) => {
                panic!("negative test failed to fail for consensus program {consensus_program:?}",)
            }
            Err(ConsensusError::RustShadowPanic(_)) => {
                panic!("TASM code must fail with expected error enum. Program was {consensus_program:?}")
            }
            Err(ConsensusError::TritonVMPanic(_, instruction_error)) => instruction_error,
        };

        assert!(
            allowed_instruction_errors.contains(&instruction_error),
            "Triton VM must fail with expected instruction error. Expected one of: [{}]\n got {}",
            allowed_instruction_errors.iter().join(","),
            instruction_error
        );
    }

    /// Derive a file name from the claim, includes the extension
    fn proof_filename(claim: &Claim) -> String {
        let base_name = Hash::hash(
            &[
                Hash::hash(&claim.input),
                claim.program_digest,
                Hash::hash(&claim.output),
            ]
            .into_iter()
            .flat_map(|d| d.values())
            .collect_vec(),
        )
        .to_hex();

        format!("{base_name}.proof")
    }

    fn proof_path(claim: &Claim) -> PathBuf {
        let name = proof_filename(claim);
        let mut path = PathBuf::new();
        path.push(TEST_DATA_DIR);
        path.push(Path::new(&name));

        path
    }

    /// First, attempt to load the proof from disk. If it does not exist,
    /// attempt to fetech it online. If that also fails, run the prover and
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

    /// Tries to load a proof for the claim from the test data directory
    fn try_load_proof_from_disk(claim: &Claim) -> Option<Proof> {
        let path = proof_path(claim);
        let Ok(mut input_file) = File::open(path.clone()) else {
            debug!(
                "cannot open file '{}' -- might not exist",
                path.to_string_lossy()
            );
            return None;
        };
        let mut file_contents = vec![];
        if input_file.read_to_end(&mut file_contents).is_err() {
            debug!("cannot read file '{}'", path.to_string_lossy());
            return None;
        }
        let mut proof_data = vec![];
        for ch in file_contents.chunks(8) {
            if let Ok(eight_bytes) = TryInto::<[u8; 8]>::try_into(ch) {
                proof_data.push(BFieldElement::new(u64::from_be_bytes(eight_bytes)));
            } else {
                debug!("cannot cast chunk to eight bytes");
                return None;
            }
        }
        let proof = Proof(proof_data);
        Some(proof)
    }

    /// Load a list of proof-servers from test data directory
    fn load_servers() -> Vec<Url> {
        let mut server_list_path = PathBuf::new();
        server_list_path.push(TEST_DATA_DIR);
        server_list_path.push(Path::new("proof_servers").with_extension("txt"));
        let Ok(mut input_file) = File::open(server_list_path.clone()) else {
            debug!(
                "cannot proof-server list '{}' -- file might not exist",
                server_list_path.to_string_lossy()
            );
            return vec![];
        };
        let mut file_contents = vec![];
        if input_file.read_to_end(&mut file_contents).is_err() {
            debug!("cannot read file '{}'", server_list_path.to_string_lossy());
            return vec![];
        }
        let Ok(file_as_string) = String::from_utf8(file_contents) else {
            debug!(
                "cannot parse file '{}' -- is it valid utf8?",
                server_list_path.to_string_lossy()
            );
            return vec![];
        };
        file_as_string
            .lines()
            .map(|s| Url::parse(s).expect("Must be able to parse string '{s}' as URL"))
            .collect()
    }

    #[test]
    fn test_load_servers() {
        let servers = load_servers();
        for server in servers {
            println!("read server: {}", server);
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
    fn try_fetch_from_server_inner(filename: String) -> Option<(Proof, Url)> {
        fn get_test_name_from_tracing() -> String {
            match Span::current().metadata().map(|x| x.name()) {
                Some(test_name) => test_name.to_owned(),
                None => "unknown".to_owned(),
            }
        }

        fn attempt_to_get_test_name() -> String {
            let thread = std::thread::current();
            match thread.name() {
                Some(test_name) => {
                    if test_name.eq("tokio-runtime-worker") {
                        get_test_name_from_tracing()
                    } else {
                        test_name.to_owned()
                    }
                }
                None => get_test_name_from_tracing(),
            }
        }

        let mut servers = load_servers();
        servers.shuffle(&mut thread_rng());

        // Add test name to request allow server to see which test requires a proof
        let mut headers = HeaderMap::new();
        headers.insert(
            TEST_NAME_HTTP_HEADER_KEY,
            HeaderValue::from_str(&attempt_to_get_test_name())
                .unwrap_or_else(|_| panic!("Must be to add test name to HTTP header")),
        );

        // TODO: Use regular (non-blocking) reqwest client if this function
        // is made `async`.
        for server in servers {
            let server_ = server.clone();
            let filename_ = filename.clone();
            let headers_ = headers.clone();
            let handle = std::thread::spawn(move || {
                let http_client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .default_headers(headers_)
                    .build()
                    .expect("Must be able to build HTTP client instance");
                let url = server_.join(&filename_).unwrap_or_else(|_| {
                    panic!("Must be able to form URL. Got: '{server_}' and '{filename_}'.")
                });
                debug!("requesting: <{url}>");
                let Ok(response) = http_client.get(url).send() else {
                    println!(
                        "server '{}' failed for file '{}'; trying next ...",
                        server_.clone(),
                        filename_
                    );

                    return None;
                };

                Some((response.status(), response.bytes()))
            });

            let Some((status_code, body)) = handle.join().unwrap() else {
                eprintln!("Could not connect to server {server}.");
                continue;
            };

            if !status_code.is_success() {
                eprintln!("{server} responded with {status_code}");
                continue;
            }

            let Ok(file_contents) = body else {
                eprintln!(
                    "error reading file '{}' from server '{}'; trying next ...",
                    filename, server
                );

                continue;
            };

            let mut proof_data = vec![];
            for ch in file_contents.chunks(8) {
                if let Ok(eight_bytes) = TryInto::<[u8; 8]>::try_into(ch) {
                    proof_data.push(BFieldElement::new(u64::from_be_bytes(eight_bytes)));
                } else {
                    eprintln!("cannot cast chunk to eight bytes. Server was: {server}");
                    continue;
                }
            }

            let proof = Proof(proof_data);
            println!("got proof.");

            return Some((proof, server));
        }

        println!("No known servers serve file `{}`", filename);

        None
    }

    #[test]
    fn test_query_proof() {
        let filename = "155848c090374716f0612597f818fb7d4879aa8b45e1a781f03aea7731079534f3ef3a05b888d72d.proof".to_string();
        assert!(try_fetch_from_server_inner(filename).is_some());
    }

    /// Call Triton VM prover to produce a proof and save it to disk.
    fn produce_and_save_proof(
        claim: &Claim,
        program: Program,
        nondeterminism: NonDeterminism,
    ) -> Proof {
        let name = proof_filename(claim);
        let mut path = PathBuf::new();
        path.push(TEST_DATA_DIR);
        create_dir_all(&path)
            .unwrap_or_else(|_| panic!("cannot create '{TEST_DATA_DIR}' directory"));
        path.push(Path::new(&name));

        let proof = triton_vm::prove(Stark::default(), claim, &program, nondeterminism)
            .expect("cannot produce proof");

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
}
