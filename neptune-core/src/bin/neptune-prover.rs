#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::io::Write;

use neptune_cash::protocol::proof_abstractions::tasm::neptune_prover_job::NeptuneProverJob;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE;
use tasm_lib::triton_vm::aet::AlgebraicExecutionTrace;
use tasm_lib::triton_vm::config::overwrite_lde_trace_caching_to;
use tasm_lib::triton_vm::config::CacheDecision;
use tasm_lib::triton_vm::config::ENV_VAR_LDE_CACHE;
use tasm_lib::triton_vm::config::ENV_VAR_LDE_CACHE_NO_CACHE;
use tasm_lib::triton_vm::config::ENV_VAR_LDE_CACHE_WITH_CACHE;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::VM;
use thread_priority::set_current_thread_priority;
use thread_priority::ThreadPriority;

/// If set, turns this executable into a proxy for the given binary or command.
const NEPTUNE_PROVER_PROXY_ENV_VAR: &str = "NEPTUNE_PROVER_PROXY";

/// Sets process-level environment variables to tune Triton VM's performance.
///
/// This is used to toggle LDE (Low Degree Extension) caching and Rayon
/// parallelism  based on the specific resource requirements of the execution
/// trace. Besides setting the environment variables, this function also calls
/// a public function exposed by triton_vm to overwrite the LDE cache config --
/// just to make sure it was set correctly.
///
/// This function may not be called more than once and may not be called from a
/// concurrent or multi-threaded context.
fn set_environment_variables(env_vars: &[(String, String)]) {
    // Set environment variables for this spawned process only, does not apply
    // globally. Documentation of `set_var` shows it's for the currently
    // running process only.
    // This is only intended to set two environment variables: TVM_LDE_TRACE and
    // RAYON_NUM_THREADS, depending on the padded height of the algebraic
    // execution trace.
    for (key, value) in env_vars {
        eprintln!("TRACE: Setting env variable for Triton VM: {key}={value}");

        // SAFETY:
        // - "The exact requirement is: you must ensure that there are no
        //   other threads concurrently writing or reading(!) the
        //   environment through functions or global variables other than
        //   the ones in this module." At this place, this program is
        //   single-threaded. Generation of algebraic execution trace is
        //   done, and proving hasn't started yet.
        unsafe {
            std::env::set_var(key, value);
        }

        // In case Triton VM has already made the cache decision prior to
        // the environment variable being set here, we override it through
        // a publicly exposed function. This override ensures that the Triton
        // VM configuration agrees with the environment variable.
        if key == ENV_VAR_LDE_CACHE {
            let value = value.to_ascii_lowercase();
            let value = value.as_str();
            let decision = if value == ENV_VAR_LDE_CACHE_WITH_CACHE {
                Some(CacheDecision::Cache)
            } else if value == ENV_VAR_LDE_CACHE_NO_CACHE {
                Some(CacheDecision::NoCache)
            } else {
                None
            };

            if let Some(d) = decision {
                eprintln!("TRACE: overwriting cache lde trace to: {d:?}");
                overwrite_lde_trace_caching_to(d);
            }
        }
    }
}

/// Produce the algebraic execution trace using the reference (CPU)
/// implementation of Triton VM.
fn triton_vm_aet(
    program: Program,
    claim: &Claim,
    non_determinism: NonDeterminism,
) -> AlgebraicExecutionTrace {
    let (aet, _) = VM::trace_execution(program, (&claim.input).into(), non_determinism).unwrap();

    aet
}

/// Execute the proof job in the current process (as opposed to delegating it to
/// another one).
fn execute_prover_job(job: NeptuneProverJob) -> Proof {
    let max_log2_padded_height = job.max_log2_padded_height;
    let claim = job.claim.clone();
    let env_vars = job.env_vars;

    let aet = triton_vm_aet(job.program, &job.claim, job.non_determinism);
    let log2_padded_height = aet.padded_height().ilog2() as u8;

    if max_log2_padded_height.is_some_and(|max| log2_padded_height > max) {
        eprintln!(
            "ERROR: Canceling prover because padded height exceeds max value of {}",
            job.max_log2_padded_height.unwrap()
        );

        // Exit with a specific error code
        std::process::exit(
            PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE + i32::from(log2_padded_height),
        );
    }

    // Set environment variables for this specific padded height
    let env_vars = env_vars
        .get(&log2_padded_height)
        .map(|x| x.to_owned())
        .unwrap_or_default();
    set_environment_variables(&env_vars);

    // run with a low priority so that neptune-core can remain responsive.
    set_current_thread_priority(ThreadPriority::Min).unwrap();

    Stark::default().prove(&claim, &aet).unwrap()
}

/// Entry point for the standalone prover process.
///
/// It consumes JSON-serialized task definitions from STDIN and produces
/// a binary-serialized Proof on STDOUT.
///
/// Uses standard error for logging purposes in the caller.
fn main() {
    eprintln!("DEBUG: Starting neptune-prover.");

    // Check for a delegated prover, which could be a binary or a command. If
    // set, use that.
    if let Ok(prover_cmd) = std::env::var(NEPTUNE_PROVER_PROXY_ENV_VAR) {
        if !prover_cmd.trim().is_empty() {
            eprintln!("INFO: Proxying prover job to command: `{prover_cmd}`");

            let mut cmd = if cfg!(unix) {
                let mut cmd = std::process::Command::new("sh");
                cmd.arg("-c").arg(&prover_cmd);
                cmd
            } else {
                let mut cmd = std::process::Command::new("cmd");
                cmd.arg("/C").arg(&prover_cmd);
                cmd
            };

            let exit_status = cmd
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .status()
                .expect("ERROR: Failed to execute alternative prover command");

            std::process::exit(exit_status.code().unwrap_or(1));
        }
    }

    let stdin = std::io::stdin();
    let job: NeptuneProverJob = match serde_json::from_reader(stdin.lock()) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("ERROR: Failed to deserialize TritonVMProverJob from STDIN:\n{e}");
            std::process::exit(1);
        }
    };

    let proof = execute_prover_job(job);

    eprintln!("DEBUG: triton-vm-prover: completed proof");

    // Write serialized proof to STDOUT.
    let as_bytes = bincode::serialize(&proof).unwrap();
    let mut stdout = std::io::stdout();
    stdout.write_all(&as_bytes).unwrap();
    stdout.flush().unwrap();
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod neptune_prover_tests {
    use neptune_cash::application::config::triton_vm_env_vars::TritonVmEnvVars;
    use tasm_lib::triton_vm;
    use tasm_lib::triton_vm::isa::triton_asm;

    use super::*;

    #[test]
    fn setting_tvm_env_vars_works() {
        let program = triton_asm!(halt);
        let program = Program::new(&program);
        let claim = Claim::about_program(&program);
        let non_determinism = NonDeterminism::default();
        let max_log2_padded_height = None;
        let mut env_vars = TritonVmEnvVars::default();
        env_vars.insert(
            8,
            vec![
                (ENV_VAR_LDE_CACHE.to_owned(), "no_cache".to_owned()),
                ("RAYON_NUM_THREADS".to_owned(), "3".to_owned()),
            ],
        );
        let job = NeptuneProverJob {
            program,
            claim: claim.clone(),
            non_determinism,
            max_log2_padded_height,
            env_vars,
        };

        let proof = execute_prover_job(job);

        assert!(triton_vm::verify(Stark::default(), &claim, &proof));

        // Verify that env variables were actually set
        assert_eq!(
            "no_cache",
            std::env::var(ENV_VAR_LDE_CACHE).expect("Env variable for LDE trace must be set")
        );
        assert_eq!(
            "3",
            std::env::var("RAYON_NUM_THREADS").expect("Env variable for num threads must be set")
        );
    }

    #[test]
    fn make_halt_proof() {
        let program = triton_asm!(halt);
        let program = Program::new(&program);
        let claim = Claim::about_program(&program);
        let non_determinism = NonDeterminism::default();
        let max_log2_padded_height = None;
        let env_vars = TritonVmEnvVars::default();
        let job = NeptuneProverJob {
            program,
            claim: claim.clone(),
            non_determinism,
            max_log2_padded_height,
            env_vars,
        };
        let proof = execute_prover_job(job);

        assert!(triton_vm::verify(Stark::default(), &claim, &proof));
    }

    #[test]
    fn halt_program() {
        let program = triton_asm!(halt);
        let program = Program::new(&program);
        let claim = Claim::about_program(&program);
        let non_determinism = NonDeterminism::default();

        println!("{}", serde_json::to_string(&claim).unwrap());
        println!("{}", serde_json::to_string(&program).unwrap());
        println!("{}", serde_json::to_string(&non_determinism).unwrap());
    }
}
