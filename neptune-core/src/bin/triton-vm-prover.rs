#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::io::Write;

use neptune_cash::application::config::triton_vm_env_vars::TritonVmEnvVars;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE;
use neptune_cash::protocol::proof_abstractions::tasm::triton_vm_prover_job::TritonVMProverJob;
use tasm_lib::triton_vm::config::overwrite_lde_trace_caching_to;
use tasm_lib::triton_vm::config::CacheDecision;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::VM;
use thread_priority::set_current_thread_priority;
use thread_priority::ThreadPriority;

const LDE_TRACE_ENV_VAR: &str = tasm_lib::triton_vm::config::ENV_VAR_LDE_CACHE;

/// If set, turns this executable into a proxy for the given binary or command.
const TRITON_PROVER_ENV_VAR: &str = "TRITON_PROVER";

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
        eprintln!("Setting env variable for Triton VM: {key}={value}");

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
        if key == LDE_TRACE_ENV_VAR {
            let decision = match value.to_lowercase().as_str() {
                "cache" => Some(CacheDecision::Cache),
                "no_cache" => Some(CacheDecision::NoCache),
                _ => None,
            };

            if let Some(d) = decision {
                eprintln!("overwriting cache lde trace to: {d:?}");
                overwrite_lde_trace_caching_to(d);
            }
        }
    }
}

/// Configure and run the STARK prover.
fn execute(
    claim: Claim,
    program: Program,
    non_determinism: NonDeterminism,
    max_log2_padded_height: Option<u8>,
    env_vars: TritonVmEnvVars,
) -> Proof {
    let stark: Stark = Stark::default();

    // Generate the Algebraic Execution Trace (AET) to determine the padded
    // table height, which is an input to later calculations.
    let (aet, _) = VM::trace_execution(program, (&claim.input).into(), non_determinism).unwrap();
    let log2_padded_height = aet.padded_height().ilog2() as u8;

    // Use std-err for logging purposes since spawner (caller) doesn't get the
    // log outputs but can capture std-err.
    eprintln!("actual log2 padded height for proof: {log2_padded_height}");

    if max_log2_padded_height.is_some_and(|max| log2_padded_height > max) {
        eprintln!(
            "Canceling prover because padded height exceeds max value of {}",
            max_log2_padded_height.unwrap()
        );
        // Exit with a specific error code so that the parent process knows
        // resource limit was hit. This error code indicates that AET padded
        // height too big, and furthermore communicates the log2 padded height.
        // It is guaranteed to be in the range [200-232].
        std::process::exit(
            PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE + i32::from(log2_padded_height),
        );
    }

    // Lookup specific environment variable-assignments for this padded table
    // height.
    let env_vars = env_vars
        .get(&log2_padded_height)
        .map(|x| x.to_owned())
        .unwrap_or_default();

    set_environment_variables(&env_vars);

    stark.prove(&claim, &aet).unwrap()
}

/// Entry point for the standalone prover process.
///
/// It consumes JSON-serialized task definitions from STDIN and produces
/// a binary-serialized Proof on STDOUT.
fn main() {
    // Check for a delegated prover, which could be a binary or a command. If
    // set, use that.
    if let Ok(prover_cmd) = std::env::var(TRITON_PROVER_ENV_VAR) {
        if !prover_cmd.trim().is_empty() {
            eprintln!("Proxying prover job to command: {prover_cmd}");

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
                .expect("Failed to execute alternative prover command");

            std::process::exit(exit_status.code().unwrap_or(1));
        }
    }

    // run with a low priority so that neptune-core can remain responsive.
    //
    // todo: we could accept a thread-prioritycli param (0..100) and
    //       pass it with ThreadPriority::CrossPlatform(x).
    set_current_thread_priority(ThreadPriority::Min).unwrap();

    // Read task definition from STDIN.
    let stdin = std::io::stdin();
    let job: TritonVMProverJob = serde_json::from_reader(stdin.lock())
        .expect("Failed to deserialize TritonVMProverJob from STDIN");

    // Perform task.
    let proof = execute(
        job.claim,
        job.program,
        job.non_determinism,
        job.max_log2_padded_height,
        job.env_vars,
    );
    eprintln!("triton-vm: completed proof");

    // Write serialized proof to STDOUT.
    let as_bytes = bincode::serialize(&proof).unwrap();
    let mut stdout = std::io::stdout();
    stdout.write_all(&as_bytes).unwrap();
    stdout.flush().unwrap();
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
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
                (LDE_TRACE_ENV_VAR.to_owned(), "no_cache".to_owned()),
                ("RAYON_NUM_THREADS".to_owned(), "3".to_owned()),
            ],
        );

        let proof = execute(
            claim.clone(),
            program,
            non_determinism,
            max_log2_padded_height,
            env_vars,
        );

        assert!(triton_vm::verify(Stark::default(), &claim, &proof));

        // Verify that env variables were actually set
        assert_eq!(
            "no_cache",
            std::env::var(LDE_TRACE_ENV_VAR).expect("Env variable for LDE trace must be set")
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
        let proof = execute(
            claim.clone(),
            program,
            non_determinism,
            max_log2_padded_height,
            env_vars,
        );

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
