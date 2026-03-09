#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::collections::HashMap;
use std::io::Write;
use std::process::Stdio;

use neptune_cash::protocol::proof_abstractions::tasm::neptune_prover_job::NeptuneProverJob;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::config::overwrite_lde_trace_caching_to;
use tasm_lib::triton_vm::config::CacheDecision;
use tasm_lib::triton_vm::config::ENV_VAR_LDE_CACHE_NO_CACHE;
use tasm_lib::triton_vm::config::ENV_VAR_LDE_CACHE_WITH_CACHE;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::VM;
#[cfg(test)]
use tasm_lib::twenty_first::bfe_vec;
use thread_priority::set_current_thread_priority;
use thread_priority::ThreadPriority;

/// If set, turns this executable into a proxy for the given binary or command.
///
/// Allows for the use of custom Triton VM provers, such as GPU provers.
const NEPTUNE_PROVER_ENV_VAR: &str = "NEPTUNE_PROVER_PROXY";

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
fn set_environment_variables(env_vars: &HashMap<String, String>) {
    // Don't carry over dispatcher env var, as it leads to infinite recursion
    // in a test.
    let env_vars: HashMap<String, String> = env_vars
        .iter()
        .filter(|(key, _)| *key != NEPTUNE_PROVER_ENV_VAR)
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    // Set environment variables for this spawned process only, does not apply
    // globally. Documentation of `set_var` shows it's for the currently
    // running process only.
    // This was originally only intended to set two environment variables:
    // TVM_LDE_TRACE and RAYON_NUM_THREADS, as these are used by Triton VM. But
    // if upstream dependencies can understand more arguments, they can of
    // course be set here as well. The cool feature is that environment
    // variables can be set as a function of the padded height. Something that
    // allows for fine-tuning of the parameters to upstream provers.
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
            std::env::set_var(&key, &value);
        }

        // In case Triton VM has already made the cache decision prior to
        // the environment variable being set here, we override it through
        // a publicly exposed function. This override ensures that the Triton
        // VM configuration agrees with the environment variable.
        if key == triton_vm::config::ENV_VAR_LDE_CACHE {
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

/// Configure and run the STARK prover. Returns the proof.
fn prove(job: NeptuneProverJob) -> Proof {
    let stark: Stark = Stark::default();

    // Generate the Algebraic Execution Trace (AET) to determine the padded
    // table height, which is an input to later calculations.
    let (aet, _) = VM::trace_execution(
        job.program.clone(),
        (&job.claim.input).into(),
        job.non_determinism.clone(),
    )
    .unwrap();
    let log2_padded_height = aet.padded_height().ilog2() as u8;

    // Use std-err for logging purposes since spawner (caller) doesn't get the
    // log outputs but can capture std-err.
    eprintln!("DEBUG: actual log2 padded height for proof: {log2_padded_height}");

    if job
        .max_log2_padded_height
        .is_some_and(|max| log2_padded_height > max)
    {
        eprintln!(
            "ERROR: Canceling prover because padded height exceeds max value of {}",
            job.max_log2_padded_height.unwrap()
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
    let env_vars = job
        .env_vars
        .get(&log2_padded_height)
        .map(|x| x.to_owned())
        .unwrap_or_default();
    let env_vars: HashMap<String, String> = env_vars.into_iter().collect();

    set_environment_variables(&env_vars);

    // Check for a delegated prover, for this padded height.
    if let Some(prover_cmd) = env_vars.get(NEPTUNE_PROVER_ENV_VAR) {
        if !prover_cmd.trim().is_empty() {
            execute_in_custom_prover(prover_cmd.to_string(), job);

            #[cfg(test)]
            {
                use crate::triton_vm::prelude::BFieldElement;
                return Proof(bfe_vec![44, 55, 66]);
            }

            // Compiler not smart enough to know this line is dead, as above
            // call exits the process.
            #[cfg(not(test))]
            std::process::exit(99);
        }
    }

    // run with a low priority so that neptune-core can remain responsive.
    set_current_thread_priority(ThreadPriority::Min).unwrap();

    stark.prove(&job.claim, &aet).unwrap()
}

/// Generate a proof with Triton VM library, write proof to stdout, and exit
/// the process.
fn execute(job: NeptuneProverJob) {
    #[cfg(test)]
    let claim = job.claim.clone();

    let proof = prove(job);
    eprintln!("DEBUG: triton-vm-prover: completed proof");

    #[cfg(test)]
    {
        assert!(triton_vm::verify(Stark::default(), &claim, &proof));
    }

    // Write serialized proof to STDOUT.
    let as_bytes = bincode::serialize(&proof).unwrap();
    let mut stdout = std::io::stdout();
    stdout.write_all(&as_bytes).unwrap();
    stdout.flush().unwrap();
}

/// Generate a proof with a custom Triton VM prover, and exit the process. IO
/// is expected to behave as in [`execute`] such that parent process can read
/// proof from this process' std out.
fn execute_in_custom_prover(prover_cmd: String, job: NeptuneProverJob) {
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

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("ERROR: Failed to spawn custom prover command");

    let job_payload = serde_json::to_vec(&job).expect("JSON encoding must work");
    child
        .stdin
        .as_mut()
        .expect("Failed to open stdin")
        .write_all(&job_payload)
        .expect("Failed to write to stdin");

    let exit_status = child.wait().expect("ERROR: Failed to wait for process");

    std::process::exit(exit_status.code().unwrap_or(1));
}

/// Entry point for the standalone prover process.
///
/// It consumes JSON-serialized task definitions from STDIN and produces
/// a binary-serialized Proof on STDOUT.
fn main() {
    eprintln!("DEBUG: Starting triton-vm-prover.");

    // Read task definition from STDIN.
    let stdin = std::io::stdin();
    let job: NeptuneProverJob = match serde_json::from_reader(stdin.lock()) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("ERROR: Failed to deserialize TritonVMProverJob from STDIN:\n{e}");
            std::process::exit(1);
        }
    };

    // Check for a delegated prover.
    if let Ok(prover_cmd) = std::env::var(NEPTUNE_PROVER_ENV_VAR) {
        if !prover_cmd.trim().is_empty() {
            execute_in_custom_prover(prover_cmd, job);

            // Compiler not smart enough to know this return not needed.
            return;
        }
    }

    execute(job);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod neptune_prover_tests {
    use neptune_cash::api::export::Claim;
    use neptune_cash::api::export::Program;
    use neptune_cash::application::config::triton_vm_env_vars::TritonVmEnvVars;
    use tasm_lib::triton_vm;
    use tasm_lib::triton_vm::isa::triton_asm;
    use tasm_lib::triton_vm::vm::NonDeterminism;

    use super::*;

    fn job_with_env_vars() -> NeptuneProverJob {
        let program = triton_asm!(halt);
        let program = Program::new(&program);
        let claim = Claim::about_program(&program);
        let non_determinism = NonDeterminism::default();
        let max_log2_padded_height = None;
        let mut env_vars = TritonVmEnvVars::default();
        env_vars.insert(
            8,
            vec![
                (
                    triton_vm::config::ENV_VAR_LDE_CACHE.to_owned(),
                    "no_cache".to_owned(),
                ),
                ("RAYON_NUM_THREADS".to_owned(), "3".to_owned()),
            ],
        );

        NeptuneProverJob {
            program,
            claim: claim.clone(),
            non_determinism,
            max_log2_padded_height,
            env_vars,
        }
    }

    #[cfg(unix)]
    #[test]
    fn custom_provers_work() {
        let mut job = job_with_env_vars();
        let env_vars = job.env_vars.get_mut(&8).unwrap();
        env_vars.push((
            NEPTUNE_PROVER_ENV_VAR.to_owned(),
            "/usr/bin/echo potato".to_string(),
        ));

        eprintln!("env_vars: {env_vars:?}");

        execute(job);
    }

    #[test]
    fn execute_works() {
        execute(job_with_env_vars());
    }

    #[test]
    fn setting_tvm_env_vars_works() {
        let job = job_with_env_vars();
        let proof = prove(job.clone());

        assert!(triton_vm::verify(Stark::default(), &job.claim, &proof));

        // Verify that env variables were actually set
        assert_eq!(
            "no_cache",
            std::env::var(triton_vm::config::ENV_VAR_LDE_CACHE).unwrap()
        );
        assert_eq!("3", std::env::var("RAYON_NUM_THREADS").unwrap());
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
        let proof = prove(job);

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
