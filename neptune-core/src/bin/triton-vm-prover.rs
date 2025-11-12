#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::io::BufRead;
use std::io::Write;

use neptune_cash::application::config::triton_vm_env_vars::TritonVmEnvVars;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE;
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

// TODO: Replace by value exposed in Triton VM
const LDE_TRACE_ENV_VAR: &str = "TVM_LDE_TRACE";

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

        // In case Triton VM has already set the cache decision prior to
        // the environment variable being set here, we override it through
        // a publicly exposed function.
        if key == LDE_TRACE_ENV_VAR {
            let maybe_overwrite = value.to_ascii_lowercase();
            let cache_lde_trace_overwrite = match maybe_overwrite.as_str() {
                "cache" => Some(CacheDecision::Cache),
                "no_cache" => Some(CacheDecision::NoCache),
                _ => None,
            };
            if let Some(cache_lde_trace_overwrite) = cache_lde_trace_overwrite {
                eprintln!("overwriting cache lde trace to: {cache_lde_trace_overwrite:?}");
                overwrite_lde_trace_caching_to(cache_lde_trace_overwrite);
            }
        }
    }
}

fn execute(
    claim: Claim,
    program: Program,
    non_determinism: NonDeterminism,
    max_log2_padded_height: Option<u8>,
    env_vars: TritonVmEnvVars,
) -> Proof {
    let stark: Stark = Stark::default();

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
        // Exit with error code indicating 1) AET padded height too big, and 2)
        // the log2 padded height. Guaranteed to be in the range [200-232].
        std::process::exit(
            PROOF_PADDED_HEIGHT_TOO_BIG_PROCESS_OFFSET_ERROR_CODE + i32::from(log2_padded_height),
        );
    }

    let env_vars = env_vars
        .get(&log2_padded_height)
        .map(|x| x.to_owned())
        .unwrap_or_default();

    set_environment_variables(&env_vars);

    stark.prove(&claim, &aet).unwrap()
}

fn main() {
    // run with a low priority so that neptune-core can remain responsive.
    //
    // todo: we could accept a thread-prioritycli param (0..100) and
    //       pass it with ThreadPriority::CrossPlatform(x).
    set_current_thread_priority(ThreadPriority::Min).unwrap();

    let stdin = std::io::stdin();
    let mut iterator = stdin.lock().lines();
    let claim: Claim = serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let program: Program = serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let non_determinism: NonDeterminism =
        serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let max_log2_padded_height: Option<u8> =
        serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();
    let env_variables: TritonVmEnvVars =
        serde_json::from_str(&iterator.next().unwrap().unwrap()).unwrap();

    let proof = execute(
        claim,
        program,
        non_determinism,
        max_log2_padded_height,
        env_variables,
    );
    eprintln!("triton-vm: completed proof");

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
