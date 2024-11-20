use std::io::BufRead;
use std::io::Write;

use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::prove;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use thread_priority::set_current_thread_priority;
use thread_priority::ThreadPriority;
use tracing::info;

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
    let default_stark: Stark = Stark::default();

    let proof = prove(default_stark, &claim, program, non_determinism).unwrap();
    info!("triton-vm: completed proof");

    let as_bytes = bincode::serialize(&proof).unwrap();
    let mut stdout = std::io::stdout();
    stdout.write_all(&as_bytes).unwrap();
    stdout.flush().unwrap();

    //    std::thread::sleep(std::time::Duration::from_secs(1));
}

#[cfg(test)]
mod tests {
    use tasm_lib::triton_vm::isa::triton_asm;

    use super::*;

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
