use std::time::SystemTime;

use neptune_cash::api::export::Claim;
use neptune_cash::api::export::Program;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::ProverJob;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::ProverJobSettings;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::ProverProcessCompletion;
use tasm_lib::triton_vm::prelude::triton_asm;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::VMState;
use tasm_lib::twenty_first::bfe_vec;
use tasm_lib::twenty_first::prelude::BFieldElement;
use tokio::sync::watch;

#[tokio::test(flavor = "multi_thread")]
async fn can_prove_out_of_process() {
    // Initialize a global subscriber that definitely writes to stdout.
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    // Compile claim.
    let fibonacci_code = triton_asm! {
        // _

        read_io 1
        push 0
        push 1

        // _ num_iterations 0 1

        call fib_loop
        // _ 0 fib_{n-1} fib_n

        write_io 1
        pop 2
        halt

        fib_loop:
            // _ n a b

            swap 1
            dup 1
            add
            // _ n b a+b

            pick 2
            addi -1
            place 2
            // _ n-1 b a+b

            dup 2 skiz recurse
            // _ 0 b a+b

            return

    };
    let fibonacci_program = Program::new(&fibonacci_code);
    let input = bfe_vec![1000];
    let mut vm_state = VMState::new(
        fibonacci_program.clone(),
        input.clone().into(),
        NonDeterminism::default(),
    );
    vm_state.run().unwrap();
    let output = vm_state.public_output;
    let claim = Claim::about_program(&fibonacci_program)
        .with_input(input)
        .with_output(output);

    // Compile job.
    let job = ProverJob::new(
        fibonacci_program,
        claim.clone(),
        NonDeterminism::default(),
        ProverJobSettings::default(),
    );

    // Execute job.
    let tick = SystemTime::now();
    let (_cancel_tx, cancel_rx) = watch::channel::<()>(());
    let prover_result = match job.prove_out_of_process(cancel_rx).await {
        Ok(r) => r,
        Err(e) => {
            panic!("Out of process job, launched according to happy path, errored: {e:?}")
        }
    };
    let ProverProcessCompletion::Finished(proof) = prover_result else {
        panic!("out-of-process prover was canceled unexpectedly");
    };
    let tock = tick.elapsed().unwrap();
    println!("Out-of-process proof took {tock:?}");

    // Verify.
    let stark = Stark::default();
    let verdict = tasm_lib::triton_vm::verify(stark, &claim, &proof);
    assert!(verdict);
}
