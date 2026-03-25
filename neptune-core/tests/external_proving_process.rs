#![recursion_limit = "256"]

use std::collections::HashMap;
use std::time::SystemTime;

use itertools::Itertools;
use neptune_cash::api::export::Claim;
use neptune_cash::api::export::Program;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::ProverJob;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::ProverJobSettings;
use neptune_cash::protocol::proof_abstractions::tasm::prover_job::ProverProcessCompletion;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::isa::triton_instr;
use tasm_lib::triton_vm::prelude::triton_asm;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::VMState;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::bfe_array;
use tasm_lib::twenty_first::bfe_vec;
use tasm_lib::twenty_first::prelude::BFieldElement;
use tokio::sync::watch;

#[tokio::test(flavor = "multi_thread")]
async fn can_prove_out_of_process_2in() {
    // Initialize a global subscriber that definitely writes to stdout.
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    // Compile claim.
    let code = triton_asm! {
        // _

        read_io 2

        halt

    };
    let program = Program::new(&code);
    let input = bfe_vec![499, 501];
    let nondeterminism = NonDeterminism::default();
    let mut vm_state = VMState::new(
        program.clone(),
        input.clone().into(),
        nondeterminism.clone(),
    );
    vm_state.run().unwrap();
    let output = vm_state.public_output;
    let claim = Claim::about_program(&program)
        .with_input(input)
        .with_output(output);

    // Compile job.
    let job = ProverJob::new(
        program,
        claim.clone(),
        nondeterminism.clone(),
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
    let verdict = stark.verify(&claim, &proof);
    assert!(verdict.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn can_prove_out_of_process_fibonacci() {
    // Initialize a global subscriber that definitely writes to stdout.
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    // Merkle nodes
    let sibling1: Digest = Digest::new(bfe_array![101, 102, 103, 104, 105]);
    let sibling2: Digest = Digest::new(bfe_array![205, 204, 203, 202, 201]);
    let leaf: Digest = Digest::new(bfe_array![35, 34, 33, 32, 31]);
    let root: Digest = Tip5::hash_pair(Tip5::hash_pair(sibling1, leaf), sibling2);

    // Macro
    let push_digest = |d: Digest| {
        d.reversed()
            .values()
            .into_iter()
            .map(|b| triton_instr!(push b))
            .collect_vec()
    };

    // Compile claim.
    let fibonacci_code = triton_asm! {
        // _

        // test fibonacci loop
        read_io 2
        add
        push 0
        push 1

        // _ num_iterations 0 1

        call fib_loop
        // _ 0 fib_{n-1} fib_n

        write_io 1
        pop 2

        // test nondeterministic tokens
        divine 5
        push 1
        push 2
        push 3
        push 4
        push 5
        assert_vector error_id 1

        // test nondeterministic digests
        push 1
        {&push_digest(leaf)}
        // _ 1 [leaf]

        merkle_step
        merkle_step
        // _ 0 [root]

        {&push_digest(root)}
        // _ 0 [root] [root]

        assert_vector error_id 2
        pop 5
        // _ 0

        push 0 eq assert error_id 3
        // _

        // test nondeterministic memory
        push 13
        read_mem 1
        pop 1
        push 37 eq assert error_id 4
        pop 1

        // add extra output
        push 5005
        write_io 1

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
    let input = bfe_vec![499, 501];
    let nondeterminism = NonDeterminism::new(bfe_vec![1, 2, 3, 4, 5])
        .with_digests(vec![sibling1, sibling2])
        .with_ram(
            [(bfe!(13), bfe!(37))]
                .into_iter()
                .collect::<HashMap<_, _>>(),
        );
    let mut vm_state = VMState::new(
        fibonacci_program.clone(),
        input.clone().into(),
        nondeterminism.clone(),
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
        nondeterminism.clone(),
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

// Some tests require functions that are hidden behind the #[cfg(test)]
// decoration. This test module activates that guard.
#[cfg(test)]
pub mod tests {
    use super::*;
    use neptune_cash::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use neptune_cash::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
    use neptune_cash::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputsWitness;
    use neptune_cash::protocol::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use neptune_cash::protocol::proof_abstractions::tasm::program::TritonProgram;
    use neptune_cash::protocol::proof_abstractions::SecretWitness;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;

    #[tokio::test(flavor = "multi_thread")]
    async fn can_prove_out_of_process_kernel_to_outputs() {
        // Initialize a global subscriber that definitely writes to stdout.
        let _ = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init();

        // Get test setup.
        let num_inputs = 2;
        let num_outputs = 2;
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness =
            PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        let std_input = kernel_to_outputs_witness.standard_input();
        let non_determinism = kernel_to_outputs_witness.nondeterminism();
        let tasm_result = KernelToOutputs
            .run_tasm(&std_input, non_determinism.clone())
            .unwrap();
        assert_eq!(kernel_to_outputs_witness.output(), tasm_result);

        let rust_result = KernelToOutputs
            .run_rust(&std_input, non_determinism.clone())
            .unwrap();
        assert_eq!(rust_result, tasm_result);

        // Compile program and claim.
        let program = KernelToOutputs.program();
        let output = rust_result;
        let claim = Claim::about_program(&program)
            .with_input(std_input)
            .with_output(output);

        // Compile job.
        let job = ProverJob::new(
            program,
            claim.clone(),
            non_determinism.clone(),
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
}
