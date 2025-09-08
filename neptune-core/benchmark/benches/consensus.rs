fn main() {
    divan::main();
}

mod transaction {
    use std::fs::create_dir_all;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;

    use neptune_cash::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use neptune_cash::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScripts;
    use neptune_cash::protocol::consensus::transaction::validity::collect_lock_scripts::CollectLockScriptsWitness;
    use neptune_cash::protocol::consensus::transaction::validity::collect_type_scripts::CollectTypeScripts;
    use neptune_cash::protocol::consensus::transaction::validity::collect_type_scripts::CollectTypeScriptsWitness;
    use neptune_cash::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputs;
    use neptune_cash::protocol::consensus::transaction::validity::kernel_to_outputs::KernelToOutputsWitness;
    use neptune_cash::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
    use neptune_cash::protocol::consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrityWitness;
    use neptune_cash::protocol::consensus::type_scripts::native_currency::NativeCurrency;
    use neptune_cash::protocol::consensus::type_scripts::native_currency::NativeCurrencyWitness;
    use neptune_cash::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_active_timelocks;
    use neptune_cash::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;
    use neptune_cash::protocol::consensus::type_scripts::time_lock::TimeLock;
    use neptune_cash::protocol::consensus::type_scripts::time_lock::TimeLockWitness;
    use neptune_cash::protocol::proof_abstractions::tasm::program::ConsensusProgram;
    use neptune_cash::protocol::proof_abstractions::timestamp::Timestamp;
    use neptune_cash::protocol::proof_abstractions::SecretWitness;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::generate_full_profile;
    use tasm_lib::snippet_bencher::write_benchmarks;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::snippet_bencher::BenchmarkResult;
    use tasm_lib::snippet_bencher::NamedBenchmarkResult;
    use tasm_lib::triton_vm::prelude::*;

    const COMMON: (usize, usize) = (2, 2);
    const LARGEISH: (usize, usize) = (4, 4);

    /// Benchmark the TASM code for a consensus program, and write the result to
    /// disk.
    pub fn bench_consensus_program<CP: ConsensusProgram>(
        cp: CP,
        input: &PublicInput,
        nondeterminism: NonDeterminism,
        name: &str,
        case: BenchmarkCase,
    ) {
        let program = cp.program();
        let (aet, _output) = VM::trace_execution(program, input.clone(), nondeterminism).unwrap();
        let benchmark_result = BenchmarkResult::new(&aet);
        let benchmark = NamedBenchmarkResult {
            name: name.to_owned(),
            benchmark_result,
            case,
        };

        write_benchmarks(vec![benchmark]);
    }

    /// Generate a profile report for the program and store it to disk.
    fn profile_consensus_program<CP: ConsensusProgram>(
        cp: CP,
        input: &PublicInput,
        nondeterminism: NonDeterminism,
        name: &str,
    ) {
        let program = cp.program();
        let (_aet, _output) =
            VM::trace_execution(program.clone(), input.clone(), nondeterminism.clone()).unwrap();
        let profile = generate_full_profile(name, program, input, &nondeterminism);
        write_profile(name.to_string(), profile);
    }

    /// Store the profile report to disk.
    fn write_profile(name: String, profile: String) {
        let mut path = PathBuf::new();
        path.push("profiles");
        create_dir_all(&path).expect("profiles directory should exist");
        path.push(Path::new(&name).with_extension("profile"));
        let mut output_file = File::create(&path).expect("open file for writing");
        output_file
            .write_all(profile.as_bytes())
            .expect("cannot write to file");
    }

    fn bench_and_profile_consensus_program<CP: ConsensusProgram + Clone>(
        cp: CP,
        input: &PublicInput,
        nondeterminism: NonDeterminism,
        name: &str,
        case: BenchmarkCase,
    ) {
        bench_consensus_program(cp.clone(), input, nondeterminism.clone(), name, case);
        profile_consensus_program(cp, input, nondeterminism, name);
    }

    #[divan::bench(sample_count = 1, args = [COMMON, LARGEISH])]
    fn removal_records_integrity(args: (usize, usize)) {
        let (num_inputs, num_outputs) = args;
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness =
            PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);

        bench_and_profile_consensus_program(
            RemovalRecordsIntegrity,
            &removal_records_integrity_witness.standard_input(),
            removal_records_integrity_witness.nondeterminism(),
            &format!("RemovalRecordsIntegrity-{num_inputs}in-{num_outputs}out"),
            BenchmarkCase::CommonCase,
        );
    }

    #[divan::bench(sample_count = 1, args = [COMMON, LARGEISH])]
    fn time_lock(args: (usize, usize)) {
        let (num_inputs, num_outputs) = args;
        let mut test_runner = TestRunner::deterministic();
        let deterministic_now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness = arbitrary_primitive_witness_with_expired_timelocks(
            num_inputs,
            num_outputs,
            2,
            deterministic_now,
        )
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
        let tl_witness: TimeLockWitness = primitive_witness.into();

        bench_and_profile_consensus_program(
            TimeLock,
            &tl_witness.standard_input(),
            tl_witness.nondeterminism(),
            &format!("TimeLock-{num_inputs}in-{num_outputs}out"),
            BenchmarkCase::CommonCase,
        );
    }

    #[divan::bench(sample_count = 1, args = [COMMON, LARGEISH])]
    fn native_currency(args: (usize, usize)) {
        let (num_inputs, num_outputs) = args;
        let mut test_runner = TestRunner::deterministic();
        let deterministic_now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness = arbitrary_primitive_witness_with_active_timelocks(
            num_inputs,
            num_outputs,
            2,
            deterministic_now,
        )
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
        let nc_witness = NativeCurrencyWitness {
            salted_input_utxos: primitive_witness.input_utxos,
            salted_output_utxos: primitive_witness.output_utxos,
            kernel: primitive_witness.kernel,
        };
        bench_and_profile_consensus_program(
            NativeCurrency,
            &nc_witness.standard_input(),
            nc_witness.nondeterminism(),
            &format!("NativeCurrency-{num_inputs}in-{num_outputs}out"),
            BenchmarkCase::CommonCase,
        );
    }

    #[divan::bench(sample_count = 1, args = [COMMON, LARGEISH])]
    fn collect_lock_scripts(args: (usize, usize)) {
        let (num_inputs, num_outputs) = args;
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness =
            PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let collect_lock_scripts_witness = CollectLockScriptsWitness::from(&primitive_witness);
        bench_and_profile_consensus_program(
            CollectLockScripts,
            &collect_lock_scripts_witness.standard_input(),
            collect_lock_scripts_witness.nondeterminism(),
            &format!("CollectLockScripts-{num_inputs}in-{num_outputs}out"),
            BenchmarkCase::CommonCase,
        );
    }

    #[divan::bench(sample_count = 1, args = [COMMON, LARGEISH])]
    fn collect_type_scripts(args: (usize, usize)) {
        let (num_inputs, num_outputs) = args;
        let mut test_runner = TestRunner::deterministic();
        let deterministic_now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness = arbitrary_primitive_witness_with_active_timelocks(
            num_inputs,
            num_outputs,
            2,
            deterministic_now,
        )
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
        let collect_type_scripts_witness = CollectTypeScriptsWitness::from(&primitive_witness);
        bench_and_profile_consensus_program(
            CollectTypeScripts,
            &collect_type_scripts_witness.standard_input(),
            collect_type_scripts_witness.nondeterminism(),
            &format!("CollectTypeScripts-{num_inputs}in-{num_outputs}out"),
            BenchmarkCase::CommonCase,
        );
    }

    #[divan::bench(sample_count = 1, args = [COMMON, LARGEISH])]
    fn kernel_to_outputs(args: (usize, usize)) {
        let (num_inputs, num_outputs) = args;
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness =
            PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        bench_and_profile_consensus_program(
            KernelToOutputs,
            &kernel_to_outputs_witness.standard_input(),
            kernel_to_outputs_witness.nondeterminism(),
            &format!("KernelToOutputs-{num_inputs}in-{num_outputs}out"),
            BenchmarkCase::CommonCase,
        );
    }
}
