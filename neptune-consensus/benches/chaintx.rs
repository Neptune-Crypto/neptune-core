//! Benchmark performance claims justifying the chaining pipeline.
//!
//! # Claim 1: `Forge + Fix` is faster than `Collect + Raise`.
//!
//! Tested on a 2-in transaction with identical primitive witness across the
//! legacy and chaining pipelines.
//!
//! Verdict: true.
//!
//! Timings come from Alan's 24-thread 12th Gen Intel(R) Core(TM) i9-12900K
//! machine with 123 GB of RAM and `TVM_LDE_TRACE=no_cache` set.
//!
//! |              | legacy: Collect + Raise | chaining: Forge + Fix |
//! |--------------|-------------------------|-----------------------|
//! | total # rows |        2 183 168        |        1 572 864      |
//! | largest PH   |        2 097 152        |        1 048 576      |
//! | time         |          858 s          |           599 s       |
//!
//! 30% faster with the chaining pipeline.
//!
//! # Claim 2: linking transactions is faster than producing them separately
//! with the legacy pipeline and then merging them.
//!
//! The quantitative comparison is not like-for-like. Linking transactions
//! admits reusing addition records (thruputs) whereas there is no thruput
//! analogue in the legacy pipeline. So the closest thing to linking N
//! chaining-transactions is to produce N *independent* legacy-transactions and
//! then merge them. So that's the thing being measured and compared:
//!
//!  `Forge + (N-1) * (Chain + Forge) + Fix` is faster than
//! `Collect + Raise + (N-1) * (Merge + Collect + Raise)`
//!
//! Verdict: true.
//!
//! Once again, timings come from Alan's 24-thread 12th Gen Intel(R) Core(TM)
//! i9-12900K machine with 123 GB of RAM and `TVM_LDE_TRACE=no_cache` set.
//!
//! ```text
//!  chained: 2 interactions
//!    Forge[0]  height  1048576     392.5 s
//!    Forge[1]  height  1048576     391.7 s
//!    Chain[0]  height  1048576     397.5 s
//!    Fix       height   524288     178.9 s
//!    TOTAL     height  3670016    1360.6 s
//!
//!  legacy: 2 separate transactions
//!    RemovalRecordsIntegrity[0]  height    65536      11.5 s
//!    CollectLockScripts[0]       height     4096       0.5 s
//!    KernelToOutputs[0]          height     8192       0.9 s
//!    CollectTypeScripts[0]       height     8192       0.8 s
//!    Raise[0]                    height  2097152     839.9 s
//!    RemovalRecordsIntegrity[1]  height    65536      11.5 s
//!    CollectLockScripts[1]       height     4096       0.5 s
//!    KernelToOutputs[1]          height     8192       0.7 s
//!    CollectTypeScripts[1]       height     8192       0.8 s
//!    Raise[1]                    height  2097152     850.4 s
//!    Merge[0]                    height  1048576     401.7 s
//!    TOTAL                       height  5414912    2119.2 s
//! ```
//!
//! The chaining pipeline is 36% faster at N=2. Note the marginal cost: one more
//! chained interaction is `Forge + Chain` ≈ 790 s, whereas one more legacy
//! transaction is `Raise + Merge` ≈ 1250 s.

fn main() {
    divan::main();
}

/// Trace a stage, prove it, and report both costs.
mod stage {
    use std::time::Duration;
    use std::time::Instant;

    use neptune_consensus::proof_abstractions::SecretWitness;
    use neptune_consensus::transaction::validity::neptune_proof::Proof;
    use tasm_lib::triton_vm::prelude::*;
    use tasm_lib::triton_vm::proof::Proof as TritonProof;
    use tasm_lib::triton_vm::stark::Stark;

    pub struct Stage {
        pub name: String,
        pub padded_height: usize,
        pub prove: Duration,
    }

    /// Prove `program` against `claim`, timing the prover and nothing else.
    ///
    /// Tracing happens first and is not timed: the algebraic execution trace is
    /// an input to the prover, and reporting its padded height alongside the
    /// seconds is the whole point -- height is the machine-independent number,
    /// seconds the one the claim is phrased in.
    pub fn prove(
        name: &str,
        program: Program,
        claim: &Claim,
        nondeterminism: NonDeterminism,
    ) -> (Stage, Proof) {
        let (aet, output) = VM::trace_execution(program, (&claim.input).into(), nondeterminism)
            .unwrap_or_else(|e| panic!("{name} must halt gracefully: {e}"));
        assert_eq!(output, claim.output, "{name} output must match its claim");
        let padded_height = aet.padded_height();

        let tick = Instant::now();
        let proof: TritonProof = Prover::new(Stark::default())
            .prove(claim, &aet)
            .unwrap_or_else(|e| panic!("{name} must prove: {e}"));
        let prove = tick.elapsed();

        let stage = Stage {
            name: name.to_owned(),
            padded_height,
            prove,
        };

        (stage, proof.into())
    }

    /// [`prove`] a witness against the claim and program it names itself.
    pub fn prove_witness<W: SecretWitness>(name: &str, witness: &W) -> (Stage, Proof) {
        prove(
            name,
            witness.program(),
            &witness.claim(),
            witness.nondeterminism(),
        )
    }

    /// Print the stages of one route, and what they add up to.
    pub fn report(route: &str, stages: &[Stage]) {
        let width = stages.iter().map(|s| s.name.len()).max().unwrap_or(0);
        println!("\n{route}");
        for stage in stages {
            println!(
                "  {:<width$}  height {:>8}  {:>8.1} s",
                stage.name,
                stage.padded_height,
                stage.prove.as_secs_f64(),
            );
        }
        println!(
            "  {:<width$}  height {:>8}  {:>8.1} s",
            "TOTAL",
            stages.iter().map(|s| s.padded_height).sum::<usize>(),
            stages
                .iter()
                .map(|s| s.prove)
                .sum::<Duration>()
                .as_secs_f64(),
        );
    }
}

/// Fixtures and stage sequences shared by both benchmarks.
mod route {
    use neptune_consensus::chaintx::chain::ChainWitness;
    use neptune_consensus::chaintx::forge::ForgeWitness;
    use neptune_consensus::chaintx::link_primitive_witness::LinkPrimitiveWitness;
    use neptune_consensus::chaintx::link_tx::LinkTx;
    use neptune_consensus::chaintx::link_tx::LinkTxProof;
    use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
    use neptune_consensus::proof_abstractions::tasm::program::TritonProgram;
    use neptune_consensus::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use neptune_consensus::proof_abstractions::triton_vm_job_queue::vm_job_queue;
    use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
    use neptune_consensus::transaction::validity::collect_lock_scripts::CollectLockScriptsWitness;
    use neptune_consensus::transaction::validity::collect_type_scripts::CollectTypeScriptsWitness;
    use neptune_consensus::transaction::validity::kernel_to_outputs::KernelToOutputsWitness;
    use neptune_consensus::transaction::validity::proof_collection::ProofCollection;
    use neptune_consensus::transaction::validity::removal_records_integrity::RemovalRecordsIntegrityWitness;
    use neptune_consensus::transaction::validity::single_proof::SingleProof;
    use neptune_consensus::transaction::validity::single_proof::SingleProofWitness;
    use neptune_consensus::transaction::validity::tasm::single_proof::fix_branch::FixWitness;
    use neptune_consensus::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
    use neptune_consensus::transaction::Transaction;
    use neptune_consensus::transaction::TransactionProof;
    use tasm_lib::prelude::Digest;

    use super::stage;
    use super::stage::Stage;

    /// The rule set that has the `Fix` branch, hence the only one under which a
    /// chained transaction reaches a block.
    pub const RULE_SET: ConsensusRuleSet = ConsensusRuleSet::HardforkDelta;

    /// The `D` indexing the `Link[D]` family: the digest of the `SingleProof`
    /// program that `Fix` is a branch of.
    pub fn single_proof_digest() -> Digest {
        SingleProof::new(RULE_SET).hash()
    }

    fn options() -> TritonVmProofJobOptions {
        TritonVmProofJobOptions::default()
    }

    /// Run the sequence a chained transaction takes to a `SingleProof`:
    /// `Forge`, then one `Chain` per predecessor folded in, then `Fix`.
    ///
    /// `links` must chain to an empty thruput list, or `Fix` rejects.
    pub async fn chain_route(links: &[LinkPrimitiveWitness]) -> Vec<Stage> {
        let d = single_proof_digest();
        let mut stages = vec![];

        let mut forged = vec![];
        for (i, lpw) in links.iter().enumerate() {
            // The lock- and type-script proofs come from the cache: they are
            // common to both routes and so are measured by neither.
            let witness = ForgeWitness::produce(lpw, d, vm_job_queue(), options())
                .await
                .unwrap();
            let (stage, proof) = stage::prove_witness(&format!("Forge[{i}]"), &witness);
            stages.push(stage);
            forged.push(LinkTx {
                kernel: lpw.kernel.clone(),
                proof: LinkTxProof::Proof(proof),
            });
        }

        let mut chained = forged.remove(0);
        for (i, operand) in forged.into_iter().enumerate() {
            let witness = ChainWitness::chain(chained, operand, d, [i as u8; 32]);
            let (stage, proof) = stage::prove_witness(&format!("Chain[{i}]"), &witness);
            stages.push(stage);
            chained = LinkTx {
                kernel: witness.link_kernel(),
                proof: LinkTxProof::Proof(proof),
            };
        }
        assert!(
            chained.kernel.thruputs.is_empty(),
            "a chained transaction must resolve every thruput before it can be fixed"
        );

        let witness = SingleProofWitness::from_fix(FixWitness::fix(chained));
        let (stage, _) = stage::prove(
            "Fix",
            witness.program(RULE_SET),
            &witness.claim(RULE_SET),
            witness.nondeterminism(RULE_SET),
        );
        stages.push(stage);

        stages
    }

    /// Run the sequence a legacy transaction takes to a `SingleProof`: prove
    /// the four collection programs, then raise them recursively.
    ///
    /// Returns the stages alongside the transaction, so a caller can go on to
    /// merge it.
    pub async fn raise_route(pw: &PrimitiveWitness, label: &str) -> (Vec<Stage>, Transaction) {
        let mut stages = vec![
            stage::prove_witness(
                &format!("RemovalRecordsIntegrity{label}"),
                &RemovalRecordsIntegrityWitness::from(pw),
            )
            .0,
            stage::prove_witness(
                &format!("CollectLockScripts{label}"),
                &CollectLockScriptsWitness::from(pw),
            )
            .0,
            stage::prove_witness(
                &format!("KernelToOutputs{label}"),
                &KernelToOutputsWitness::from(pw),
            )
            .0,
            stage::prove_witness(
                &format!("CollectTypeScripts{label}"),
                &CollectTypeScriptsWitness::from(pw),
            )
            .0,
        ];

        // The collection the raise recurses into. Assembled through the cache:
        // its four proofs are the ones just measured, and its script proofs are
        // the ones the chained route also pays for.
        let collection = ProofCollection::produce(pw, RULE_SET, vm_job_queue(), options())
            .await
            .unwrap();
        let witness = SingleProofWitness::from_collection(collection);
        let (stage, proof) = stage::prove(
            &format!("Raise{label}"),
            witness.program(RULE_SET),
            &witness.claim(RULE_SET),
            witness.nondeterminism(RULE_SET),
        );
        stages.push(stage);

        let transaction = Transaction {
            kernel: pw.kernel.clone(),
            proof: TransactionProof::SingleProof(proof),
        };

        (stages, transaction)
    }

    /// Merge `transactions` down to one, left to right.
    pub fn merge_route(transactions: Vec<Transaction>) -> Vec<Stage> {
        let mut stages = vec![];
        let mut transactions = transactions.into_iter();
        let mut merged = transactions.next().expect("nothing to merge");
        for (i, operand) in transactions.enumerate() {
            let witness = SingleProofWitness::from_merge(MergeWitness::from_transactions(
                merged,
                operand,
                [i as u8; 32],
            ));
            let (stage, proof) = stage::prove(
                &format!("Merge[{i}]"),
                witness.program(RULE_SET),
                &witness.claim(RULE_SET),
                witness.nondeterminism(RULE_SET),
            );
            let SingleProofWitness::Merger(merge_witness) = &witness else {
                unreachable!("just built as a merger")
            };
            merged = Transaction {
                kernel: merge_witness.new_kernel.clone(),
                proof: TransactionProof::SingleProof(proof),
            };
            stages.push(stage);
        }

        stages
    }

    /// Block on `future` on a fresh runtime.
    ///
    /// Divan benchmarks are synchronous and the proof-producing constructors
    /// are not.
    pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }
}

/// `Forge` (RRI inlined, proven once, non-recursively) against `Collect`+`Raise`
/// (RRI proven on its own, then verified recursively inside `SingleProof`).
mod cost {
    use neptune_consensus::chaintx::link_primitive_witness::LinkPrimitiveWitness;
    use neptune_consensus::chaintx::test_helpers::deterministic_primitive_witness;

    use super::route;
    use super::stage;

    /// Two inputs, two outputs, one announcement -- the shape `consensus.rs`
    /// calls the common case.
    const NUM_INPUTS: usize = 2;

    #[divan::bench(sample_count = 1, sample_size = 1)]
    fn forge_versus_raise() {
        let pw = deterministic_primitive_witness(NUM_INPUTS);

        // No thruputs: the two routes must carry the *same* transaction, and a
        // thruput is an input the legacy route cannot express.
        let lpw = LinkPrimitiveWitness::from_primitive_witness(pw.clone(), 0);

        let chained = route::block_on(route::chain_route(std::slice::from_ref(&lpw)));
        let (raised, _) = route::block_on(route::raise_route(&pw, ""));

        stage::report("chained: Forge -> Fix", &chained);
        stage::report("legacy: Collect -> Raise", &raised);
    }
}

/// `N` interactions collapsing into one block-borne transaction: chained, or
/// the closest the legacy pipeline can come.
mod throughput {
    use neptune_consensus::chaintx::test_helpers::fan_in_link_primitive_witnesses;
    use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use super::route;
    use super::stage;

    /// One successor funded by `N - 1` predecessors, all chained down to a
    /// thruput-free transaction and fixed.
    fn chained<const N: usize>() {
        let (predecessors, successor) = fan_in_link_primitive_witnesses(N - 1);
        let links = [predecessors, vec![successor]].concat();

        let stages = route::block_on(route::chain_route(&links));
        stage::report(&format!("chained: {N} interactions"), &stages);
    }

    /// `N` transactions over one mutator set, each raised on its own and then
    /// merged -- what a block can hold today.
    ///
    /// These are necessarily *independent* transactions. The chained fixture's
    /// successor spends its predecessors' unconfirmed outputs, which is the one
    /// thing this route cannot express; there is no matched legacy fixture, and
    /// that absence is the thruput claim.
    ///
    /// One input, two outputs, one announcement: an input apiece like the
    /// chained fixture's predecessors, and an output side like its successor.
    /// No coinbase -- one of these would otherwise draw one, and a coinbase
    /// transaction has no counterpart in a chain at all.
    fn separate<const N: usize>() {
        let mut test_runner = TestRunner::deterministic();
        let pws = PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets_and_given_coinbase(
            [(1, 2, 1); N],
            None,
        )
        .new_tree(&mut test_runner)
        .unwrap()
        .current();

        let mut stages = vec![];
        let mut transactions = vec![];
        for (i, pw) in pws.iter().enumerate() {
            let (raised, transaction) = route::block_on(route::raise_route(pw, &format!("[{i}]")));
            stages.extend(raised);
            transactions.push(transaction);
        }
        stages.extend(route::merge_route(transactions));

        stage::report(&format!("legacy: {N} separate transactions"), &stages);
    }

    #[divan::bench(sample_count = 1, sample_size = 1)]
    fn chained_2() {
        chained::<2>()
    }

    #[divan::bench(sample_count = 1, sample_size = 1)]
    fn separate_2() {
        separate::<2>()
    }

    #[divan::bench(sample_count = 1, sample_size = 1)]
    fn chained_4() {
        chained::<4>()
    }

    #[divan::bench(sample_count = 1, sample_size = 1)]
    fn separate_4() {
        separate::<4>()
    }
}
