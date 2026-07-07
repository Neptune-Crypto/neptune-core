//! Test-support constructors and proptest strategies for transactions.

use itertools::Itertools;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::timestamp::Timestamp;
use proptest::collection::vec;
use proptest::prelude::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest_arbitrary_interop::arb;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::bfe;

use crate::transaction::transaction_kernel::TransactionKernelProxy;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::Transaction;
use crate::transaction::TransactionProof;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;

/// Make a transaction with `Invalid` transaction proof.
pub fn make_mock_transaction(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
) -> Transaction {
    make_mock_transaction_with_mutator_set_hash(inputs, outputs, Digest::default())
}

pub fn make_mock_transaction_with_mutator_set_hash_and_timestamp(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
    timestamp: Timestamp,
) -> Transaction {
    Transaction {
        kernel: TransactionKernelProxy {
            inputs,
            outputs,
            announcements: vec![],
            fee: NativeCurrencyAmount::coins(1),
            timestamp,
            coinbase: None,
            mutator_set_hash,
            merge_bit: false,
        }
        .into_kernel(),
        proof: TransactionProof::invalid(),
    }
}

pub fn make_mock_transaction_with_mutator_set_hash(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    mutator_set_hash: Digest,
) -> Transaction {
    let timestamp = Timestamp::now();

    make_mock_transaction_with_mutator_set_hash_and_timestamp(
        inputs,
        outputs,
        mutator_set_hash,
        timestamp,
    )
}

/// `count` primitive-witness-backed transactions with expired time locks and
/// the given timestamp.
pub fn make_mock_txs_with_primitive_witness_with_timestamp(
    count: usize,
    timestamp: Timestamp,
) -> Vec<Transaction> {
    let mut test_runner = TestRunner::deterministic();
    let primitive_witnesses = vec(
        arbitrary_primitive_witness_with_expired_timelocks(2, 2, 2, timestamp),
        count,
    )
    .new_tree(&mut test_runner)
    .unwrap()
    .current();

    primitive_witnesses
        .into_iter()
        .map(|pw| Transaction {
            kernel: pw.kernel.clone(),
            proof: TransactionProof::Witness(pw),
        })
        .collect_vec()
}

/// `count` primitive-witness-backed transactions with expired time locks and a
/// deterministic timestamp.
pub fn make_plenty_mock_transaction_supported_by_primitive_witness(
    count: usize,
) -> Vec<Transaction> {
    let mut test_runner = TestRunner::deterministic();
    let deterministic_now = arb::<Timestamp>()
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
    make_mock_txs_with_primitive_witness_with_timestamp(count, deterministic_now)
}

/// `count` transactions carrying an `Invalid` single proof.
pub fn make_plenty_mock_transaction_supported_by_invalid_single_proofs(
    count: usize,
) -> Vec<Transaction> {
    let mut sp_backeds = make_plenty_mock_transaction_supported_by_primitive_witness(count);
    for pw_backed in &mut sp_backeds {
        pw_backed.proof = TransactionProof::invalid();
    }

    sp_backeds
}

/// `count` transactions carrying a single proof of the given size, in bytes.
pub fn mock_transactions_with_sized_single_proof(
    count: usize,
    proof_size_in_bytes: usize,
) -> Vec<Transaction> {
    let mut sp_backeds = make_plenty_mock_transaction_supported_by_primitive_witness(count);
    let proof_size_in_num_bfes = proof_size_in_bytes / BFieldElement::BYTES;
    for sp_backed in &mut sp_backeds {
        sp_backed.proof =
            TransactionProof::SingleProof(Proof::from(vec![bfe!(0); proof_size_in_num_bfes]));
    }

    sp_backeds
}

/// Proptest strategies producing [`TransactionKernel`]s.
///
/// [`TransactionKernel`]: crate::transaction::transaction_kernel::TransactionKernel
pub mod txkernel {
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::strategies::removalrecord;
    use neptune_primitives::timestamp::Timestamp;
    use proptest::collection;
    use proptest::prelude::*;
    use proptest::prop_compose;
    use proptest::sample::SizeRange;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Digest;

    use crate::transaction::transaction_kernel::TransactionKernel;
    use crate::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    pub fn default(fee_nonegative: bool) -> impl Strategy<Value = TransactionKernel> {
        self::with_lengths(1usize..=5, 1usize..=6, 0usize..5, fee_nonegative)
    }

    prop_compose! {
        pub fn with_lengths(
            num_inputs: impl Into<SizeRange>,
            num_outputs: impl Into<SizeRange>,
            num_announcements: impl Into<SizeRange>,
            fee_nonegative: bool,
        ) (
            inputs in collection::vec(removalrecord(), num_inputs),
            outputs in collection::vec(arb::<AdditionRecord>(), num_outputs),
            announcements in collection::vec(collection::vec(arb::<tasm_lib::triton_vm::prelude::BFieldElement>(), 10..59), num_announcements).prop_map(
                |vecvec| itertools::Itertools::collect_vec(vecvec.into_iter().map(|message| crate::transaction::announcement::Announcement{message}))
            ),
            fee in arb::<NativeCurrencyAmount>(),
            coinbase in arb::<Option<NativeCurrencyAmount>>(),
            timestamp in arb::<Timestamp>(),
            mutator_set_hash in arb::<Digest>(),
            merge_bit in any::<bool>(),
        ) -> TransactionKernel {TransactionKernelProxy {
            inputs,
            outputs,
            announcements,
            fee: if fee_nonegative {fee.abs()} else {fee},
            coinbase,
            timestamp,
            mutator_set_hash,
            merge_bit,
        }
        .into_kernel()}
    }

    prop_compose! {
        pub fn with_usualtxdata(
            inputs: Vec<neptune_mutator_set::removal_record::RemovalRecord>,
            outputs: Vec<AdditionRecord>,
            fee: NativeCurrencyAmount,
            timestamp: Timestamp,
        ) (mutator_set_hash in arb::<Digest>()) -> TransactionKernel {
            TransactionKernelProxy {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                announcements: vec![],
                fee,
                timestamp,
                coinbase: None,
                mutator_set_hash,
                merge_bit: false,
            }
            .into_kernel()
        }
    }
}
