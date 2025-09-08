use itertools::Itertools;
use proptest::collection::vec;
use proptest::prelude::Strategy;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest_arbitrary_interop::arb;

use super::Timestamp;
use super::Transaction;
use super::TransactionProof;
use crate::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;

pub(crate) fn make_mock_txs_with_primitive_witness_with_timestamp(
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

pub(crate) fn make_plenty_mock_transaction_supported_by_primitive_witness(
    count: usize,
) -> Vec<Transaction> {
    let mut test_runner = TestRunner::deterministic();
    let deterministic_now = arb::<Timestamp>()
        .new_tree(&mut test_runner)
        .unwrap()
        .current();
    let primitive_witnesses = vec(
        arbitrary_primitive_witness_with_expired_timelocks(2, 2, 2, deterministic_now),
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
