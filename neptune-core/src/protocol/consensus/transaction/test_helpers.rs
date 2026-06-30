//! Test-support constructors and proptest strategies for transactions.

use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::prelude::Digest;

use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

/// Make a transaction with `Invalid` transaction proof.
pub(crate) fn make_mock_transaction(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
) -> Transaction {
    make_mock_transaction_with_mutator_set_hash(inputs, outputs, Digest::default())
}

pub(crate) fn make_mock_transaction_with_mutator_set_hash_and_timestamp(
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

pub(crate) fn make_mock_transaction_with_mutator_set_hash(
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

/// Proptest strategies producing [`TransactionKernel`]s.
///
/// [`TransactionKernel`]: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel
pub(crate) mod txkernel {
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::strategies::removalrecord;
    use neptune_primitives::timestamp::Timestamp;
    use proptest::collection;
    use proptest::prelude::*;
    use proptest::prop_compose;
    use proptest::sample::SizeRange;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Digest;

    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

    pub(crate) fn default(fee_nonegative: bool) -> impl Strategy<Value = TransactionKernel> {
        self::with_lengths(1usize..=5, 1usize..=6, 0usize..5, fee_nonegative)
    }

    prop_compose! {
        pub(crate) fn with_lengths(
            num_inputs: impl Into<SizeRange>,
            num_outputs: impl Into<SizeRange>,
            num_announcements: impl Into<SizeRange>,
            fee_nonegative: bool,
        ) (
            inputs in collection::vec(removalrecord(), num_inputs),
            outputs in collection::vec(arb::<AdditionRecord>(), num_outputs),
            announcements in collection::vec(collection::vec(arb::<tasm_lib::triton_vm::prelude::BFieldElement>(), 10..59), num_announcements).prop_map(
                |vecvec| itertools::Itertools::collect_vec(vecvec.into_iter().map(|message| crate::protocol::consensus::transaction::announcement::Announcement{message}))
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
        pub(crate) fn with_usualtxdata(
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
