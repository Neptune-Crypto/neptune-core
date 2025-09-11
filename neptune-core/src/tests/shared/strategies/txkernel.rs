use proptest::collection;
use proptest::prelude::*;
use proptest::prop_compose;
use proptest::sample::SizeRange;
use proptest_arbitrary_interop::arb;
use tasm_lib::prelude::Digest;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Timestamp;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
use crate::util_types::mutator_set::addition_record::AdditionRecord;

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
        inputs in collection::vec(super::removalrecord(), num_inputs),
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
    pub fn with_usualtxdata(
        inputs: Vec<crate::util_types::mutator_set::removal_record::RemovalRecord>,
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
