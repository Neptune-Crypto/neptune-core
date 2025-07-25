use proptest::prelude::*;
use proptest::{collection, prop_compose};
use proptest_arbitrary_interop::arb;
use tasm_lib::prelude::Digest;

use crate::api::export::{NativeCurrencyAmount, Timestamp, Transaction};
use crate::models::blockchain::transaction::transaction_kernel::{
    TransactionKernel, TransactionKernelProxy,
};
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

// TODO: Change this function into something more meaningful!
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    fee: NativeCurrencyAmount,
    _wallet_state: &crate::models::state::wallet::wallet_state::WalletState,
    timestamp: Option<Timestamp>,
) -> proptest::prelude::BoxedStrategy<Transaction> {
    super::strategies::txkernel_with_usualtxdata(
        inputs,
        outputs,
        fee,
        match timestamp {
            Some(ts) => ts,
            None => Timestamp::now(),
        },
    )
    .prop_map(|kernel| Transaction {
        kernel,
        proof: crate::api::export::TransactionProof::invalid(),
    })
    .boxed()
}

prop_compose! {
    pub fn txkernel_with_lengths(
        num_inputs: usize,
        num_outputs: usize,
        num_announcements: usize,
    ) (
        inputs in collection::vec(crate::util_types::test_shared::mutator_set::propcompose_rr_with_independent_absindset_chunkdict(), num_inputs),
        outputs in collection::vec(arb::<AdditionRecord>(), num_outputs),
        announcements in collection::vec(collection::vec(arb::<tasm_lib::triton_vm::prelude::BFieldElement>(), 10..59), num_announcements).prop_map(
            |vecvec| itertools::Itertools::collect_vec(vecvec.into_iter().map(|message|crate::models::blockchain::transaction::announcement::Announcement{message}))
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
        fee,
        coinbase,
        timestamp,
        mutator_set_hash,
        merge_bit,
    }
    .into_kernel()}
}

prop_compose! {
    pub fn txkernel_with_usualtxdata(
        inputs: Vec<RemovalRecord>,
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

// TODO ditch this by rewriting the underlying `Strategy` with `IntoRange`
prop_compose! {
    pub fn txkernel() (num_inputs in 1usize..=5, num_outputs in 1usize..=6, num_announcements in 0usize..5)
    (r in txkernel_with_lengths(num_inputs, num_outputs, num_announcements)) -> TransactionKernel {
        r
    }
}
