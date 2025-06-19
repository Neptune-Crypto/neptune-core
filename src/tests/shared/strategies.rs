use proptest::prelude::*;

use crate::api::export::{NativeCurrencyAmount, Timestamp, Transaction};
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

pub use crate::models::blockchain::block::tests::strategies as block;

pub mod txkernel;

// TODO: Change this function into something more meaningful!
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    fee: NativeCurrencyAmount,
    _wallet_state: &crate::models::state::wallet::wallet_state::WalletState,
    timestamp: Option<Timestamp>,
) -> proptest::prelude::BoxedStrategy<Transaction> {
    txkernel::with_usualtxdata(
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
