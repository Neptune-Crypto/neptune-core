use neptune_consensus::transaction::Transaction;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::timestamp::Timestamp;
use proptest::prelude::*;

// TODO: Change this function into something more meaningful!
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    fee: NativeCurrencyAmount,
    _wallet_state: &crate::state::wallet::wallet_state::WalletState,
    timestamp: Option<Timestamp>,
) -> proptest::prelude::BoxedStrategy<Transaction> {
    neptune_consensus::transaction::test_helpers::txkernel::with_usualtxdata(
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
        proof: neptune_consensus::transaction::transaction_proof::TransactionProof::invalid(),
    })
    .boxed()
}
