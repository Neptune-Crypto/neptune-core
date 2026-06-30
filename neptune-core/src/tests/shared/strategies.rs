use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::removal_record::RemovalRecord;
// The mutator-set proptest strategies now live in the neptune-mutator-set crate;
// re-exported here so existing `tests::shared::strategies::*` paths keep working.
pub use neptune_mutator_set::strategies::absindset;
pub use neptune_mutator_set::strategies::absindset_with_limit;
pub use neptune_mutator_set::strategies::chunkdict;
pub use neptune_mutator_set::strategies::chunkdict_with_leafs_limit;
pub use neptune_mutator_set::strategies::mmrmembershipproof_and_index;
pub use neptune_mutator_set::strategies::msmembershipproof;
pub use neptune_mutator_set::strategies::removalrecord;
use proptest::prelude::*;

use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Timestamp;
use crate::api::export::Transaction;
pub use crate::protocol::consensus::block::tests::arbitrary_kernel as block_with_arbkernel;

// TODO: Change this function into something more meaningful!
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    fee: NativeCurrencyAmount,
    _wallet_state: &crate::state::wallet::wallet_state::WalletState,
    timestamp: Option<Timestamp>,
) -> proptest::prelude::BoxedStrategy<Transaction> {
    crate::protocol::consensus::transaction::test_helpers::txkernel::with_usualtxdata(
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
