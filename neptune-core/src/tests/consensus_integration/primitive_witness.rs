use macro_rules_attr::apply;
use neptune_consensus::block::Block;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::transaction_details::TransactionDetails;
use tracing_test::traced_test;

use crate::tests::shared_tokio_runtime;

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn nop_pw_is_valid() {
    let network = Network::Main;
    let genesis = Block::genesis(network);
    let nop = TransactionDetails::nop(
        genesis.mutator_set_accumulator_after().unwrap(),
        Timestamp::now(),
        network,
    );
    let nop = nop.primitive_witness();
    assert!(nop.validate().await.is_ok(), "nop PW must be valid");
}
