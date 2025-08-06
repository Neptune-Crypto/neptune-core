use neptune_cash::api::export::Network;
use neptune_cash::models::blockchain::block::Block;

/// test: Verify that the genesis block on main net has not changed.
#[test]
pub fn genesis_block_hasnt_changed_main_net() {
    assert_eq!(
        "7962e48729acd97e08efa77b5b28d49f2dc0e5609a4f1f1affca5b4549c78e520462a7f955371386",
        Block::genesis(Network::Main).hash().to_hex()
    );
}

/// test: Verify that the genesis block on testnet-0 has not changed.
#[test]
pub fn genesis_block_hasnt_changed_testnet_0() {
    assert_eq!(
        "bb1fa49a35a294dd2c09811c648c4d76f6ea17acc61fe7a6f1c3c8d81c967bc68e7cdb41f472544e",
        Block::genesis(Network::Testnet(0)).hash().to_hex()
    );
}