//! A driver reading a RegTest node over JSON-RPC.

use neptune_defi::chain::BlockId;
use neptune_defi::chain::ObservedBlock;
use neptune_defi::driver::Chain;
use neptune_defi::driver::ChainError;
use neptune_defi::driver::ChainState;
use neptune_defi::driver::Driver;
use neptune_defi::driver::RpcChain;

use common::mine_block;
use common::start_node;

mod common;

/// The blocks a driver applied, in order.
#[derive(Debug, Default)]
struct Applied(Vec<ObservedBlock>);

impl ChainState for Applied {
    fn apply(&mut self, block: &ObservedBlock) {
        self.0.push(block.clone());
    }

    fn roll_back_to(&mut self, _: BlockId) {
        panic!("a RegTest node of its own does not reorganize");
    }
}

/// The RPC chain reads every block as the node holds it, and the tip; and a
/// driver reading it fills a gap of missed notifications.
#[tokio::test(flavor = "multi_thread")]
async fn a_driver_follows_the_node_over_json_rpc() {
    let (client, mut state) = start_node().await;
    let mut blocks = vec![];
    for _ in 0..3 {
        blocks.push(mine_block(&mut state).await);
    }
    let chain = RpcChain { client };

    for block in &blocks {
        assert_eq!(
            Ok(ObservedBlock::from(block)),
            chain.block(block.hash()).await
        );
    }
    assert_eq!(Ok(blocks[2].hash()), chain.tip().await);
    let unknown = rand::random();
    assert_eq!(
        Err(ChainError::Unknown(unknown)),
        chain.block(unknown).await
    );

    let mut driver = Driver::new(Applied::default(), 10);
    driver.on_block(blocks[0].hash(), &chain).await.unwrap();
    driver.on_block(blocks[2].hash(), &chain).await.unwrap();
    assert_eq!(
        blocks.iter().map(ObservedBlock::from).collect::<Vec<_>>(),
        driver.state().0
    );
}
