mod common;

use common::genesis_node::GenesisNode;

#[tokio::test(flavor = "multi_thread")]
pub async fn it_returns_ok() -> anyhow::Result<()> {
    let (_main_loop_handler, _jh) = GenesisNode::start_node(GenesisNode::default_args()).await?;

    println!("Got here");

    Ok(())
}
