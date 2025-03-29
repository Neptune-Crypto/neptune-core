mod common;

use common::genesis_node::GenesisNode;
use neptune_cash::tx_initiation::export::KeyType;
use neptune_cash::tx_initiation::export::Timestamp;
use neptune_cash::tx_initiation::export::NativeCurrencyAmount;
use tracing_test::traced_test;

#[traced_test]
#[tokio::test(flavor = "multi_thread")]
pub async fn send_alice_to_bob() -> anyhow::Result<()> {
    let mut args = GenesisNode::default_args();
    args.peer_port += 1000;
    args.rpc_port += 1000;

    let (mut alice_gsl, _jh) = GenesisNode::start_node(GenesisNode::default_args()).await?;
    let (mut bob_gsl, _jh) = GenesisNode::start_node(args).await?;

    // todo: make a tx_initiation::receive module.
    let bob_address = bob_gsl
        .lock_guard_mut()
        .await
        .wallet_state
        .next_unused_spending_key(KeyType::Generation)
        .await
        .unwrap()  // for now.
        .to_address()
        .unwrap();  // for now.

    let mut alice_sender = alice_gsl.tx_sender_mut();

    let result = alice_sender.send(
        vec![(bob_address, NativeCurrencyAmount::coins_from_str("2.45")?)],
        Default::default(),
        0.into(),
        Timestamp::now(),
    ).await;

    assert!(result.is_err());

    if let Err(e) = result {
        println!("{}", e);
    }


    // println!("tx sent!");

    Ok(())
}
