//! A SOFuN order filled in a coinbase transaction, end to end, on RegTest.
//!
//! The test places an order in a block by hand, and runs the SOFuN plugin
//! against a node over JSON-RPC. The plugin finds the order, builds the
//! coinbase transaction that fills it, and hands that transaction to the
//! node, which mines it; its wallet picks up the composer's outputs.

use neptune_cash::api::export::GlobalStateLock;
use neptune_consensus::block::Block;
use neptune_consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_defi::plugin::Event;
use neptune_defi::plugin::Kind;
use neptune_defi::plugin::Notification;
use neptune_defi::standing_swap_order::sofun::plugin::Outcome;
use neptune_defi::standing_swap_order::sofun::plugin::SofunPlugin;
use neptune_defi::standing_swap_order::sofun::Sofun;
use neptune_defi::standing_swap_order::sofun::SofunParams;
use neptune_defi::standing_swap_order::StandingSwapOrder;
use neptune_primitives::timestamp::Timestamp;
use neptune_rpc_api::api::rpc::RpcApi;
use neptune_rpc_api::model::mining::RpcPrimitiveWitness;
use neptune_wallet::transaction_details::TransactionDetails;
use neptune_wallet::transaction_output::TxOutput;
use neptune_wallet::utxo_notification::UtxoNotificationMethod;
use num_traits::CheckedSub;
use tasm_lib::prelude::Digest;

use common::mine_block;
use common::start_node;
use common::NETWORK;

mod common;

fn native_currency(amount: NativeCurrencyAmount, release_date: Option<Timestamp>) -> Utxo {
    let utxo = Utxo::new_native_currency(Digest::default(), amount);
    match release_date {
        Some(release_date) => utxo.with_time_lock(release_date),
        None => utxo,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_plugin_fills_a_sofun_order_in_a_coinbase_transaction() {
    let (client, mut state) = start_node().await;
    let genesis = state.lock_guard().await.chain.tip().clone();

    // The plugin starts at genesis, where there is no order to fill.
    let mut plugin = SofunPlugin::new(client.clone(), NETWORK, 10).await.unwrap();
    assert_eq!(
        Ok(Outcome::NoOrder),
        plugin.on_event(&Event::Lagged(0)).await
    );

    // Block 1 places the order. Its coinbase transaction pays the offered
    // amount into the order UTXO and announces the order. The rest of the
    // subsidy goes to a lock script no one can unlock; half of it is
    // time-locked, as the coinbase rules demand.
    let placed_at = Timestamp::now();
    let offered = NativeCurrencyAmount::coins(10);
    let order = StandingSwapOrder::<Sofun>::new(
        offered,
        SofunParams {
            d_zero: placed_at + MINING_REWARD_TIME_LOCK_PERIOD + Timestamp::days(1),
            epoch: 0,
        },
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    )
    .unwrap();
    let order_utxo = order.order_utxo();
    let subsidy = Block::block_subsidy(genesis.header().height.next());
    let placement = TransactionDetails::new_with_coinbase(
        vec![
            TxOutput::new(
                order_utxo.utxo.clone(),
                order_utxo.sender_randomness,
                order_utxo.receiver_digest,
                UtxoNotificationMethod::None,
                false,
                false,
            ),
            TxOutput::no_notification_as_change(
                native_currency(
                    subsidy.half(),
                    Some(placed_at + MINING_REWARD_TIME_LOCK_PERIOD),
                ),
                rand::random(),
                rand::random(),
            ),
            TxOutput::no_notification_as_change(
                native_currency(subsidy.half().checked_sub(&offered).unwrap(), None),
                rand::random(),
                rand::random(),
            ),
        ],
        subsidy,
        NativeCurrencyAmount::coins(0),
        placed_at,
        genesis.mutator_set_accumulator_after().unwrap(),
        NETWORK,
    )
    .with_announcements([order.announce(&Sofun::asset_pair())]);
    let placement = RpcPrimitiveWitness::from(&placement.primitive_witness());
    client.set_coinbase_tx(Some(placement)).await.unwrap();
    let block_1 = mine_block(&mut state).await;

    // Told of block 1, the plugin finds the order and has the node fill it.
    let notified = |block: &Block| {
        Event::Notification(Notification {
            kind: Kind::Block,
            id: block.hash(),
        })
    };
    let Ok(Outcome::Filling(order_id)) = plugin.on_event(&notified(&block_1)).await else {
        panic!("the plugin does not fill the order");
    };

    // Block 2 fills the order. It pays the reward at a point of the order's
    // grid, and the composer's share, the subsidy and the offered amount less
    // the reward, to the node's wallet.
    let balance_before = wallet_balance(&state).await;
    let block_2 = mine_block(&mut state).await;
    assert_eq!(
        Ok(Outcome::NoOrder),
        plugin.on_event(&notified(&block_2)).await
    );

    let closed_in = plugin.book().get(order_id).unwrap().closed_in;
    assert_eq!(Some(block_2.hash()), closed_in.map(|block| block.hash));
    let outputs = &block_2.body().transaction_kernel.outputs;
    let rewards_paid = order
        .rewards()
        .iter()
        .filter(|reward| outputs.contains(&reward.addition_record()))
        .count();
    assert_eq!(1, rewards_paid);
    let demanded = order.demanded_amount();
    assert_eq!(
        balance_before + (subsidy + offered).checked_sub(&demanded).unwrap(),
        wallet_balance(&state).await
    );
}

/// The node wallet's confirmed balance at its tip, time-locked coins included.
async fn wallet_balance(state: &GlobalStateLock) -> NativeCurrencyAmount {
    let state = state.lock_guard().await;
    let height = state.chain.tip().header().height;
    state
        .get_wallet_status_for_tip()
        .await
        .confirmed_total_balance(height)
}
