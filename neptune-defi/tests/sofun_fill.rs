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
use neptune_rpc_client::http::HttpClient;
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

    // The plugin starts at genesis, where there is no order to fill.
    let mut plugin = SofunPlugin::new(client.clone(), NETWORK, 10).await.unwrap();
    assert_eq!(
        Ok(Outcome::NoOrder),
        plugin.on_event(&Event::Lagged(0)).await
    );

    // Block 1 places the order.
    let offered = NativeCurrencyAmount::coins(10);
    let (order, block_1) = place_order(&client, &mut state, offered).await;
    let subsidy = Block::block_subsidy(block_1.header().height.next());

    // Told of block 1, the plugin finds the order and has the node fill it.
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

/// Have the node mine a block that places a SOFuN order offering `offered`,
/// and return the order and the block.
///
/// The block's coinbase transaction pays the offered amount into the order
/// UTXO and announces the order. The rest of the subsidy goes to a lock script
/// no one can unlock; half of it is time-locked, as the coinbase rules demand.
async fn place_order(
    client: &HttpClient,
    state: &mut GlobalStateLock,
    offered: NativeCurrencyAmount,
) -> (StandingSwapOrder<Sofun>, Block) {
    let tip = state.lock_guard().await.chain.tip().clone();
    let placed_at = Timestamp::now();
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
    let subsidy = Block::block_subsidy(tip.header().height.next());
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
        tip.mutator_set_accumulator_after().unwrap(),
        NETWORK,
    )
    .with_announcements([order.announce(&Sofun::asset_pair())]);
    let placement = RpcPrimitiveWitness::from(&placement.primitive_witness());
    client.set_coinbase_tx(Some(placement)).await.unwrap();
    let block = mine_block(state).await;

    (order, block)
}

fn notified(block: &Block) -> Event {
    Event::Notification(Notification {
        kind: Kind::Block,
        id: block.hash(),
    })
}

/// A fill already mined stays set on the node until the plugin hears of the
/// block, and the node then composes its own coinbase transaction rather than
/// a block that spends the order twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_fill_already_mined_is_not_used_again() {
    let (client, mut state) = start_node().await;
    let mut plugin = SofunPlugin::new(client.clone(), NETWORK, 10).await.unwrap();
    plugin.on_event(&Event::Lagged(0)).await.unwrap();
    let (order, block_1) = place_order(&client, &mut state, NativeCurrencyAmount::coins(10)).await;
    assert!(matches!(
        plugin.on_event(&notified(&block_1)).await,
        Ok(Outcome::Filling(_))
    ));

    let block_2 = mine_block(&mut state).await;
    let block_3 = mine_block(&mut state).await;

    let paid = |block: &Block| {
        let outputs = &block.body().transaction_kernel.outputs;
        order
            .rewards()
            .iter()
            .filter(|reward| outputs.contains(&reward.addition_record()))
            .count()
    };
    assert_eq!(1, paid(&block_2));
    assert_eq!(0, paid(&block_3));
    assert_eq!(
        Ok(Outcome::NoOrder),
        plugin.on_event(&Event::Lagged(0)).await
    );
}

/// A notification of a block the node does not know, which any local process
/// can send, is an error that leaves the book as it was, and the plugin goes
/// on with the next real one.
#[tokio::test(flavor = "multi_thread")]
async fn a_spoofed_notification_changes_nothing() {
    let (client, mut state) = start_node().await;
    let mut plugin = SofunPlugin::new(client.clone(), NETWORK, 10).await.unwrap();
    plugin.on_event(&Event::Lagged(0)).await.unwrap();
    let (_, block_1) = place_order(&client, &mut state, NativeCurrencyAmount::coins(10)).await;
    plugin.on_event(&notified(&block_1)).await.unwrap();
    let open_before = plugin.book().open_orders().count();

    let spoofed = Event::Notification(Notification {
        kind: Kind::Block,
        id: rand::random(),
    });
    assert!(plugin.on_event(&spoofed).await.is_err());
    assert_eq!(open_before, plugin.book().open_orders().count());
    assert_eq!(
        Some(block_1.hash()),
        plugin.book().tip().map(|tip| tip.hash)
    );

    let block_2 = mine_block(&mut state).await;
    assert_eq!(
        Ok(Outcome::NoOrder),
        plugin.on_event(&notified(&block_2)).await
    );
}

/// A plugin that missed more blocks than its driver remembers starts its book
/// over at the tip rather than stopping.
#[tokio::test(flavor = "multi_thread")]
async fn a_plugin_that_missed_too_much_starts_over() {
    let (client, mut state) = start_node().await;
    let depth = 2;
    let mut plugin = SofunPlugin::new(client.clone(), NETWORK, depth)
        .await
        .unwrap();
    plugin.on_event(&Event::Lagged(0)).await.unwrap();

    let mut tip = None;
    for _ in 0..=depth {
        tip = Some(mine_block(&mut state).await);
    }
    assert_eq!(
        Ok(Outcome::NoOrder),
        plugin.on_event(&Event::Lagged(0)).await
    );
    assert_eq!(
        tip.map(|block| block.hash()),
        plugin.book().tip().map(|tip| tip.hash)
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
