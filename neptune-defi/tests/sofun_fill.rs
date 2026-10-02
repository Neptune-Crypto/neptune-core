//! A SOFuN order filled in a coinbase transaction, end to end, on RegTest.
//!
//! The test plays the plugin. It places an order, finds it in the order book,
//! builds the coinbase transaction that fills it, and hands that transaction
//! to a node over JSON-RPC. The node mines it and its wallet picks up the
//! composer's outputs.

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;

use neptune_cash::api::export::GlobalStateLock;
use neptune_cash::application::config::cli_args::Args;
use neptune_consensus::block::Block;
use neptune_consensus::block::MINING_REWARD_TIME_LOCK_PERIOD;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::primitive_witness::PrimitiveWitness;
use neptune_consensus::transaction::transparent_input::TransparentInput;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_defi::chain::ObservedBlock;
use neptune_defi::standing_swap_order::order_book::OrderBook;
use neptune_defi::standing_swap_order::sofun::Sofun;
use neptune_defi::standing_swap_order::sofun::SofunParams;
use neptune_defi::standing_swap_order::sofun::NUM_GRID_POINTS;
use neptune_defi::standing_swap_order::StandingSwapOrder;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use neptune_rpc_api::api::ops::Namespace;
use neptune_rpc_api::api::rpc::RpcApi;
use neptune_rpc_api::model::mining::RpcPrimitiveWitness;
use neptune_rpc_client::http::HttpClient;
use neptune_wallet::address::KeyType;
use neptune_wallet::address::ReceivingAddress;
use neptune_wallet::transaction_details::TransactionDetails;
use neptune_wallet::transaction_output::TxOutput;
use neptune_wallet::unlocked_utxo::UnlockedUtxo;
use neptune_wallet::utxo_notification::UtxoNotificationMethod;
use num_traits::CheckedSub;
use tasm_lib::prelude::Digest;
use tokio::net::TcpListener;

const NETWORK: Network = Network::RegTest;

/// A RegTest node with a fresh wallet, serving the JSON-RPC namespaces a
/// plugin uses, with unrestricted access.
async fn start_node() -> (HttpClient, GlobalStateLock) {
    async fn free_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    let mut args = Args::default_with_network(NETWORK);
    args.peer_port = free_port().await;
    args.quic_port = free_port().await;
    args.tcp_port = free_port().await;
    args.rpc_port = free_port().await;
    let rpc_address = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port().await));
    args.listen_rpc = Some(rpc_address);
    args.rpc_modules = vec![Namespace::Wallet, Namespace::Personal, Namespace::Mining];
    args.unsafe_rpc = true;
    args.data_dir = Some(
        std::env::temp_dir()
            .join("neptune-defi-tests")
            .join(format!("{:016x}", rand::random::<u64>())),
    );

    let mut main_loop = neptune_cash::initialize(args, None).await.unwrap();
    let state = main_loop.global_state_lock();
    tokio::spawn(async move { main_loop.run().await.unwrap() });

    // The RPC server needs a moment to start listening.
    tokio::time::sleep(Duration::from_secs(1)).await;

    (HttpClient::new(format!("http://{rpc_address}")), state)
}

/// Have the node mine one block on its tip, and return that block.
async fn mine_block(state: &mut GlobalStateLock) -> Block {
    state
        .api_mut()
        .regtest_mut()
        .mine_blocks_to_wallet(1, false)
        .await
        .unwrap();
    state.lock_guard().await.chain.tip().clone()
}

fn native_currency(amount: NativeCurrencyAmount, release_date: Option<Timestamp>) -> Utxo {
    let utxo = Utxo::new_native_currency(Digest::default(), amount);
    match release_date {
        Some(release_date) => utxo.with_time_lock(release_date),
        None => utxo,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sofun_order_is_filled_in_a_coinbase_transaction() {
    let (client, mut state) = start_node().await;
    let genesis = state.lock_guard().await.chain.tip().clone();
    let mut book = OrderBook::<Sofun>::new(Sofun::asset_pair(), 10);
    let observe = |book: &mut OrderBook<Sofun>, block: &Block| {
        let update = book.observe(&ObservedBlock::from(block));
        book.apply(update.clone()).unwrap();
        update
    };
    observe(&mut book, &genesis);

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
    assert_eq!(1, observe(&mut book, &block_1).opened.len());

    // The plugin picks the order to fill, and the earliest grid point whose
    // reward counts as time-locked.
    let filled_at = Timestamp::now().max(block_1.header().timestamp + Timestamp::millis(1));
    let height = block_1.header().height.next();
    let subsidy = Block::block_subsidy(height);
    let demanded = subsidy.half();
    let best = book.best_fill(demanded, filled_at).unwrap();
    let (order_id, order) = (best.id, best.order);
    let reward = (0..NUM_GRID_POINTS)
        .map(|k| order.reward(k).unwrap())
        .find(|reward| {
            reward
                .utxo
                .release_date()
                .is_some_and(|date| date >= filled_at + MINING_REWARD_TIME_LOCK_PERIOD)
        })
        .unwrap();

    // The order UTXO's membership proof, from the node.
    let snapshot = client
        .restore_membership_proof(vec![order.absolute_index_set(order_id)])
        .await
        .unwrap()
        .snapshot;
    let mutator_set = MutatorSetAccumulator::from(snapshot.synced_mutator_set);
    let membership_proof = snapshot.membership_proofs[0]
        .clone()
        .extract_ms_membership_proof(
            order_id.0,
            order.offered_sender_randomness(),
            order.offered_receiver_preimage(),
        )
        .unwrap();

    // Block 2 fills the order. Its coinbase transaction spends the order UTXO,
    // pays the reward, and pays the rest to the node's wallet, with on-chain
    // notifications so that the wallet finds them. On a chain this young,
    // every input must lustrate, which reveals the order's amount; the order
    // announcement made it public already. The order's input counts
    // toward the total that must be half time-locked, so the composer
    // time-locks half of the offered amount on top of the reward.
    let address = client
        .generate_address(KeyType::Generation)
        .await
        .unwrap()
        .address;
    let address = ReceivingAddress::from_bech32m(&address, NETWORK).unwrap();
    let composer_output = |amount, release_date| {
        let utxo = Utxo::new_native_currency(address.lock_script_hash(), amount);
        let utxo = match release_date {
            Some(release_date) => utxo.with_time_lock(release_date),
            None => utxo,
        };
        TxOutput::onchain_utxo(utxo, rand::random(), address.clone(), true)
    };
    let time_locked = offered.half();
    let liquid = (subsidy + offered)
        .checked_sub(&(demanded + time_locked))
        .unwrap();
    let placeholder_witness = order.lock_script().cancel(Digest::default());
    let fill = TransactionDetails::new(
        UnlockedUtxo::unlock(
            order_utxo.utxo.clone(),
            placeholder_witness,
            membership_proof,
        ),
        vec![
            TxOutput::new(
                reward.utxo.clone(),
                reward.sender_randomness,
                reward.receiver_digest,
                UtxoNotificationMethod::None,
                false,
                false,
            ),
            composer_output(
                time_locked,
                Some(filled_at + MINING_REWARD_TIME_LOCK_PERIOD + Timestamp::days(1)),
            ),
            composer_output(liquid, None),
        ],
        NativeCurrencyAmount::coins(0),
        Some(subsidy),
        filled_at,
        mutator_set,
        NETWORK,
    )
    .with_announcements(Announcement::lustration_announcements(
        block_1.header().pow.lustration_status().unwrap(),
        &[TransparentInput {
            utxo: order_utxo.utxo,
            aocl_leaf_index: order_id.0,
            sender_randomness: order.offered_sender_randomness(),
            receiver_preimage: order.offered_receiver_preimage(),
        }],
    ));

    // The fill witness points into the kernel's outputs, so it can only be
    // computed once the kernel is. The kernel does not depend on it.
    let mut witness: PrimitiveWitness = fill.primitive_witness();
    witness.lock_scripts_and_witnesses[0] = order.lock_script().fill(&witness.kernel).unwrap();
    witness.validate().await.unwrap();

    let balance_before = wallet_balance(&state).await;
    client
        .set_coinbase_tx(Some(RpcPrimitiveWitness::from(&witness)))
        .await
        .unwrap();
    let block_2 = mine_block(&mut state).await;

    assert_eq!(vec![order_id], observe(&mut book, &block_2).closed);
    let outputs = &block_2.body().transaction_kernel.outputs;
    assert!(outputs.contains(&reward.addition_record()));
    assert_eq!(
        balance_before + time_locked + liquid,
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
