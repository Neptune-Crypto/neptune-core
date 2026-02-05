use divan::Bencher;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::application::config::cli_args;
use neptune_cash::bench_helpers::devops_global_state_genesis;
use neptune_cash::bench_helpers::next_block_incoming_utxos;
use neptune_cash::protocol::consensus::block::Block;
use neptune_cash::state::wallet::utxo_notification::UtxoNotificationMedium;

fn main() {
    divan::main();
}

mod wallet_state {
    use neptune_cash::state::GlobalStateLock;

    use super::*;

    async fn setup<const NUM_OUTPUTS_PER_TX: usize, const NUM_BLOCKS: usize>(
    ) -> (GlobalStateLock, [Block; NUM_BLOCKS]) {
        // The goal is to benchmark various parts of state updating or reading
        // when the blocks have many inputs and outputs. To build a block with
        // many inputs, we first need to get the wallet to a state where it has
        // many UTXOs.

        let network = Network::Main;
        let cli_args = cli_args::Args::default_with_network(network);
        let genesis = Block::genesis(network);
        let mut blocks = vec![genesis];

        let mut global_state = devops_global_state_genesis(cli_args).await;
        {
            let mut global_state = global_state.lock_guard_mut().await;
            let own_address = global_state
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await
                .to_address();
            for _ in 0..NUM_BLOCKS {
                let prev = blocks.last().unwrap();
                let timestamp = prev.header().timestamp + Timestamp::months(7);
                let (block, _) = next_block_incoming_utxos(
                    prev,
                    own_address.clone(),
                    NUM_OUTPUTS_PER_TX,
                    &global_state,
                    timestamp,
                    network,
                    UtxoNotificationMedium::OnChain,
                )
                .await;

                global_state.set_new_tip(block.clone()).await.unwrap();

                blocks.push(block);
            }
        }

        (global_state, blocks[1..].to_vec().try_into().unwrap())
    }

    fn wallet_history<const NUM_OUTPUTS_PER_TX: usize, const NUM_BLOCKS: usize>(bencher: Bencher) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut global_state, _) = rt.block_on(setup::<NUM_OUTPUTS_PER_TX, NUM_BLOCKS>());

        let state = rt.block_on(global_state.lock_guard_mut());

        bencher.bench_local(|| {
            let _history = rt.block_on(state.get_balance_history());
        });
    }

    fn wallet_status_for_tip<const NUM_OUTPUTS_PER_TX: usize, const NUM_BLOCKS: usize>(
        bencher: Bencher,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut global_state, _) = rt.block_on(setup::<NUM_OUTPUTS_PER_TX, NUM_BLOCKS>());

        let state = rt.block_on(global_state.lock_guard_mut());

        bencher.bench_local(|| {
            let _spandable_inputs = rt.block_on(state.get_wallet_status_for_tip());
        });
    }

    fn spendable_inputs<const NUM_OUTPUTS_PER_TX: usize, const NUM_BLOCKS: usize>(
        bencher: Bencher,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut global_state, blocks) = rt.block_on(setup::<NUM_OUTPUTS_PER_TX, NUM_BLOCKS>());

        let state = rt.block_on(global_state.lock_guard_mut());

        let timestamp = blocks.last().unwrap().header().timestamp;
        bencher.bench_local(|| {
            let _spandable_inputs = rt.block_on(state.wallet_spendable_inputs(timestamp));
        });
    }

    fn coins_with_possible_timelocks<const NUM_OUTPUTS_PER_TX: usize, const NUM_BLOCKS: usize>(
        bencher: Bencher,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut global_state, _) = rt.block_on(setup::<NUM_OUTPUTS_PER_TX, NUM_BLOCKS>());

        let state = rt.block_on(global_state.lock_guard_mut());

        bencher.bench_local(|| {
            let _coins_list = rt.block_on(state.coins_with_possible_timelocks());
        });
    }

    fn set_new_tip<const NUM_OUTPUTS_PER_TX: usize, const NUM_BLOCKS: usize>(bencher: Bencher) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (mut global_state, blocks) = rt.block_on(setup::<NUM_OUTPUTS_PER_TX, NUM_BLOCKS>());

        let mut global_state = rt.block_on(global_state.lock_guard_mut());

        bencher.bench_local(|| {
            for block in blocks.clone() {
                rt.block_on(global_state.set_new_tip(block)).unwrap();
            }
        });
    }

    #[divan::bench(sample_count = 10)]
    fn set_new_tip_1000_4(bencher: Bencher) {
        set_new_tip::<1000, 4>(bencher);
    }

    #[divan::bench(sample_count = 10)]
    fn wallet_history_1000_4(bencher: Bencher) {
        wallet_history::<1000, 4>(bencher);
    }

    #[divan::bench(sample_count = 10)]
    fn wallet_status_for_tip_1000_4(bencher: Bencher) {
        wallet_status_for_tip::<1000, 4>(bencher);
    }

    #[divan::bench(sample_count = 10)]
    fn spendable_inputs_1000_4(bencher: Bencher) {
        spendable_inputs::<1000, 4>(bencher);
    }

    #[divan::bench(sample_count = 10)]
    fn coins_with_possible_timelocks_1000_4(bencher: Bencher) {
        coins_with_possible_timelocks::<1000, 4>(bencher);
    }
}
