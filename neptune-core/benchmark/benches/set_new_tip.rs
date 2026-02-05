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

mod set_new_tip {

    use super::*;

    fn update_state<const NUM_OUTPUTS_IN_TX: usize, const NUM_BLOCKS: usize>(bencher: Bencher) {
        // The goal is to benchmark how long it takes to run `set_new_tip` when
        // a block has many inputs and outputs. To build a block with many
        // inputs, we first need to get the wallet to a state where it has many
        // UTXOs.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let network = Network::Main;
        let cli_args = cli_args::Args::default_with_network(network);

        let mut global_state = rt.block_on(devops_global_state_genesis(cli_args));
        let mut global_state = rt.block_on(global_state.lock_guard_mut());
        let own_address = rt
            .block_on(
                global_state
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation),
            )
            .to_address();
        let genesis = Block::genesis(network);

        let mut blocks = vec![genesis];
        for _ in 0..NUM_BLOCKS {
            let prev = blocks.last().unwrap();
            let timestamp = prev.header().timestamp + Timestamp::months(7);
            let (block, _) = rt.block_on(next_block_incoming_utxos(
                prev,
                own_address.clone(),
                NUM_OUTPUTS_IN_TX,
                &global_state,
                timestamp,
                network,
                UtxoNotificationMedium::OnChain,
            ));

            rt.block_on(global_state.set_new_tip(block.clone()))
                .unwrap();

            blocks.push(block);
        }

        bencher.bench_local(|| {
            for block in blocks.clone() {
                rt.block_on(global_state.set_new_tip(block)).unwrap();
            }
        });
    }

    #[divan::bench(sample_count = 10)]
    fn set_new_tip_1000_4(bencher: Bencher) {
        update_state::<1000, 4>(bencher);
    }
}
