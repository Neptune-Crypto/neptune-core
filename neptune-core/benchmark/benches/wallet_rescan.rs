use divan::Bencher;
use itertools::Itertools;
use neptune_cash::api::export::BlockHeight;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::application::config::cli_args;
use neptune_cash::bench_helpers::devops_global_state_genesis;
use neptune_cash::bench_helpers::extract_expected_utxos;
use neptune_cash::bench_helpers::next_block_empty;
use neptune_cash::bench_helpers::next_block_incoming_utxos;
use neptune_cash::protocol::consensus::block::Block;
use neptune_cash::state::wallet::utxo_notification::UtxoNotificationMedium;

fn main() {
    divan::main();
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RescanOperation {
    Announced,
    Expected,
    Outgoing,
}

mod rescan {

    use super::*;

    fn rescan_110_blocks(bencher: Bencher, operation: RescanOperation) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let network = Network::Main;
        let mut cli_args = cli_args::Args::default_with_network(network);
        cli_args.utxo_index = true;
        let mut global_state = rt.block_on(devops_global_state_genesis(cli_args));
        let mut global_state = rt.block_on(global_state.lock_guard_mut());

        let genesis = Block::genesis(network);
        let own_address = global_state
            .wallet_state
            .nth_spending_key(KeyType::Generation, 102)
            .to_address();

        // Bump derivation counter to register 102nd key as own
        rt.block_on(
            global_state
                .wallet_state
                .bump_derivation_index(KeyType::Generation, 200),
        );

        let notification_medium = if operation == RescanOperation::Announced {
            UtxoNotificationMedium::OnChain
        } else {
            UtxoNotificationMedium::OffChain
        };

        // Add 10 blocks with UTXOs for us, and 100 without UTXOs for us.
        let mut block = genesis;
        let mut tx_outputs;
        for _ in 0..10 {
            let timestamp = block.header().timestamp + Timestamp::months(7);
            (block, tx_outputs) = rt.block_on(next_block_incoming_utxos(
                &block,
                own_address.clone(),
                10,
                &global_state.wallet_state,
                timestamp,
                network,
                notification_medium,
            ));
            let expected_utxos =
                extract_expected_utxos(&global_state.wallet_state, tx_outputs.iter());
            rt.block_on(global_state.wallet_state.add_expected_utxos(expected_utxos));
            rt.block_on(global_state.set_new_tip(block.clone()))
                .unwrap();

            for _ in 0..10 {
                let timestamp = block.header().timestamp + Timestamp::minutes(2);
                block = next_block_empty(&block, timestamp, network);
                rt.block_on(global_state.set_new_tip(block.clone()))
                    .unwrap();
            }
        }

        // Clear MUTXOs to ensure rescan actually finds something
        rt.block_on(global_state.wallet_state.wallet_db.clear_mutxos());

        // In the case of outgoing, we must ensure that the own UTXOs are known
        // first, so outgoing has something (absolute indices) to look for. And
        // we don't want that operation to be timed as part of the benchmark.
        let all_keys = global_state
            .wallet_state
            .get_all_known_spending_keys()
            .collect_vec();
        let first: BlockHeight = 0u64.into();
        let last: BlockHeight = 200u64.into();
        if operation == RescanOperation::Outgoing {
            rt.block_on(global_state.rescan_expected_incoming(first, last));
            rt.block_on(global_state.rescan_announced_incoming(all_keys.clone(), first, last))
                .unwrap();
        }

        // Run the rescan method we are actually interested in timing.
        bencher.bench_local(|| match operation {
            RescanOperation::Announced => rt
                .block_on(global_state.rescan_announced_incoming(all_keys.clone(), first, last))
                .unwrap(),
            RescanOperation::Expected => {
                rt.block_on(global_state.rescan_expected_incoming(first, last))
            }
            RescanOperation::Outgoing => rt
                .block_on(global_state.rescan_outgoing(first, last))
                .unwrap(),
        });
    }

    #[divan::bench(sample_count = 10)]
    fn rescan_110_blocks_announced_bench(bencher: Bencher) {
        rescan_110_blocks(bencher, RescanOperation::Announced);
    }

    #[divan::bench(sample_count = 10)]
    fn rescan_110_blocks_expected_bench(bencher: Bencher) {
        rescan_110_blocks(bencher, RescanOperation::Expected);
    }

    #[divan::bench(sample_count = 10)]
    fn rescan_110_blocks_outgoing_bench(bencher: Bencher) {
        rescan_110_blocks(bencher, RescanOperation::Outgoing);
    }
}
