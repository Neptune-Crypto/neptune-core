use divan::Bencher;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::bench_helpers::devops_global_state_genesis;
use neptune_cash::bench_helpers::next_block_incoming_utxos;
use neptune_cash::protocol::consensus::block::Block;

fn main() {
    divan::main();
}

mod set_new_tip {
    use super::*;

    fn update_state(bencher: Bencher) {
        // The goal is to benchmark how long it takes to run `set_new_tip` when
        //  a block has many inputs. To build a block with many inputs, we first
        // need to get the wallet to a state where it has many UTXOs.
        const NUM_INPUTS_IN_TX: usize = 1000;
        const NUM_OUTPUTS_IN_TX: usize = 1000;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let network = Network::Main;

        let mut global_state_lock = rt.block_on(devops_global_state_genesis(network));
        let mut global_state = rt.block_on(global_state_lock.lock_guard_mut());
        let genesis = Block::genesis(network);
        let own_address = rt
            .block_on(
                global_state
                    .wallet_state
                    .next_unused_spending_key(KeyType::Generation),
            )
            .to_address();
        let block1_time = network.launch_date() + Timestamp::months(7);
        let block1 = rt.block_on(next_block_incoming_utxos(
            &genesis,
            own_address.clone(),
            NUM_INPUTS_IN_TX,
            &global_state.wallet_state,
            block1_time,
            network,
        ));

        rt.block_on(global_state.set_new_tip(block1.clone()))
            .unwrap();

        // Wallet now has N inputs it can spend
        let block2_time = block1_time + Timestamp::hours(1);
        let block2 = rt.block_on(next_block_incoming_utxos(
            &block1,
            own_address,
            NUM_OUTPUTS_IN_TX,
            &global_state.wallet_state,
            block2_time,
            network,
        ));

        bencher.bench_local(|| {
            rt.block_on(global_state.set_new_tip(block1.clone()))
                .unwrap();

            rt.block_on(global_state.set_new_tip(block2.clone()))
                .unwrap();
        });
    }

    #[divan::bench(sample_count = 10)]
    fn set_new_tip(bencher: Bencher) {
        update_state(bencher);
    }
}
