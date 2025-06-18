use divan::Bencher;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::bench_helpers::devops_wallet_state_genesis;
use neptune_cash::bench_helpers::next_block_incoming_utxos;
use neptune_cash::models::blockchain::block::Block;

fn main() {
    divan::main();
}

mod resync_membership_proofs {
    use super::*;

    mod sync_200_msmps_over_10_blocks {
        use neptune_cash::bench_helpers::devops_global_state_genesis;

        use super::*;

        fn resync_msmps(bencher: Bencher) {
            // Start a fork with a LUCA of block height 1.
            // Each fork has length 10 and contain many UTXOs for the wallet.
            // The benchmark measures how long it takes to resync the mutator
            // set membership proofs from the tip of one fork to the other.
            let rt = tokio::runtime::Runtime::new().unwrap();
            let network = Network::Main;
            let mut global_state_lock = rt.block_on(devops_global_state_genesis(Network::Main));

            let genesis = Block::genesis(network);
            let own_address = rt
                .block_on(
                    rt.block_on(global_state_lock.lock_guard_mut())
                        .wallet_state
                        .next_unused_spending_key(KeyType::Generation),
                )
                .to_address();

            let block1_timestamp = genesis.header().timestamp + Timestamp::months(7);
            let block1 = rt.block_on(next_block_incoming_utxos(
                &genesis,
                own_address.clone(),
                10,
                &rt.block_on(global_state_lock.lock_guard()).wallet_state,
                block1_timestamp,
                network,
            ));
            rt.block_on(global_state_lock.set_new_tip(block1.clone()))
                .unwrap();

            let mut block_a_tip = None;
            for j in 0..=1 {
                let mut block = block1.clone();
                for i in 0..=10 {
                    if i == 0 && j == 1 {
                        // Sync membership proofs to ensure we can create
                        // transactions on the 2nd fork.
                        rt.block_on(global_state_lock.set_new_tip(block1.clone()))
                            .unwrap();
                        rt.block_on(async {
                            global_state_lock
                                .lock_guard_mut()
                                .await
                                .resync_membership_proofs()
                                .await
                                .unwrap()
                        });
                    }

                    // Different block times on each fork to ensure the forks
                    // contain distinct blocks.
                    let block_time = block.header().timestamp + Timestamp::hours(1 + j);
                    let next_block = rt.block_on(next_block_incoming_utxos(
                        &block,
                        own_address.clone(),
                        10,
                        &rt.block_on(global_state_lock.lock_guard()).wallet_state,
                        block_time,
                        network,
                    ));
                    rt.block_on(global_state_lock.set_new_tip(next_block.clone()))
                        .unwrap();
                    block = next_block;
                }
                if j == 0 {
                    block_a_tip = Some(block);
                }
            }

            // Force MSMPs to become unsynced, such that we can resync them and
            // benchmark how long that takes.
            rt.block_on(global_state_lock.set_new_tip(block_a_tip.unwrap()))
                .unwrap();
            let mut global_state = rt.block_on(global_state_lock.lock_guard_mut());
            bencher.bench_local(|| {
                rt.block_on(async { global_state.resync_membership_proofs().await.unwrap() });
            });
        }

        #[divan::bench(sample_count = 10)]
        fn resync_msmps_bench(bencher: Bencher) {
            resync_msmps(bencher);
        }
    }
}

mod maintain_membership_proofs {
    use super::*;

    /// Maintain 100 membership proofs, while receiving an additional 100 UTXOs.
    mod maintain_100_100 {
        use super::*;

        fn update_wallet_with_block2(bencher: Bencher) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let network = Network::Main;
            let mut wallet_state = rt.block_on(devops_wallet_state_genesis(Network::Main));

            let genesis = Block::genesis(network);
            let own_address = rt
                .block_on(wallet_state.next_unused_spending_key(KeyType::Generation))
                .to_address();
            let block1_time = Network::Main.launch_date() + Timestamp::months(7);
            let block1 = rt.block_on(next_block_incoming_utxos(
                &genesis,
                own_address.clone(),
                100,
                &wallet_state,
                block1_time,
                network,
            ));

            rt.block_on(async {
                wallet_state
                    .update_wallet_state_with_new_block(
                        &genesis.mutator_set_accumulator_after().unwrap(),
                        &block1,
                    )
                    .await
                    .unwrap()
            });

            let block2_time = block1_time + Timestamp::hours(1);
            let block2 = rt.block_on(next_block_incoming_utxos(
                &block1,
                own_address,
                100,
                &wallet_state,
                block2_time,
                network,
            ));

            // Benchmark the receival of 100 UTXOs while already managing 100
            // UTXOs in the wallet.
            bencher.bench_local(|| {
                rt.block_on(async {
                    wallet_state
                        .update_wallet_state_with_new_block(
                            &block1.mutator_set_accumulator_after().unwrap(),
                            &block2,
                        )
                        .await
                        .unwrap()
                });
            });
        }

        #[divan::bench(sample_count = 10)]
        fn apply_block2(bencher: Bencher) {
            update_wallet_with_block2(bencher);
        }
    }
}
