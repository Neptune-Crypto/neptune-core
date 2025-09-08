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

mod resync_membership_proofs {
    use super::*;

    mod sync_200_msmps_over_10_blocks {

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

    /// Maintain 400 membership proofs, while receiving an additional 10 UTXOs.
    mod maintain_400_10 {
        use super::*;

        fn update_wallet_with_block2(bencher: Bencher, maintain_msmps_from_block_data: bool) {
            const NUM_UTXOS_MAINTAINED: usize = 400;
            const NUM_NEW_UTXOS: usize = 10;
            let rt = tokio::runtime::Runtime::new().unwrap();
            let network = Network::Main;
            let mut global_state_lock = rt.block_on(devops_global_state_genesis(Network::Main));
            let mut global_state = rt.block_on(global_state_lock.lock_guard_mut());

            let genesis = Block::genesis(network);
            let own_address = rt
                .block_on(
                    global_state
                        .wallet_state
                        .next_unused_spending_key(KeyType::Generation),
                )
                .to_address();
            let block1_time = Network::Main.launch_date() + Timestamp::months(7);
            let block1 = rt.block_on(next_block_incoming_utxos(
                &genesis,
                own_address.clone(),
                NUM_UTXOS_MAINTAINED,
                &global_state.wallet_state,
                block1_time,
                network,
            ));

            rt.block_on(global_state.set_new_tip(block1.clone()))
                .unwrap();

            let block2_time = block1_time + Timestamp::hours(1);
            let block2 = rt.block_on(next_block_incoming_utxos(
                &block1,
                own_address,
                NUM_NEW_UTXOS,
                &global_state.wallet_state,
                block2_time,
                network,
            ));

            // update the mutator set with the UTXOs from this block
            rt.block_on(
                global_state
                    .chain
                    .archival_state_mut()
                    .update_mutator_set(&block2),
            )
            .unwrap();
            *global_state.chain.light_state_mut() = std::sync::Arc::new(block2.clone());

            bencher.bench_local(|| {
                rt.block_on(async {
                    let recovery_data = global_state
                        .wallet_state
                        .update_wallet_state_with_new_block(
                            &block1.mutator_set_accumulator_after().unwrap(),
                            &block2,
                            maintain_msmps_from_block_data,
                        )
                        .await
                        .unwrap();

                    global_state
                        .restore_monitored_utxos_from_archival_mutator_set(Some(recovery_data))
                        .await
                });
            });
        }

        #[divan::bench(sample_count = 10)]
        fn apply_block2_maintain_msmps(bencher: Bencher) {
            update_wallet_with_block2(bencher, true);
        }

        #[divan::bench(sample_count = 10)]
        fn apply_block2_no_maintain_msmps(bencher: Bencher) {
            update_wallet_with_block2(bencher, false);
        }
    }
}
