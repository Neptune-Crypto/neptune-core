use divan::Bencher;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::Timestamp;
use neptune_cash::models::blockchain::block::Block;

fn main() {
    divan::main();
}

mod maintain_membership_proofs {
    use super::*;

    /// Maintain 100 membership proofs, while receiving an additional 100 UTXOs.
    mod maintain_100_100 {

        use neptune_cash::bench_helpers::devops_wallet_state_genesis;
        use neptune_cash::bench_helpers::next_block_incoming_utxos;

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
                        &genesis.mutator_set_accumulator_after(),
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
                            &block1.mutator_set_accumulator_after(),
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
