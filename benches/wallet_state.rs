use divan::Bencher;

fn main() {
    divan::main();
}

mod maintain_membership_proofs {
    use super::*;

    /// Maintain 100 membership proofs, while receiving an additional 100 UTXOs.
    mod maintain_100_100 {
        use neptune_cash::api::export::KeyType;
        use neptune_cash::api::export::Timestamp;
        use neptune_cash::api::wallet::Wallet;
        use neptune_cash::models::state::GlobalState;

        use super::helper::next_block_incoming_utxos;
        use super::*;

        fn update_wallet_with_block2(bencher: Bencher) {
            let rt = tokio::runtime::Runtime::new().unwrap();

            // obtain global-state-lock and blocks at height 2 and 3.
            // height 1 = mined coinbase to wallet.
            // height 2 = mined coinbase to wallet + sent 100 utxo to self.
            // height 3 = mined coinbase to wallet + sent 100 utxo to self.
            let (gsl, block2, block3) = rt.block_on(async {
                // note: network is regtest, for mock blocks
                let cli = super::helper::cli();

                // init neptune-cash, obtain main-loop-handler
                let main_loop_handler = neptune_cash::initialize(cli).await.unwrap();
                let gsl = main_loop_handler.global_state_lock();

                // we must run the main loop in order to fully process mined blocks
                // we use Option::take() to satisfy the borrow-checker.
                let mut handler_for_task = Some(main_loop_handler);

                let main_loop_jh = tokio::spawn(async move {
                    let mut main_loop = handler_for_task.take().unwrap();
                    let _ = main_loop.run().await;
                });

                // the regtest api provides methods to mine next block(s) to our wallet.
                let mut regtest = gsl.api().regtest_mut();

                // obtain some coins by mining a block to our wallet.
                let block1_digest = regtest
                    .mine_block_to_wallet(Timestamp::now())
                    .await
                    .unwrap();

                // obtain newly mined block
                let block1 = gsl.lock_guard().await.chain.light_state().clone();
                assert_eq!(block1_digest, block1.hash());

                // wallet api simplifies obtaining next receiving address.
                let mut wallet: Wallet = gsl.clone().into();
                let own_address = wallet
                    .next_receiving_address(KeyType::Generation)
                    .await
                    .unwrap();

                // obtain blocks 2 and 3 with 100 utxos sent to own wallet in each.
                let (block2, block3) = {
                    let block2 =
                        next_block_incoming_utxos(gsl.clone(), own_address.clone(), 100).await;

                    let block3 = next_block_incoming_utxos(gsl.clone(), own_address, 100).await;

                    (block2, block3)
                };

                // give the main loop a chance to process messages.
                // needed for now since we don't have a good way to request
                // graceful shutdown.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                // end the main loop. later we should have a cleaner way to do this.
                main_loop_jh.abort();
                let _ = main_loop_jh.await;

                (gsl, block2, block3)
            });

            // we need to extract the inner GlobalState holding the WalletState
            // so that lock-acquisitions are not performed inside the benchmark
            // as that would inflate the numbers.

            // brute force: drop runtime to ensure no other clones of gsl.
            // this is because MainLoopHandler does not (yet) expose a
            // proper shutdown method, so spawned tasks may outlive it.
            drop(rt);

            // perform extraction
            let mut gs: GlobalState = gsl.try_into().unwrap();

            let rt = tokio::runtime::Runtime::new().unwrap();

            // Benchmark the receival of 100 UTXOs while already managing 100
            // UTXOs in the wallet.
            bencher.bench_local(|| {
                rt.block_on(async {
                    gs.wallet_state
                        .update_wallet_state_with_new_block(
                            &block2.mutator_set_accumulator_after(),
                            &block3,
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

mod helper {

    use std::env;
    use std::path::Path;
    use std::path::PathBuf;

    use neptune_cash::api::export::NativeCurrencyAmount;
    use neptune_cash::api::export::Network;
    use neptune_cash::api::export::ReceivingAddress;
    use neptune_cash::api::export::Timestamp;
    use neptune_cash::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
    use neptune_cash::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    use neptune_cash::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
    use neptune_cash::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
    use neptune_cash::config_models::cli_args;
    use neptune_cash::models::blockchain::block::Block;
    use neptune_cash::models::blockchain::transaction::transaction_proof::TransactionProofType;
    use neptune_cash::models::state::GlobalStateLock;
    use neptune_cash::models::state::StateLock;
    use num_traits::ops::checked::CheckedSub;
    use rand::distr::Alphanumeric;
    use rand::distr::SampleString;

    fn benchmark_data_directory() -> PathBuf {
        let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
        env::temp_dir()
            .join(format!("neptune-benchmark-runs-{}", user))
            .join(Path::new(&Alphanumeric.sample_string(&mut rand::rng(), 16)))
    }

    // returns cli args with:
    //   network = RegTest,
    //   data_dir = neptune-benchmark-runs-<user>
    pub fn cli() -> cli_args::Args {
        let mut cli_args = cli_args::Args::default();
        cli_args.network = Network::RegTest;
        cli_args.data_dir = Some(benchmark_data_directory());
        cli_args
    }

    /// Sends the wallet's entire balance to the provided address. Divides the
    /// transaction up into `N` outputs, guaranteeing that the entire available
    /// balance is being spent.
    pub async fn next_block_incoming_utxos(
        gsl: GlobalStateLock,
        recipient: ReceivingAddress,
        num_outputs: usize,
    ) -> Block {
        let one_nau = NativeCurrencyAmount::from_nau(1);
        let fee = one_nau;

        // create N outputs of 1 nau each
        let mut outputs = vec![(recipient.clone(), one_nau); num_outputs - 1];

        // calc change amount and add it to outputs
        let total_spend = outputs
            .iter()
            .map(|(_, amt)| *amt)
            .sum::<NativeCurrencyAmount>()
            + fee;
        let change_amt = gsl
            .api()
            .wallet()
            .balances(Timestamp::now())
            .await
            .confirmed_available
            .checked_sub(&total_spend)
            .unwrap();
        outputs.push((recipient.clone(), change_amt));

        let mut tx_initiator = gsl.api().tx_initiator_mut();

        // build TxOutputList
        let tx_outputs = TxOutputListBuilder::new()
            .outputs(outputs)
            .build(&StateLock::from(gsl.clone()))
            .await;

        // build TxInputList from all spendable inputs
        let tx_inputs = TxInputListBuilder::new()
            .spendable_inputs(tx_initiator.spendable_inputs().await.to_vec())
            .spend_amount(tx_outputs.total_native_coins() + fee)
            .build();

        // build Tx details
        let tx_details = TransactionDetailsBuilder::new()
            .inputs(tx_inputs.into())
            .outputs(tx_outputs)
            .fee(fee)
            .build(&mut StateLock::from(gsl.clone()))
            .await
            .unwrap();

        // build proof-job-options, specify SingleProof
        let options = TritonVmProofJobOptionsBuilder::new()
            .template(&gsl.cli().as_proof_job_options())
            .proof_type(TransactionProofType::SingleProof)
            .build();

        // build the (mock) proof
        let tx_proof = TransactionProofBuilder::new()
            .transaction_details(&tx_details)
            .proof_job_options(options)
            .build()
            .await
            .unwrap();

        // build tx artifacts
        let tx_artifacts = tx_initiator
            .assemble_transaction_artifacts(tx_details, tx_proof)
            .unwrap();

        // record and broadcast tx
        tx_initiator
            .record_and_broadcast_transaction(&tx_artifacts)
            .await
            .unwrap();

        // mine a block to wallet, so the wallet obtains the utxos
        let mut regtest = gsl.api().regtest_mut();
        let digest = regtest
            .mine_block_to_wallet(Timestamp::now())
            .await
            .unwrap();

        // retrieve the newly mined block
        let block = gsl.lock_guard().await.chain.light_state().clone();
        assert_eq!(digest, block.hash());

        block
    }
}
