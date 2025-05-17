use std::env;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use divan::Bencher;
use neptune_cash::api::export::KeyType;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::NeptuneProof;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::ReceivingAddress;
use neptune_cash::api::export::Timestamp;
use neptune_cash::api::export::Transaction;
use neptune_cash::api::export::TransactionDetails;
use neptune_cash::api::export::TransactionProof;
use neptune_cash::api::export::TxInput;
use neptune_cash::config_models::cli_args;
use neptune_cash::config_models::data_directory::DataDirectory;
use neptune_cash::models::blockchain::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use neptune_cash::models::blockchain::block::validity::block_proof_witness::BlockProofWitness;
use neptune_cash::models::blockchain::block::Block;
use neptune_cash::models::blockchain::block::BlockProof;
use neptune_cash::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use neptune_cash::models::state::wallet::transaction_output::TxOutput;
use neptune_cash::models::state::wallet::wallet_configuration::WalletConfiguration;
use neptune_cash::models::state::wallet::wallet_entropy::WalletEntropy;
use neptune_cash::models::state::wallet::wallet_state::WalletState;
use num_traits::CheckedSub;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use rand::Rng;

fn main() {
    divan::main();
}

mod maintain_membership_proofs {
    use super::*;

    /// Maintain 100 membership proofs, while receiving an additional 100 UTXOs.
    mod maintain_100_100 {

        use super::*;
        use crate::helper::*;

        fn update_wallet_with_block2(bencher: Bencher) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut wallet_state = rt.block_on(devops_wallet_state_genesis(Network::Main));

            let genesis = Block::genesis(Network::Main);
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

mod helper {
    use super::*;

    fn benchmark_data_directory(network: Network) -> Result<DataDirectory> {
        let mut rng = rand::rng();
        let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
        let tmp_root: PathBuf = env::temp_dir()
            .join(format!("neptune-benchmark-runs-{}", user))
            .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));

        DataDirectory::get(Some(tmp_root), network)
    }

    pub async fn devops_wallet_state_genesis(network: Network) -> WalletState {
        let data_directory = benchmark_data_directory(network).unwrap();
        DataDirectory::create_dir_if_not_exists(&data_directory.root_dir_path())
            .await
            .unwrap();

        DataDirectory::create_dir_if_not_exists(&data_directory.wallet_directory_path())
            .await
            .unwrap();
        let cli_args = cli_args::Args::default();
        let configuration = WalletConfiguration::new(&data_directory).absorb_options(&cli_args);

        WalletState::try_new(configuration, WalletEntropy::devnet_wallet())
            .await
            .unwrap()
    }

    /// Sends the wallet's entire balance to the provided address. Divides the
    /// transaction up into `N` outputs, guaranteeing that the entire available
    /// balance is being spent.
    pub async fn next_block_incoming_utxos(
        parent: &Block,
        recipient: ReceivingAddress,
        num_outputs: usize,
        sender: &WalletState,
        timestamp: Timestamp,
    ) -> Block {
        let one_nau = NativeCurrencyAmount::from_nau(1);

        let fee = one_nau;

        // create N outputs of 1 nau each

        let mut outputs = vec![(recipient.clone(), one_nau); num_outputs - 1];

        // calc remaining amount and add it to outputs
        let intermediate_spend = outputs
            .iter()
            .map(|(_, amt)| *amt)
            .sum::<NativeCurrencyAmount>()
            + fee;

        let msa = parent.mutator_set_accumulator_after();
        let wallet_status = sender.get_wallet_status(parent.hash(), &msa).await;
        let change_amt = wallet_status
            .synced_unspent_available_amount(timestamp)
            .checked_sub(&intermediate_spend)
            .unwrap();

        outputs.push((recipient.clone(), change_amt));

        let mut input_funds: Vec<TxInput> = vec![];
        for input in sender.spendable_inputs(wallet_status, timestamp) {
            input_funds.push(input);
        }

        let mut rng = rand::rng();
        let outputs = outputs.into_iter().map(|(recipient, amount)| {
            TxOutput::onchain_native_currency_as_change(amount, rng.random(), recipient)
        });
        let tx_details = TransactionDetails::new_without_coinbase(
            input_funds,
            outputs,
            fee,
            timestamp,
            msa,
            Network::Main,
        );

        let kernel = PrimitiveWitness::from_transaction_details(&tx_details).kernel;

        let tx = Transaction {
            kernel,
            proof: TransactionProof::SingleProof(NeptuneProof::invalid()),
        };

        let block_primitive_witness = BlockPrimitiveWitness::new(parent.to_owned(), tx);
        let body = block_primitive_witness.body().to_owned();
        let header = block_primitive_witness.header(timestamp, None);
        let (appendix, proof) = {
            let block_proof_witness = BlockProofWitness::produce(block_primitive_witness);
            let appendix = block_proof_witness.appendix();
            (appendix, BlockProof::SingleProof(NeptuneProof::invalid()))
        };

        Block::new(header, body, appendix, proof)
    }
}
