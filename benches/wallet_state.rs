use std::env;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use divan::Bencher;
use neptune_cash::api::export::Network;
use neptune_cash::config_models::data_directory::DataDirectory;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;

fn main() {
    divan::main();
}

pub(crate) fn benchmark_data_directory(network: Network) -> Result<DataDirectory> {
    let mut rng = rand::rng();
    let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
    let tmp_root: PathBuf = env::temp_dir()
        .join(format!("neptune-benchmark-runs-{}", user))
        .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));

    DataDirectory::get(Some(tmp_root), network)
}

mod maintain_membership_proofs {
    use super::*;

    mod maintain_100_100_100 {
        use neptune_cash::api::export::NeptuneProof;
        use neptune_cash::api::export::Network;
        use neptune_cash::api::export::Timestamp;
        use neptune_cash::api::export::Transaction;
        use neptune_cash::api::export::TransactionDetails;
        use neptune_cash::api::export::TransactionProof;
        use neptune_cash::config_models::cli_args;
        use neptune_cash::config_models::data_directory::DataDirectory;
        use neptune_cash::models::blockchain::block::validity::block_primitive_witness::BlockPrimitiveWitness;
        use neptune_cash::models::blockchain::block::validity::block_proof_witness::BlockProofWitness;
        use neptune_cash::models::blockchain::block::Block;
        use neptune_cash::models::blockchain::block::BlockProof;
        use neptune_cash::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
        use neptune_cash::models::state::wallet::wallet_file::WalletFileContext;
        use neptune_cash::models::state::wallet::wallet_state::WalletState;

        use super::*;

        async fn wallet_state() -> WalletState {
            let data_directory = benchmark_data_directory(Network::Main).unwrap();
            DataDirectory::create_dir_if_not_exists(&data_directory.root_dir_path())
                .await
                .unwrap();

            let wallet_dir = data_directory.wallet_directory_path();
            DataDirectory::create_dir_if_not_exists(&wallet_dir)
                .await
                .unwrap();
            let wallet_file_context = WalletFileContext::read_from_file_or_create(
                &data_directory.wallet_directory_path(),
            )
            .unwrap();
            let cli_args = cli_args::Args::default();

            WalletState::try_new_from_context(&data_directory, wallet_file_context, &cli_args)
                .await
                .unwrap()
        }

        fn next_block(parent: &Block) -> Block {
            let timestamp = Timestamp::now();
            let tx_details = TransactionDetails::nop(
                parent.mutator_set_accumulator_after(),
                timestamp,
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

        fn update_impl(bencher: Bencher) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut wallet_state = rt.block_on(wallet_state());

            let genesis = Block::genesis(Network::Main);
            let block1 = next_block(&genesis);

            bencher.bench_local(|| {
                rt.block_on(async {
                    wallet_state
                        .update_wallet_state_with_new_block(
                            &genesis.mutator_set_accumulator_after(),
                            &block1,
                        )
                        .await
                        .unwrap()
                });
            });
        }

        #[divan::bench]
        fn apply_block1(bencher: Bencher) {
            update_impl(bencher);
        }
    }
}
