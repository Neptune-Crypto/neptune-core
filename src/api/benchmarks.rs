use std::env;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use rand::Rng;

use super::export::NativeCurrencyAmount;
use super::export::NeptuneProof;
use super::export::ReceivingAddress;
use super::export::Timestamp;
use super::export::Transaction;
use super::export::TransactionDetails;
use super::export::TransactionProof;
use super::export::TxOutputList;
use super::tx_initiation::send;
use crate::api::export::Network;
use crate::config_models::cli_args;
use crate::config_models::data_directory::DataDirectory;
use crate::models::blockchain::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use crate::models::blockchain::block::validity::block_proof_witness::BlockProofWitness;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockProof;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::state::wallet::transaction_output::TxOutput;
use crate::models::state::wallet::wallet_configuration::WalletConfiguration;
use crate::models::state::wallet::wallet_entropy::WalletEntropy;
use crate::models::state::wallet::wallet_state::WalletState;

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

/// Return a block with N incoming UTXOs to the provided address, sent from the
/// provided wallet.
pub async fn next_block_incoming_utxos(
    parent: &Block,
    recipient: ReceivingAddress,
    num_ouputs: usize,
    sender: &WalletState,
) -> Block {
    let timestamp = Timestamp::now();
    let one_nau = NativeCurrencyAmount::from_nau(1);
    let mut rng = rand::rng();
    let tx_outputs: TxOutputList =
        vec![
            TxOutput::onchain_native_currency(one_nau, rng.random(), recipient, false);
            num_ouputs
        ]
        .into();
    let fee = one_nau;
    let total_spend = tx_outputs.total_native_coins() + fee;
    let inputs = sender
        .allocate_sufficient_input_funds(
            total_spend,
            tip_digest,
            mutator_set_accumulator,
            timestamp,
        )
        .await
        .unwrap();
    // let tx_details = TransactionDetails::nop(
    //     parent.mutator_set_accumulator_after(),
    //     timestamp,
    //     Network::Main,
    // );
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
