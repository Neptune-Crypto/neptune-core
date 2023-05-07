use anyhow::Result;
use neptune_core::config_models::data_directory::DataDirectory;
use neptune_core::config_models::network::Network;
use neptune_core::models::blockchain::address::generation_address;
use neptune_core::models::state::wallet::WalletSecret;

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::Main;

    // The root path is where both the wallet and all databases are stored
    let root_data_dir = DataDirectory::get(None, network)?;
    let root_data_dir_path = root_data_dir.database_dir_path();

    // Create root directory for databases and wallet if it does not already exist
    DataDirectory::create_dir_if_not_exists(&root_data_dir_path).unwrap();

    let wallet_file = root_data_dir.wallet_file_path();
    let wallet_secret = WalletSecret::read_from_file_or_create(&wallet_file).unwrap();

    println!("Wallet stored in: {}", wallet_file.display());
    // println!("Wallet public key: {}", wallet_secret.get_public_key());
    let spending_key = generation_address::SpendingKey::derive_from_seed(wallet_secret.secret_seed);
    println!(
        "Wallet receiver address: {}",
        generation_address::ReceivingAddress::from_spending_key(&spending_key)
            .to_bech32m(network)
            .unwrap()
    );

    Ok(())
}
