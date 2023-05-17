use anyhow::Result;
use neptune_core::config_models::data_directory::DataDirectory;
use neptune_core::config_models::network::Network;
use neptune_core::models::state::wallet::WalletSecret;

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::Main;

    // The root path is where both the wallet and all databases are stored
    let root_data_dir = DataDirectory::get(None, network)?;
    let root_data_dir_path = root_data_dir.database_dir_path();

    // Create root directory for databases and wallet if it does not already exist
    DataDirectory::create_dir_if_not_exists(&root_data_dir_path).unwrap();

    let wallet_file = root_data_dir.wallet_director_path();
    let wallet_secret = WalletSecret::read_from_file_or_create(&wallet_file).unwrap();

    println!("Wallet stored in: {}", wallet_file.display());
    let spending_key = wallet_secret.nth_generation_spending_key(0);
    let receiver_address = spending_key.to_address();
    println!(
        "Wallet receiver address: {}",
        receiver_address.to_bech32m(network).unwrap()
    );

    Ok(())
}
