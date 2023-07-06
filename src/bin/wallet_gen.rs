use anyhow::Result;
use neptune_core::config_models::data_directory::DataDirectory;
use neptune_core::config_models::network::Network;
use neptune_core::models::state::wallet::WalletSecret;

#[tokio::main]
async fn main() -> Result<()> {
    let network = Network::Main;

    // The root path is where both the wallet and all databases are stored
    let data_dir = DataDirectory::get(None, network)?;

    // Get wallet object, create various wallet secret files
    let wallet_dir = data_dir.wallet_directory_path();
    DataDirectory::create_dir_if_not_exists(&wallet_dir)?;

    let wallet_dir = data_dir.wallet_directory_path();
    let (wallet_secret, secret_file_paths) =
        WalletSecret::read_from_file_or_create(&wallet_dir).unwrap();

    println!(
        "Wallet stored in: {}\nMake sure you also see this path if you run the neptune-core client",
        secret_file_paths.wallet_secret_path.display()
    );
    let spending_key = wallet_secret.nth_generation_spending_key(0);
    let receiver_address = spending_key.to_address();
    println!(
        "Wallet receiver address: {}",
        receiver_address.to_bech32m(network).unwrap()
    );

    Ok(())
}
