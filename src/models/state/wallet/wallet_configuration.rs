use std::path::PathBuf;

use tracing::info;

use crate::config_models::cli_args;
use crate::config_models::data_directory::DataDirectory;
use crate::config_models::network::Network;

use super::scan_mode_configuration::ScanModeConfiguration;
use super::wallet_file::WALLET_INCOMING_SECRETS_FILE_NAME;

/// Configuration options for [`WalletState`](super::wallet_state::WalletState).
///
/// These configurations are often downstream from CLI arguments. However,
/// exceptions to this rule exist. For instance: scan mode can be activated by
/// importing a wallet, even without CLI arguments.
#[derive(Debug, Clone)]
pub(crate) struct WalletConfiguration {
    /// Whether we are in scan mode and, if so, how many future keys to scan
    /// with and the range of block heights where the scanning step is done.
    pub(crate) scan_mode: Option<ScanModeConfiguration>,

    /// How many mutator set membership proofs to store per monitored UTXO.
    pub(crate) num_mps_per_utxo: usize,

    /// Where wallet files are stored
    wallet_files_directory: PathBuf,

    /// Where the wallet database is stored
    wallet_database_directory: PathBuf,

    /// Which network we are on
    network: Network,
}

impl WalletConfiguration {
    /// Constructor for [`WalletConfiguration`].
    ///
    /// Best used in combination with self-consuming constructor-helpers
    /// [`Self::absorb_options`] and [`Self::with_scan_mode_if_necessary`], in
    /// that order.
    pub(crate) fn new(data_dir: &DataDirectory) -> Self {
        Self {
            scan_mode: None,
            num_mps_per_utxo: 0,
            wallet_files_directory: data_dir.wallet_directory_path(),
            wallet_database_directory: data_dir.wallet_database_dir_path(),
            network: Network::Main,
        }
    }

    /// Self-consuming constructor-helper for [`WalletConfiguration`].
    ///
    /// Extract those configuration options from the CLI arguments that are
    /// relevant for wallet state management.
    pub(crate) fn absorb_options(mut self, cli_args: &cli_args::Args) -> Self {
        self.num_mps_per_utxo = cli_args.number_of_mps_per_utxo;

        self.scan_mode = match (&cli_args.scan_blocks, cli_args.scan_keys) {
            (None, None) => None,
            (None, Some(num_future_keys)) => {
                info!("Activating scan mode: CLI argument `--scan-keys`.");
                Some(ScanModeConfiguration::scan().for_many_future_keys(num_future_keys))
            }
            (Some(range), None) => {
                info!("Activating scan mode: CLI argument `--scan-blocks`.");
                Some(ScanModeConfiguration::scan().blocks(range.to_owned()))
            }
            (Some(range), Some(num_future_keys)) => {
                info!("Activating scan mode: CLI arguments `--scan-keys` and `--scan-blocks`.");
                Some(
                    ScanModeConfiguration::scan()
                        .blocks(range.to_owned())
                        .for_many_future_keys(num_future_keys),
                )
            }
        };

        self.network = cli_args.network;

        self
    }

    /// Self-consuming constructor-helper for [`WalletConfiguration`].
    ///
    /// If not already active, activate scan mode if necessary.
    ///
    /// Specifically, scan mode is activated with default parameters if (all
    /// of):
    ///  - it is not already active,
    ///  - the wallet file was present (it is not new), and
    ///  - the wallet database was absent (it is new).
    ///
    /// The latter two bullet points indicate that the wallet was imported,
    /// perhaps via the command line tool.
    pub(crate) fn with_scan_mode_if_necessary(
        mut self,
        wallet_was_new: bool,
        database_was_new: bool,
    ) -> Self {
        if self.scan_mode.is_none() && !wallet_was_new && database_was_new {
            info!(
                "Activating scan mode: wallet file present but \
            databse absent; wallet may have been imported."
            );
            self.scan_mode = Some(ScanModeConfiguration::default());
        }
        self
    }

    pub(crate) fn incoming_secrets_path(&self) -> PathBuf {
        self.wallet_files_directory_path()
            .join(WALLET_INCOMING_SECRETS_FILE_NAME)
    }

    pub(crate) fn wallet_files_directory_path(&self) -> PathBuf {
        self.wallet_files_directory.to_owned()
    }

    pub(crate) fn wallet_database_directory_path(&self) -> PathBuf {
        self.wallet_database_directory.to_owned()
    }

    pub(crate) fn network(&self) -> Network {
        self.network
    }
}

#[cfg(test)]
mod test {
    use crate::config_models::cli_args::Args;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::tests::shared::unit_test_data_directory;

    use super::*;
    #[test]
    fn scan_mode_is_off_by_default() {
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();
        let configuration = WalletConfiguration::new(&data_dir).absorb_options(&Args::default());
        assert!(configuration.scan_mode.is_none());
    }

    #[test]
    fn scan_mode_is_on_with_scan_blocks_or_scan_keys() {
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();

        let cli_args_1 = Args {
            scan_blocks: Some(0u64..=10),
            ..Default::default()
        };
        let configuration_1 = WalletConfiguration::new(&data_dir).absorb_options(&cli_args_1);
        assert!(configuration_1.scan_mode.is_some());

        let cli_args_2 = Args {
            scan_keys: Some(10),
            ..Default::default()
        };
        let configuration_2 = WalletConfiguration::new(&data_dir).absorb_options(&cli_args_2);
        assert!(configuration_2.scan_mode.is_some());

        let cli_args_3 = Args {
            scan_blocks: Some(0u64..=10),
            scan_keys: Some(10),
            ..Default::default()
        };
        let configuration_3 = WalletConfiguration::new(&data_dir).absorb_options(&cli_args_3);
        assert!(configuration_3.scan_mode.is_some());
    }

    #[test]
    fn scan_mode_is_on_if_wallet_was_imported() {
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();
        let cli_args = Args {
            scan_blocks: Some(0u64..=10),
            ..Default::default()
        };
        let configuration = WalletConfiguration::new(&data_dir)
            .absorb_options(&cli_args)
            .with_scan_mode_if_necessary(false, true);
        assert!(configuration.scan_mode.is_some());
    }

    #[test]
    fn num_future_keys_default_is_sane() {
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();

        // activate scan mode by setting --scan-blocks, so num future keys
        // will assume its default value
        let cli_args = Args {
            scan_blocks: Some(0u64..=10),
            ..Default::default()
        };
        let configuration = WalletConfiguration::new(&data_dir).absorb_options(&cli_args);

        let scan_mode = configuration.scan_mode.unwrap();
        assert!(scan_mode.num_future_keys() > 0);
        assert!(scan_mode.num_future_keys() < 10_000);
    }

    #[test]
    fn block_height_range_check_agrees_with_interval_membership() {
        let network = Network::Main;
        let data_dir = unit_test_data_directory(network).unwrap();

        let lower_bound = 10;
        let upper_bound = 20;

        // activate scan mode by setting --scan-blocks, so num future keys
        // will assume its default value
        let cli_args = Args {
            scan_blocks: Some(lower_bound..=upper_bound),
            ..Default::default()
        };
        let configuration = WalletConfiguration::new(&data_dir).absorb_options(&cli_args);
        let scan_mode = configuration.scan_mode.unwrap();

        for h in (lower_bound - 5)..(upper_bound + 5) {
            assert_eq!(
                (lower_bound..=upper_bound).contains(&h),
                scan_mode.block_height_is_in_range(BlockHeight::from(h)),
            );
        }
    }
}
