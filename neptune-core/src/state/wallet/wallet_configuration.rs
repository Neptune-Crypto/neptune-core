use std::path::PathBuf;

use tracing::info;

use super::scan_mode_configuration::ScanModeConfiguration;
use super::wallet_file::WALLET_INCOMING_SECRETS_FILE_NAME;
use crate::application::config::cli_args;
use crate::application::config::data_directory::DataDirectory;
use crate::application::config::network::Network;

/// Configuration options for [`WalletState`](super::wallet_state::WalletState).
///
/// These configurations are often downstream from CLI arguments. However,
/// exceptions to this rule exist. For instance: scan mode can be activated by
/// importing a wallet, even without CLI arguments.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WalletConfiguration {
    /// Whether we are in scan mode and, if so, how many future keys to scan
    /// with and the range of block heights where the scanning step is done.
    pub(crate) scan_mode: Option<ScanModeConfiguration>,

    /// How many mutator set membership proofs to store per monitored UTXO.
    pub(crate) num_mps_per_utxo: usize,

    /// data directory configs for neptune-core
    data_directory: DataDirectory,

    /// Which network we are on
    network: Network,
}

impl WalletConfiguration {
    /// Constructor for [`WalletConfiguration`].
    ///
    /// Best used in combination with self-consuming constructor-helper
    /// [`Self::absorb_options`].
    pub(crate) fn new(data_dir: &DataDirectory) -> Self {
        Self {
            scan_mode: None,
            num_mps_per_utxo: 0,
            data_directory: data_dir.clone(),
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
            (None, None) => self.scan_mode,
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

        if cli_args.compose {
            if let Some(scan_mode_configuration) = self.scan_mode.as_mut() {
                scan_mode_configuration.set_guesser_fraction(cli_args.guesser_fraction);
            };
        }

        self.network = cli_args.network;

        self
    }

    /// Activate scan mode with default parameters, if not active already.
    pub(crate) fn enable_scan_mode(&mut self) {
        if self.scan_mode.is_none() {
            info!("Activating scan mode with default configurations.");
            self.scan_mode = Some(ScanModeConfiguration::default());
        }
    }

    pub(crate) fn incoming_secrets_path(&self) -> PathBuf {
        self.data_directory()
            .wallet_directory_path()
            .join(WALLET_INCOMING_SECRETS_FILE_NAME)
    }

    pub(crate) fn network(&self) -> Network {
        self.network
    }

    /// get the data directory
    pub(crate) fn data_directory(&self) -> &DataDirectory {
        &self.data_directory
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    use super::*;
    use crate::application::config::cli_args::Args;
    use crate::protocol::consensus::block::block_height::BlockHeight;
    use crate::tests::shared::files::unit_test_data_directory;
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
