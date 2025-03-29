use std::path::Path;
use std::path::PathBuf;

use neptune_cash::config_models::cli_args::Args;
use neptune_cash::config_models::data_directory::DataDirectory;
use neptune_cash::main_loop::MainLoopHandler;
use neptune_cash::tx_initiation::export::GlobalStateLock;
use neptune_cash::tx_initiation::export::Network;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use tokio::task::JoinHandle;

pub struct GenesisNode;

impl GenesisNode {
    /// Create a randomly named `DataDirectory` so filesystem-bound tests can run
    /// in parallel. If this is not done, parallel execution of unit tests will
    /// fail as they each hold a lock on the database.
    ///
    /// For now we use databases on disk. In-memory databases would be nicer.
    pub fn integration_test_data_directory(network: Network) -> anyhow::Result<DataDirectory> {
        let mut rng = rand::rng();
        let user = std::env::var("USER").unwrap_or_else(|_| "default".to_string());
        let tmp_root: PathBuf = std::env::temp_dir()
            .join(format!("neptune-integration-tests-{}", user))
            .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));

        DataDirectory::get(Some(tmp_root), network)
    }

    pub fn default_args() -> Args {
        let mut args = Args::default();

        if let Ok(dd) = Self::integration_test_data_directory(Network::Main) {
            args.data_dir = Some(dd.root_dir_path());
        }

        args
    }

    pub async fn start_node(
        args: Args,
    ) -> anyhow::Result<(GlobalStateLock, JoinHandle<anyhow::Result<i32>>)> {
        let mut main_loop_handler = neptune_cash::initialize(args).await?;
        let global_state_lock = main_loop_handler.global_state_lock();

        let jh = tokio::task::spawn(use_main_loop_handler(main_loop_handler));

        Ok((global_state_lock, jh))
    }
}

// async fn use_main_loop_handler(h: MainLoopHandler) -> anyhow::Result<i32> where MainLoopHandler: Send {
//     println!("{:?}", h);
//     Ok(5)
// }

async fn use_main_loop_handler(mut h: MainLoopHandler) -> anyhow::Result<i32>
where
    MainLoopHandler: Send,
{
    h.run().await
}
