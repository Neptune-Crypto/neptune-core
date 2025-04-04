use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use neptune_cash::api::export::GlobalStateLock;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::TransactionKernelId;
use neptune_cash::config_models::cli_args::Args;
use neptune_cash::config_models::data_directory::DataDirectory;
use neptune_cash::models::blockchain::block::block_height::BlockHeight;
use neptune_cash::models::proof_abstractions::timestamp::Timestamp;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use tokio::task::JoinHandle;

pub struct GenesisNode {
    pub gsl: GlobalStateLock,

    // may be useful for future tests.
    #[allow(dead_code)]
    pub main_loop_join_handle: JoinHandle<anyhow::Result<i32>>,
}

// has methods that may be useful for future tests
#[allow(dead_code)]
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

    /// provides default neptune-core cli arguments for typical integration tests.
    ///
    /// if starting multiple nodes, each should use a unique instance parameter
    /// in order to prevent port conflicts.
    #[track_caller]
    pub fn default_args(node_instance: u8) -> Args {
        let mut args = Args::default();

        args.network = Network::RegTest;

        if let Ok(dd) = Self::integration_test_data_directory(Network::Main) {
            args.data_dir = Some(dd.root_dir_path());
        }

        let caller = core::panic::Location::caller();
        args.rpc_port =
            Self::hash_string_to_port_range(&format!("rpc:{}{}", caller, node_instance));
        args.peer_port =
            Self::hash_string_to_port_range(&format!("peer:{}{}", caller, node_instance));

        args
    }

    #[track_caller]
    pub fn cluster_id() -> String {
        core::panic::Location::caller().to_string()
    }

    /// provides cli args for each node in a cluster to connect with eachother
    ///
    /// cluster_id must be unique for the process in order to avoid port conflicts.
    ///
    /// each node will have --peers arguments for every other node.
    ///
    /// the first node will have rpc port and peer_port based on a hash of cluster_id
    /// each in the range of 1024..65000.
    ///
    /// subsequent nodes increment the rpc-port and peer-port from previous node by 1.
    pub fn default_args_for_cluster(cluster_id: &str, num_nodes: u8) -> Vec<Args> {
        let mut all_args = vec![];
        let mut base_args = Self::default_args(0);

        // fix ports based on the cluster_id
        base_args.rpc_port = Self::hash_string_to_port_range(&format!("rpc:{}{}", cluster_id, 0));
        base_args.peer_port = Self::hash_string_to_port_range(&format!("peer:{}{}", cluster_id, 0));

        let peers: Vec<_> = (0..u16::from(num_nodes))
            .map(|v| {
                SocketAddr::from_str(&format!("127.0.0.1:{}", base_args.peer_port + v)).unwrap()
            })
            .collect();

        for i in 0..num_nodes {
            let mut args = Self::default_args(i);
            args.peers = peers
                .clone()
                .into_iter()
                .enumerate()
                .filter(|(x, _)| *x != usize::from(i))
                .map(|(_, s)| s)
                .collect();
            args.peer_port = base_args.peer_port + u16::from(i);
            args.rpc_port = base_args.rpc_port + u16::from(i);
            all_args.push(args)
        }
        tracing::debug!("all_args: {:#?}", all_args);
        all_args
    }

    /// starts specified number of nodes running in a cluster with default args
    ///
    /// caller should obtain cluster_id via `cluster_id()` method.
    ///
    /// node arguments are generated with `default_args_for_cluster()`.
    pub async fn start_cluster<const N: usize>(
        cluster_id: &str,
        num_nodes: u8,
    ) -> anyhow::Result<[Self; N]> {
        Self::start_nodes(Self::default_args_for_cluster(cluster_id, num_nodes)).await
    }

    /// starts nodes running in a cluster with default args and waits until all connected
    ///
    /// caller should obtain cluster_id via `cluster_id()` method.
    ///
    /// node arguments are generated with `default_args_for_cluster()`.
    pub async fn start_connected_cluster<const N: usize>(
        cluster_id: &str,
        num_nodes: u8,
        timeout_secs: u16,
    ) -> anyhow::Result<[Self; N]> {
        let cluster =
            Self::start_nodes(Self::default_args_for_cluster(cluster_id, num_nodes)).await?;
        Self::wait_until_all_peers_connected(&cluster, timeout_secs).await?;
        Ok(cluster)
    }

    /// starts a node for each provided args
    pub async fn start_nodes<const N: usize>(args: Vec<Args>) -> anyhow::Result<[Self; N]> {
        let mut nodes = vec![];
        for node_args in args {
            nodes.push(Self::start_node(node_args).await?);
        }

        // Convert Vec to Array
        nodes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Incorrect number of nodes started"))
    }

    /// starts a fully functional node running.
    ///
    /// note: no dummy components are used.
    pub async fn start_node(args: Args) -> anyhow::Result<Self> {
        let mut main_loop_handler = neptune_cash::initialize(args).await?;
        let gsl = main_loop_handler.global_state_lock();

        let main_loop_join_handle =
            tokio::task::spawn(async move { main_loop_handler.run().await });

        Ok(Self {
            gsl,
            main_loop_join_handle,
        })
    }

    /// starts a fully functional node running with default args
    ///
    /// note: no dummy components are used.
    pub async fn start_default_node() -> anyhow::Result<Self> {
        Self::start_node(Self::default_args(0)).await
    }

    /// waits until node has a peer connected or timeout occurs.
    pub async fn wait_until_one_peer_connected(&self, timeout_secs: u16) -> anyhow::Result<()> {
        self.wait_until_peers_connected(1, timeout_secs).await
    }

    /// waits until node has at least n peers connected or timeout occurs.
    pub async fn wait_until_peers_connected(
        &self,
        min_num_peers: u8,
        timeout_secs: u16,
    ) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        while self.gsl.lock_guard().await.net.peer_map.len() < min_num_peers.into() {
            if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
                anyhow::bail!(
                    "connection(s) not established after {} seconds",
                    timeout_secs
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// waits until all nodes in a cluster are connected to eachother or timeout occurs.
    pub async fn wait_until_all_peers_connected(
        nodes: &[GenesisNode],
        timeout_secs: u16,
    ) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        let mut connected_nodes_count = 0;

        while connected_nodes_count < nodes.len() {
            if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
                anyhow::bail!("connections not established after {} seconds", timeout_secs);
            }

            // note: it *should* be equivalent to only check a single peer

            connected_nodes_count = 0; // reset to 0 each iteration
            for node in nodes {
                if node.gsl.lock_guard().await.net.peer_map.len() == nodes.len() - 1 {
                    connected_nodes_count += 1;
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// wait until specified transaction is in the mempool or timeout occurs.
    ///
    /// when a transaction is accepted by neptune-core it may take a short
    /// time until it actually appears in the mempool.  This method
    /// waits for it.
    pub async fn wait_until_tx_in_mempool(
        &self,
        txid: TransactionKernelId,
        timeout_secs: u16,
    ) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        while self.gsl.lock_guard().await.mempool.get(txid).is_none() {
            if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
                anyhow::bail!("tx not in mempool after {} seconds", timeout_secs);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// wait until wallet unconfirmed balance does not match confirmed balance
    ///
    /// when a transaction is accepted by neptune-core it may take a short
    /// time until it actually appears in the mempool.  This method waits for
    /// an uncomfirmed balance discrepancy, a proxy indicator of arriving funds.
    pub async fn wait_until_unconfirmed_balance(&self, timeout_secs: u16) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        loop {
            let balances = self.gsl.api().wallet().balances(Timestamp::now()).await;
            if balances.confirmed_total != balances.unconfirmed_total {
                break;
            }

            if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
                anyhow::bail!(
                    "confirmed and unconfirmed balance still match after {} seconds",
                    timeout_secs
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// wait until wallet unconfirmed balance matches confirmed balance
    ///
    /// when a block is mined with funds destined for our wallet
    /// those unconfirmed funds become comfirmed.  This method provides
    /// a proxy indicator that this has happened.
    pub async fn wait_until_confirmed_balance(&self, timeout_secs: u16) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        loop {
            let balances = self.gsl.api().wallet().balances(Timestamp::now()).await;
            if balances.confirmed_total == balances.unconfirmed_total {
                break;
            }

            if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
                anyhow::bail!(
                    "confirmed and unconfirmed balance still match after {} seconds",
                    timeout_secs
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// waits until a given block height is reached in canonical chain
    pub async fn wait_until_block_height(
        &self,
        height: impl Into<BlockHeight>,
        timeout_secs: u16,
    ) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        let h: BlockHeight = height.into();
        while self
            .gsl
            .lock_guard()
            .await
            .chain
            .light_state()
            .header()
            .height
            < h
        {
            if start.elapsed() > std::time::Duration::from_secs(timeout_secs.into()) {
                anyhow::bail!(
                    "block height {} not reached after {} seconds",
                    h,
                    timeout_secs
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn hash_string_to_port_range(input: &str) -> u16 {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        let hash_value = hasher.finish();

        let min: u64 = 1024;
        let max: u64 = 65000;
        let range_size: u64 = max - min + 1;

        // Scale the hash_value to the size of range_size.
        let scaled_hash = hash_value % range_size;

        // Shift the scaled value to the minimum of the range.
        (scaled_hash + min) as u16
    }
}
