use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;

use crate::api::export::BlockHeight;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::TxProvingCapability;
use crate::application::network::overview::NetworkOverview;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::state::mining::mining_status::MiningStatus;
use crate::state::sync_status::SyncStatus;

/// Dashboard overview data from client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverviewData {
    pub tip_digest: Digest,
    pub tip_header: BlockHeader,
    pub sync_status: SyncStatus,
    pub confirmed_available_balance: NativeCurrencyAmount,
    pub confirmed_total_balance: NativeCurrencyAmount,
    pub unconfirmed_available_balance: NativeCurrencyAmount,
    pub unconfirmed_total_balance: NativeCurrencyAmount,
    pub mempool_size: usize,
    pub mempool_total_tx_count: usize,
    pub mempool_own_tx_count: usize,

    // `None` signifies failure to get network overview
    pub network_overview: Option<NetworkOverview>,
    pub peer_count: usize,

    // `None` symbolizes failure to get mining status
    pub mining_status: Option<MiningStatus>,

    pub proving_capability: TxProvingCapability,

    // # of confirmations of the last wallet balance change.
    //
    // Starts at 1, as the block in which a tx is included is considered the 1st
    // confirmation.
    //
    // `None` indicates that wallet balance has never changed.
    pub confirmations: Option<BlockHeight>,

    /// CPU temperature in degrees Celsius
    pub cpu_temp: Option<f32>,
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<OverviewData> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> OverviewData {
        fn random_option<D, R: rand::Rng + ?Sized>(rng: &mut R) -> Option<D>
        where
            rand::distr::StandardUniform: rand::distr::Distribution<D>,
        {
            if rng.random_bool(0.5) {
                Some(rng.random())
            } else {
                None
            }
        }

        OverviewData {
            tip_digest: rng.random(),
            tip_header: rng.random(),
            sync_status: rng.random(),
            confirmed_available_balance: rng.random(),
            confirmed_total_balance: rng.random(),
            unconfirmed_available_balance: rng.random(),
            unconfirmed_total_balance: rng.random(),
            mempool_size: rng.random_range(0..1000),
            mempool_total_tx_count: rng.random_range(0..1000),
            mempool_own_tx_count: rng.random_range(0..1000),
            network_overview: random_option(rng),
            peer_count: rng.random_range(0..10),
            mining_status: random_option(rng),
            proving_capability: rng.random(),
            confirmations: random_option(rng),
            cpu_temp: if rng.random_bool(0.5) {
                Some(rng.random_range(-10.0_f32..110.0))
            } else {
                None
            },
        }
    }
}
