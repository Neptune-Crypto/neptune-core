use std::fmt::Display;

use serde::Deserialize;
use serde::Serialize;

use crate::application::loops::sync_loop::sync_progress::SyncProgress;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Eq, PartialEq)]
#[cfg_attr(feature = "mock-rpc", derive(strum::EnumCount))]
pub enum SyncStatus {
    #[default]
    Unknown,
    Challenges(usize),
    Syncing(SyncProgress),
    Synced,
}

impl Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncStatus::Unknown => write!(f, "unknown"),
            SyncStatus::Challenges(number) => write!(f, "{number} open challenges"),
            SyncStatus::Syncing(status) => write!(f, "{status}"),
            SyncStatus::Synced => write!(f, "synced"),
        }
    }
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<SyncStatus> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> SyncStatus {
        match rng.random_range(0usize..<SyncStatus as strum::EnumCount>::COUNT) {
            0 => SyncStatus::Unknown,
            1 => SyncStatus::Challenges(rng.random_range(0..1000)),
            2 => SyncStatus::Syncing(rng.random()),
            3 => SyncStatus::Synced,
            _ => unreachable!(),
        }
    }
}
