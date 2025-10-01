use std::fmt::Display;

use serde::Deserialize;
use serde::Serialize;

use crate::api::export::BlockHeight;
use crate::api::export::NativeCurrencyAmount;
use crate::api::export::Timestamp;

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum UtxoStatusEvent {
    Confirmed {
        block_height: BlockHeight,
        timestamp: Timestamp,
    },
    Pending,
    Expected,
    Abandoned,
    None,
}

impl Display for UtxoStatusEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            UtxoStatusEvent::Confirmed {
                block_height,
                timestamp,
            } => format!("{block_height}. {}", timestamp.standard_format()),
            UtxoStatusEvent::Pending => "pending".to_string(),
            UtxoStatusEvent::Expected => "expected".to_string(),
            UtxoStatusEvent::Abandoned => "abandoned".to_string(),
            UtxoStatusEvent::None => "-".to_string(),
        };
        f.write_str(&s)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct UiUtxo {
    pub received: UtxoStatusEvent,
    pub aocl_leaf_index: Option<u64>,
    pub spent: UtxoStatusEvent,
    pub amount: NativeCurrencyAmount,
    pub release_date: Option<Timestamp>,
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<UtxoStatusEvent> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> UtxoStatusEvent {
        let block_height = rng.random();
        let timestamp = rng.random();
        match rng.random_range(0..5) {
            0 => UtxoStatusEvent::Confirmed {
                block_height,
                timestamp,
            },
            1 => UtxoStatusEvent::Pending,
            2 => UtxoStatusEvent::Expected,
            3 => UtxoStatusEvent::Abandoned,
            4 => UtxoStatusEvent::None,
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<UiUtxo> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> UiUtxo {
        UiUtxo {
            received: rng.random(),
            spent: rng.random(),
            aocl_leaf_index: if rng.random_bool(0.5) {
                Some(rng.random_range(0u64..(u64::MAX >> 20)))
            } else {
                None
            },
            amount: rng.random(),
            release_date: if rng.random_bool(0.5) {
                Some(rng.random())
            } else {
                None
            },
        }
    }
}
