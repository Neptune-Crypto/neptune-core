use std::fmt::Display;
use std::time::Duration;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GuessingWorkInfo {
    work_start: SystemTime,
    num_inputs: usize,
    num_outputs: usize,
    total_coinbase: NativeCurrencyAmount,
    pub(crate) total_guesser_fee: NativeCurrencyAmount,
}

impl GuessingWorkInfo {
    pub(crate) fn new(work_start: SystemTime, block: &Block) -> Self {
        Self {
            work_start,
            num_inputs: block.body().transaction_kernel.inputs.len(),
            num_outputs: block.body().transaction_kernel.outputs.len(),
            total_coinbase: block.body().transaction_kernel.coinbase.unwrap_or_default(),
            total_guesser_fee: block.body().transaction_kernel.fee,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ComposingWorkInfo {
    // Only this info is available at the beginning of the composition work.
    // The rest of the information will have to be read from the log.
    work_start: SystemTime,
}

impl ComposingWorkInfo {
    pub(crate) fn new(work_start: SystemTime) -> Self {
        Self { work_start }
    }
}

#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
pub enum MiningStatus {
    Guessing(GuessingWorkInfo),
    Composing(ComposingWorkInfo),

    #[default]
    Inactive,
}

impl Display for MiningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let elapsed_time_exact = match self {
            MiningStatus::Guessing(guessing_work_info) => Some(
                guessing_work_info
                    .work_start
                    .elapsed()
                    .unwrap_or(Duration::ZERO),
            ),
            MiningStatus::Composing(composing_work_info) => Some(
                composing_work_info
                    .work_start
                    .elapsed()
                    .unwrap_or(Duration::ZERO),
            ),
            MiningStatus::Inactive => None,
        };
        // remove sub-second component, so humantime ends with seconds.
        let elapsed_time = elapsed_time_exact.map(|v| {
            v.checked_sub(Duration::from_nanos(v.subsec_nanos().into()))
                .unwrap()
        });
        let input_output_info = match self {
            MiningStatus::Guessing(info) => {
                format!(" {}/{}", info.num_inputs, info.num_outputs)
            }
            _ => String::default(),
        };

        let work_type_and_duration = match self {
            MiningStatus::Guessing(_) => {
                format!(
                    "guessing for {}",
                    humantime::format_duration(elapsed_time.unwrap())
                )
            }
            MiningStatus::Composing(_) => {
                format!(
                    "composing for {}",
                    humantime::format_duration(elapsed_time.unwrap())
                )
            }
            MiningStatus::Inactive => "inactive".to_owned(),
        };
        let reward = match self {
            MiningStatus::Guessing(block_work_info) => format!(
                "; total guesser reward: {}",
                block_work_info.total_guesser_fee
            ),
            _ => String::default(),
        };

        write!(f, "{work_type_and_duration}{input_output_info}{reward}",)
    }
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<MiningStatus> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> MiningStatus {
        let random_time = SystemTime::UNIX_EPOCH + Duration::from_millis(rng.next_u64() >> 20);
        match rng.random_range(0..3) {
            0 => MiningStatus::Inactive,
            1 => {
                let composing_work_info = ComposingWorkInfo {
                    work_start: random_time,
                };
                MiningStatus::Composing(composing_work_info)
            }
            2 => {
                let guessing_work_info = GuessingWorkInfo {
                    work_start: random_time,
                    num_inputs: rng.random_range(0..10000),
                    num_outputs: rng.random_range(0..10000),
                    total_coinbase: rng.random(),
                    total_guesser_fee: rng.random(),
                };
                MiningStatus::Guessing(guessing_work_info)
            }
            _ => unreachable!(),
        }
    }
}
