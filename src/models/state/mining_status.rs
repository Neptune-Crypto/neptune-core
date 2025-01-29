use std::fmt::Display;
use std::time::Duration;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::block::Block;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GuessingWorkInfo {
    work_start: SystemTime,
    num_inputs: usize,
    num_outputs: usize,
    total_coinbase: NativeCurrencyAmount,
    total_guesser_fee: NativeCurrencyAmount,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MiningStatus {
    Guessing(GuessingWorkInfo),
    Composing(ComposingWorkInfo),
    Inactive,
}

impl Display for MiningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let elapsed_time = match self {
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
        let input_output_info = match self {
            MiningStatus::Guessing(info) => {
                format!(" {}/{}", info.num_inputs, info.num_outputs)
            }
            _ => String::default(),
        };

        let work_type_and_duration = match self {
            MiningStatus::Guessing(_) => {
                format!("guessing for {} seconds", elapsed_time.unwrap().as_secs(),)
            }
            MiningStatus::Composing(_) => {
                format!("composing for {} seconds", elapsed_time.unwrap().as_secs())
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
