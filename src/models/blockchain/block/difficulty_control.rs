use std::fmt::Display;

use get_size::GetSize;
use num_bigint::BigUint;
use num_traits::abs;
use rand::{distributions::Standard, prelude::Distribution};
use serde::{Deserialize, Serialize};
use tasm_lib::{
    triton_vm::prelude::{BFieldCodec, BFieldElement, Digest},
    twenty_first::prelude::U32s,
};

use crate::models::{
    blockchain::block::block_header::{
        MINIMUM_DIFFICULTY, TARGET_BLOCK_INTERVAL, TARGET_DIFFICULTY_U32_SIZE,
    },
    proof_abstractions::timestamp::Timestamp,
};

use super::block_height::BlockHeight;

/// Signals for PID controller.
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize, Default,
)]
pub struct ControlSignals {
    pub(crate) integral: u64,
    pub(crate) error: u64,
}

impl ControlSignals {
    pub fn new(integral: u64, error: u64) -> Self {
        Self { integral, error }
    }
}

impl Distribution<ControlSignals> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> ControlSignals {
        ControlSignals {
            integral: rng.gen(),
            error: rng.gen(),
        }
    }
}

impl Display for ControlSignals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ControlSignals {{ integral : {}, error: {} }}",
            self.integral, self.error
        )
    }
}

/// Convert a difficulty to a target threshold so as to test whether a block
/// has proof-of-work.
pub(crate) fn target(difficulty: U32s<TARGET_DIFFICULTY_U32_SIZE>) -> Digest {
    let difficulty_as_bui: BigUint = difficulty.into();
    let max_threshold_as_bui: BigUint =
        Digest([BFieldElement::new(BFieldElement::MAX); Digest::LEN]).into();
    let threshold_as_bui: BigUint = max_threshold_as_bui / difficulty_as_bui;

    threshold_as_bui.try_into().unwrap()
}

/// Control system for block difficulty.
///
/// This function computes the new block's difficulty from the block's
/// timestamp, the previous block's difficulty, and the previous block's
/// timestamp. It regulates the block interval by tuning the difficulty.
/// It assumes that the block timestamp is valid.
///
/// This mechanism is a PID controller with the following system diagram.
///
/// ```notest
///                          --------------
///                         |              |--- new timestamp ------
///  --- new difficulty --->|  blockchain  |--- old timestamp ----  |
/// |   (control signal)    |              |--- old difficulty -  | |
/// |                        --------------                     | | |
/// |   ---                                                     | | |
///  --| + |<---------------------------------------------------  | |
///     ---                                                       v v -
///      ^                                                        ---
///      |                                                       | + |
///      |                                                        ---
///      |                                              (process   |
///      |                           (setpoint:)        variable:) |
///      |                             target             observed |
///      |                              block           block time |
///      | adjustment                 interval                     v
///      |                               |                     -  ---
///      |                                ---------------------->| + |
///      |                                                        ---
///      |                                                         |
///     ---                                                  error |
///    | + |<----(*KP)---------------------------------------------|
///     ---                                                        |
///     -^-                -----------                             |
///    | + |<----(*KI)----| integrate |<---------------------------|
///     ---                -----------                             |
///      ^                 --------                                |
///      '-------(*KD)----| derive |<------------------------------
///                        --------
/// ```
pub(crate) fn difficulty_control(
    new_timestamp: Timestamp,
    old_timestamp: Timestamp,
    old_difficulty: U32s<TARGET_DIFFICULTY_U32_SIZE>,
    old_control_signals: ControlSignals,
    target_block_interval: Option<Timestamp>,
    previous_block_height: BlockHeight,
) -> (U32s<TARGET_DIFFICULTY_U32_SIZE>, ControlSignals) {
    // no adjustment if the previous block is the genesis block
    if previous_block_height.is_genesis() {
        return (old_difficulty, ControlSignals::default());
    }

    // otherwise, compute PID control signal
    const ONE_OVER_KP: i64 = -100;
    const ONE_OVER_KI: i64 = -10000;
    const ONE_OVER_KD: i64 = -1000;

    // target; signal to follow
    let target_block_interval = target_block_interval.unwrap_or(TARGET_BLOCK_INTERVAL);

    // most recent observed block time
    let delta_t = new_timestamp - old_timestamp;

    // distance to target
    let error = delta_t.0.value() as i64 - target_block_interval.0.value() as i64;

    let old_error = old_control_signals.error as i64;
    let derivative = error - old_error;

    let old_integral = old_control_signals.integral as i64;
    let integral = old_integral + error;

    let new_control_signals = ControlSignals::new(integral as u64, error as u64);

    // change to control signal
    let proportional_contribution = error / ONE_OVER_KP;
    let integral_contribution = integral / ONE_OVER_KI;
    let differential_contribution = derivative / ONE_OVER_KD;
    let adjustment = proportional_contribution + integral_contribution + differential_contribution;

    // make adjustment work for u160s
    let absolute_adjustment = abs(adjustment) as u64;
    let adjustment_is_positive = adjustment >= 0;
    let adj_hi = (absolute_adjustment >> 32) as u32;
    let adj_lo = absolute_adjustment as u32;
    let absolute_adjustment_u32s =
        U32s::<TARGET_DIFFICULTY_U32_SIZE>::new([adj_lo, adj_hi, 0u32, 0u32, 0u32]);

    if adjustment_is_positive {
        (
            old_difficulty + absolute_adjustment_u32s,
            new_control_signals,
        )
    } else if absolute_adjustment_u32s > old_difficulty - MINIMUM_DIFFICULTY.into() {
        (MINIMUM_DIFFICULTY.into(), new_control_signals)
    } else {
        (
            old_difficulty - absolute_adjustment_u32s,
            new_control_signals,
        )
    }
}
