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
/// This mechanism is a PID controller (with I=D=0) with the following
/// system diagram.
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
///      |                            interval                     v
///      |                               |                     -  ---
///      |                                ---------------------->| + |
///      |                   _                                    ---
///      |                  / |                                    |
///      | adjustment      /  |                              error |
///       ----------------(* P|------------------------------------
///                        \  |
///                         \_|
/// ```
pub(crate) fn difficulty_control(
    new_timestamp: Timestamp,
    old_timestamp: Timestamp,
    old_difficulty: U32s<TARGET_DIFFICULTY_U32_SIZE>,
    target_block_interval: Option<Timestamp>,
    previous_block_height: BlockHeight,
) -> U32s<TARGET_DIFFICULTY_U32_SIZE> {
    // no adjustment if the previous block is the genesis block
    if previous_block_height.is_genesis() {
        return old_difficulty;
    }

    // otherwise, compute PID control signal
    const ONE_OVER_P: i64 = -100;

    // target; signal to follow
    let target_block_interval = target_block_interval.unwrap_or(TARGET_BLOCK_INTERVAL);

    // most recent observed block time
    let delta_t = new_timestamp - old_timestamp;

    // distance to target
    let error = delta_t.0.value() as i64 - target_block_interval.0.value() as i64;

    // change to control signal
    let adjustment = error / ONE_OVER_P;

    // make adjustment work for u160s
    let absolute_adjustment = abs(adjustment) as u64;
    let adjustment_is_positive = adjustment >= 0;
    let adj_hi = (absolute_adjustment >> 32) as u32;
    let adj_lo = absolute_adjustment as u32;
    let absolute_adjustment_u32s =
        U32s::<TARGET_DIFFICULTY_U32_SIZE>::new([adj_lo, adj_hi, 0u32, 0u32, 0u32]);

    if adjustment_is_positive {
        old_difficulty + absolute_adjustment_u32s
    } else if absolute_adjustment_u32s > old_difficulty - MINIMUM_DIFFICULTY.into() {
        MINIMUM_DIFFICULTY.into()
    } else {
        old_difficulty - absolute_adjustment_u32s
    }
}
