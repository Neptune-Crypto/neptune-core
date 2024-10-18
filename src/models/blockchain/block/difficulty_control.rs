use itertools::Itertools;
use num_bigint::BigUint;
use tasm_lib::{
    triton_vm::prelude::{BFieldElement, Digest},
    twenty_first::prelude::U32s,
};

use crate::models::{
    blockchain::block::block_header::{
        DIFFICULTY_NUM_LIMBS, MINIMUM_DIFFICULTY, TARGET_BLOCK_INTERVAL,
    },
    proof_abstractions::timestamp::Timestamp,
};

use super::block_height::BlockHeight;

/// Convert a difficulty to a target threshold so as to test a block's
/// proof-of-work.
pub(crate) fn target(difficulty: U32s<DIFFICULTY_NUM_LIMBS>) -> Digest {
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
/// This mechanism is a PID controller (with P = -2^-4 and I = D = 0) with
/// the following system diagram.
///
/// ```notest
///                          --------------
///                         |              |--- new timestamp ------
///  --- new difficulty --->|  blockchain  |--- old timestamp ----  |
/// |   (control signal)    |              |--- old difficulty -  | |
/// |                        --------------                     | | |
/// |   ---                                                     | | |
///  --| * |<---------------------------------------------------  | |
///     ---                                                     - v v
///      ^                                                        ---
///      |                                                       | + |
///     ---                                                       ---
///    | + |<--- 1.0                                    (process   |
///     ---                          (setpoint:)        variable:) |
///      ^                             target             observed |
///      |                              block           block time |
///      |                            interval                     v
///      |                               |                     -  ---
///      |                               |---------------------->| + |
///      |                   _           |   -----                ---
///      |                  / |          '->| ^-1 |------v         |
///      | adjustment      /  |              -----      ---  error |
///       ----------------(P* |<-----------------------| * |<------
///                        \  |                         ---
///                         \_|
///
/// ```
pub(crate) fn difficulty_control(
    new_timestamp: Timestamp,
    old_timestamp: Timestamp,
    old_difficulty: U32s<DIFFICULTY_NUM_LIMBS>,
    target_block_interval: Option<Timestamp>,
    previous_block_height: BlockHeight,
) -> U32s<DIFFICULTY_NUM_LIMBS> {
    // no adjustment if the previous block is the genesis block
    if previous_block_height.is_genesis() {
        return old_difficulty;
    }

    // otherwise, compute PID control signal

    // target; signal to follow
    let target_block_interval = target_block_interval.unwrap_or(TARGET_BLOCK_INTERVAL);

    // most recent observed block time
    let delta_t = new_timestamp - old_timestamp;

    // distance to target
    let error = (delta_t.0.value() as i64 - target_block_interval.0.value() as i64)
        * ((1i64 << 32) / (target_block_interval.0.value() as i64));

    // change to control signal
    // adjustment_factor = (1 + P * error)
    let adjustment_factor = (1i64 << 32) - (error >> 4);
    let adjustment_factor = U32s::<6>::new([
        adjustment_factor as u32,
        (adjustment_factor >> 32) as u32,
        0,
        0,
        0,
        0,
    ]);
    let old_difficulty = U32s::<6>::new(
        old_difficulty
            .as_ref()
            .iter()
            .copied()
            .chain([0])
            .collect_vec()
            .try_into()
            .unwrap(),
    );

    let new_difficulty = old_difficulty * adjustment_factor;
    let new_difficulty = U32s::<5>::new(
        new_difficulty
            .as_ref()
            .iter()
            .skip(1)
            .copied()
            .collect_vec()
            .try_into()
            .unwrap(),
    );

    if new_difficulty < MINIMUM_DIFFICULTY.into() {
        MINIMUM_DIFFICULTY.into()
    } else {
        new_difficulty
    }
}
