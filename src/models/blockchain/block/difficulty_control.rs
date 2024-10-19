use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;

use get_size::GetSize;
use num_bigint::BigUint;
use num_traits::Zero;
use rand::Rng;
use rand_distr::Distribution;
use rand_distr::Standard;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Digest;

use crate::models::blockchain::block::block_header::TARGET_BLOCK_INTERVAL;
use crate::models::proof_abstractions::timestamp::Timestamp;

use super::block_height::BlockHeight;

const DIFFICULTY_NUM_LIMBS: usize = 5;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize)]
pub struct Difficulty([u32; DIFFICULTY_NUM_LIMBS]);

impl Difficulty {
    pub const NUM_LIMBS: usize = DIFFICULTY_NUM_LIMBS;
    pub const MINIMUM: Self = Self::new([1000, 0, 0, 0, 0]);
    pub(crate) const fn new(difficulty: [u32; DIFFICULTY_NUM_LIMBS]) -> Self {
        Self(difficulty)
    }

    /// Convert a difficulty to a target threshold so as to test a block's
    /// proof-of-work.
    pub(crate) fn target(&self) -> Digest {
        let difficulty_as_bui: BigUint = BigUint::from(*self);
        let max_threshold_as_bui: BigUint =
            Digest([BFieldElement::new(BFieldElement::MAX); Digest::LEN]).into();
        let threshold_as_bui: BigUint = max_threshold_as_bui / difficulty_as_bui;

        threshold_as_bui.try_into().unwrap()
    }
}

impl IntoIterator for Difficulty {
    type Item = u32;
    type IntoIter = std::array::IntoIter<Self::Item, { Self::NUM_LIMBS }>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<Difficulty> for BigUint {
    fn from(value: Difficulty) -> Self {
        let mut bi = BigUint::zero();
        for &limb in value.0.iter().rev() {
            bi = (bi << 32) + limb;
        }
        bi
    }
}

impl PartialOrd for Difficulty {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Difficulty {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .into_iter()
            .rev()
            .zip(other.0.into_iter().rev())
            .map(|(lhs, rhs)| lhs.cmp(&rhs))
            .fold(Ordering::Equal, |acc, new| match acc {
                Ordering::Less => acc,
                Ordering::Equal => new,
                Ordering::Greater => acc,
            })
    }
}

impl Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BigUint::from(*self))
    }
}

impl Distribution<Difficulty> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Difficulty {
        Difficulty(rng.gen::<[u32; Difficulty::NUM_LIMBS]>())
    }
}

impl<T> From<T> for Difficulty
where
    T: Into<u32>,
{
    fn from(value: T) -> Self {
        let mut array = [0u32; Self::NUM_LIMBS];
        array[0] = value.into();
        Self(array)
    }
}

const POW_NUM_LIMBS: usize = 6;

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize)]
pub struct ProofOfWork([u32; POW_NUM_LIMBS]);

impl ProofOfWork {
    pub(crate) const NUM_LIMBS: usize = POW_NUM_LIMBS;
    pub(crate) const fn new(amount: [u32; Self::NUM_LIMBS]) -> Self {
        Self(amount)
    }
}

impl IntoIterator for ProofOfWork {
    type Item = u32;
    type IntoIter = std::array::IntoIter<Self::Item, { Self::NUM_LIMBS }>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> Add<T> for ProofOfWork
where
    T: IntoIterator<Item = u32>,
{
    type Output = ProofOfWork;

    fn add(self, rhs: T) -> Self::Output {
        let mut result = [0u32; Self::NUM_LIMBS];
        let mut carry = 0u32;
        let mut n = 0;
        for (i, (difficulty_digit, pow_digit)) in
            rhs.into_iter().zip(self.0.into_iter()).enumerate()
        {
            let sum = (carry as u64) + (difficulty_digit as u64) + (pow_digit as u64);
            result[i] = sum as u32;
            carry = (sum >> 32) as u32;
            n += 1;
        }
        for (self_i, result_i) in self.into_iter().zip(result.iter_mut()).skip(n) {
            let sum = (carry as u64) + (self_i as u64);
            *result_i = sum as u32;
            carry = (sum >> 32) as u32;
        }
        Self(result)
    }
}

impl Zero for ProofOfWork {
    fn zero() -> Self {
        Self::new([0u32; Self::NUM_LIMBS])
    }

    fn is_zero(&self) -> bool {
        *self == Self::zero()
    }
}

impl From<ProofOfWork> for BigUint {
    fn from(value: ProofOfWork) -> Self {
        let mut bi = BigUint::zero();
        for &limb in value.0.iter().rev() {
            bi = (bi << 32) + limb;
        }
        bi
    }
}

impl PartialOrd for ProofOfWork {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProofOfWork {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .into_iter()
            .rev()
            .zip(other.0.into_iter().rev())
            .map(|(lhs, rhs)| lhs.cmp(&rhs))
            .fold(Ordering::Equal, |acc, new| match acc {
                Ordering::Less => acc,
                Ordering::Equal => new,
                Ordering::Greater => acc,
            })
    }
}

impl Display for ProofOfWork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BigUint::from(*self))
    }
}

impl Distribution<ProofOfWork> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ProofOfWork {
        ProofOfWork(rng.gen::<[u32; ProofOfWork::NUM_LIMBS]>())
    }
}

/// Control system for block difficulty.
///
/// This function computes the new block's difficulty from the block's
/// timestamp, the previous block's difficulty, and the previous block's
/// timestamp. It regulates the block interval by tuning the difficulty.
/// It assumes that the block timestamp is valid.
///
/// This mechanism is a PID controller with P = -2^-4 (and I = D = 0) and with
/// the relative error being clamped within [-1;4]. The following diagram
/// describes the mechanism.
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
///     ---                              (setpoint:)    variable:) |
///      ^                                 target         observed |
///      |                                  block       block time |
///      |                                interval                 v
///      |                                   |                 -  ---
///      |                                   |------------------>| + |
///      |                                   |                    ---
///      |                                   |                     |
///      |                                   v                     |
///      |                                 -----                   |
///      |                                | 1/x |                  |
///      |      _                          -----                   |
///      |     / |                           v                     |
///      |    /  |    ---------------       ---     absolute error |
///       ---(P* |<--| clamp [-1; 4] |<----| * |<------------------
///           \  |    ---------------  rel. ---
///            \_|                    error
///``
/// The P-controller (without clamping) does have a systematic error up to -5%
/// of the setpoint, whose exact magnitude depends on the relation between
/// proving and guessing time. This bias could be eliminated in principle by
/// setting I and D; but the resulting controller is more complex (=> difficult
/// to implement), generates overshoot (=> bad for liveness), and periodicity
/// (=> attack vector). Most importantly, the bias is counteracted to some
/// degree by the clamping.
/// ```
pub(crate) fn difficulty_control(
    new_timestamp: Timestamp,
    old_timestamp: Timestamp,
    old_difficulty: Difficulty,
    target_block_interval: Option<Timestamp>,
    previous_block_height: BlockHeight,
) -> Difficulty {
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
    let absolute_error = (delta_t.0.value() as i64) - (target_block_interval.0.value() as i64);
    let relative_error = absolute_error * ((1i64 << 32) / (target_block_interval.0.value() as i64));
    let clamped_error = relative_error.clamp(-1 << 32, 4 << 32);

    // change to control signal
    // adjustment_factor = (1 + P * error)
    // const P: f64 = -1.0 / 16.0;
    let one_plus_p_times_error = (1i64 << 32) + ((-clamped_error) >> 4);
    let lo = one_plus_p_times_error as u32;
    let hi = (one_plus_p_times_error >> 32) as u32;

    let mut new_difficulty = [0u32; DIFFICULTY_NUM_LIMBS + 1];
    let mut carry = 0u32;
    for (old_difficulty_i, new_difficulty_i) in old_difficulty
        .0
        .iter()
        .zip(new_difficulty.iter_mut().take(DIFFICULTY_NUM_LIMBS))
    {
        let sum = (carry as u64) + (*old_difficulty_i as u64) * (lo as u64);
        *new_difficulty_i = sum as u32;
        carry = (sum >> 32) as u32;
    }
    new_difficulty[DIFFICULTY_NUM_LIMBS] = carry;
    carry = 0u32;
    for (old_difficulty_i, new_difficulty_i_plus_one) in old_difficulty
        .0
        .iter()
        .zip(new_difficulty.iter_mut().skip(1))
    {
        let sum = (carry as u64) + (*old_difficulty_i as u64) * (hi as u64);
        let (digit, carry_bit) = new_difficulty_i_plus_one.overflowing_add(sum as u32);
        *new_difficulty_i_plus_one = digit;
        carry = ((sum >> 32) as u32) + (carry_bit as u32);
    }
    let new_difficulty = Difficulty::new(new_difficulty[1..].to_owned().try_into().unwrap());

    if new_difficulty < Difficulty::MINIMUM {
        Difficulty::MINIMUM
    } else {
        new_difficulty
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use num_bigint::{BigInt, BigUint};
    use num_rational::BigRational;
    use num_traits::ToPrimitive;
    use rand::{rngs::StdRng, thread_rng, SeedableRng};
    use rand_distr::{Distribution, Geometric};

    use crate::models::{
        blockchain::block::{block_height::BlockHeight, difficulty_control::Difficulty},
        proof_abstractions::timestamp::Timestamp,
    };

    use super::difficulty_control;

    impl Difficulty {
        pub(crate) fn from_biguint(bi: BigUint) -> Self {
            if bi.iter_u32_digits().count() > Self::NUM_LIMBS {
                panic!("BigUint too large to convert to Difficulty");
            }
            Self(
                bi.iter_u32_digits()
                    .take(Self::NUM_LIMBS)
                    .pad_using(Self::NUM_LIMBS, |_| 0u32)
                    .collect_vec()
                    .try_into()
                    .unwrap(),
            )
        }
    }

    fn sample_block_time(
        hash_rate: f64,
        difficulty: Difficulty,
        proving_time: f64,
        rng: &mut StdRng,
    ) -> f64 {
        let p_rational = BigRational::from_integer(1.into())
            / BigRational::from_integer(BigInt::from(BigUint::from(difficulty)));
        let p = p_rational
            .to_f64()
            .expect("difficulty-to-target conversion from `BigRational` to `f64` should succeed");
        let geo = Geometric::new(p).unwrap();
        let num_hashes = 1u64 + geo.sample(rng);
        let guessing_time = (num_hashes as f64) / hash_rate;
        proving_time + guessing_time
    }

    #[derive(Debug, Clone, Copy)]
    struct SimulationEpoch {
        log_hash_rate: f64,
        proving_time: f64,
        num_iterations: usize,
    }

    #[test]
    fn block_time_tracks_target() {
        // declare epochs
        let epochs = [
            SimulationEpoch {
                log_hash_rate: 2.0,
                proving_time: 300.0,
                num_iterations: 2000,
            },
            SimulationEpoch {
                log_hash_rate: 3.0,
                proving_time: 300.0,
                num_iterations: 2000,
            },
            SimulationEpoch {
                log_hash_rate: 3.0,
                proving_time: 60.0,
                num_iterations: 2000,
            },
            SimulationEpoch {
                log_hash_rate: 5.0,
                proving_time: 60.0,
                num_iterations: 2000,
            },
            SimulationEpoch {
                log_hash_rate: 2.0,
                proving_time: 0.0,
                num_iterations: 2000,
            },
        ];

        // run simulation
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();
        let mut block_times = vec![];
        let mut difficulty = Difficulty::MINIMUM;
        let target_block_time = 600f64;
        let target_block_interval = Timestamp::seconds(target_block_time.round() as u64);
        let mut new_timestamp = Timestamp::now();
        let mut block_height = BlockHeight::genesis();
        for SimulationEpoch {
            log_hash_rate,
            proving_time,
            num_iterations,
        } in epochs
        {
            let hash_rate = 10f64.powf(log_hash_rate);
            for _ in 0..num_iterations {
                let block_time = sample_block_time(hash_rate, difficulty, proving_time, &mut rng);
                block_times.push(block_time);
                let old_timestamp = new_timestamp;
                new_timestamp = new_timestamp + Timestamp::seconds(block_time.round() as u64);

                difficulty = difficulty_control(
                    new_timestamp,
                    old_timestamp,
                    difficulty,
                    Some(target_block_interval),
                    block_height,
                );
                block_height = block_height.next();
            }
        }

        // filter out monitored block times
        let allowed_adjustment_period = 1000usize;
        let mut monitored_block_times = vec![];
        let mut counter = 0;
        for epoch in epochs {
            monitored_block_times.append(
                &mut block_times
                    [counter + allowed_adjustment_period..counter + epoch.num_iterations]
                    .to_owned(),
            );
            counter += epoch.num_iterations;
        }

        // perform statistical test on block times
        let n = monitored_block_times.len();
        let mean = monitored_block_times.into_iter().sum::<f64>() / (n as f64);
        println!("mean block time: {mean}\ntarget is: {target_block_time}");

        let margin = 0.05;
        assert!(target_block_time * (1.0 - margin) < mean);
        assert!(mean < target_block_time * (1.0 + margin));
    }
}
