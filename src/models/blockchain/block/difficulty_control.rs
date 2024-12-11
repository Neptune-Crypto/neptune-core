use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;
use std::ops::Shr;
use std::ops::ShrAssign;

use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
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

use super::block_height::BlockHeight;
use crate::models::blockchain::block::block_header::ADVANCE_DIFFICULTY_CORRECTION_FACTOR;
use crate::models::blockchain::block::block_header::ADVANCE_DIFFICULTY_CORRECTION_WAIT;
use crate::models::blockchain::block::block_header::TARGET_BLOCK_INTERVAL;
use crate::models::proof_abstractions::timestamp::Timestamp;

const DIFFICULTY_NUM_LIMBS: usize = 5;

/// Estimated number of hashes required to find a block.
///
/// Every `Difficulty` determines a *target*, which is a hash digest. A block
/// has proof-of-work if its hash is smaller than the difficulty of its
/// predecessor.
///
/// The `Difficulty` is set by the `difficulty_control` mechanism such that the
/// target block interval is by actual block times.
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize, Arbitrary,
)]
pub struct Difficulty([u32; DIFFICULTY_NUM_LIMBS]);

impl Difficulty {
    pub const NUM_LIMBS: usize = DIFFICULTY_NUM_LIMBS;
    const LIMBS_FOR_MINIMUM: [u32; Self::NUM_LIMBS] = [1000, 0, 0, 0, 0];
    pub const MINIMUM: Self = Self::new(Self::LIMBS_FOR_MINIMUM);
    pub const MAXIMUM: Self = Self::new([u32::MAX; Self::NUM_LIMBS]);

    pub(crate) const fn new(difficulty: [u32; DIFFICULTY_NUM_LIMBS]) -> Self {
        let mut lte_minimum = true;
        let mut i = 0;
        while i < Self::NUM_LIMBS {
            if difficulty[i] > Self::LIMBS_FOR_MINIMUM[i] {
                lte_minimum = false;
            }
            i += 1;
        }
        if lte_minimum {
            Self(Self::LIMBS_FOR_MINIMUM)
        } else {
            Self(difficulty)
        }
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

    /// Multiply the `Difficulty` with a positive fixed point rational number
    /// consisting of two u32s as limbs separated by the point. Returns the
    /// (wrapping) result and the out-of-bounds limb containing the overflow, if
    /// any.
    fn safe_mul_fixed_point_rational(&self, lo: u32, hi: u32) -> (Self, u32) {
        let mut new_difficulty = [0u32; Self::NUM_LIMBS + 1];
        let mut carry = 0u32;
        for (old_difficulty_i, new_difficulty_i) in self
            .0
            .iter()
            .zip(new_difficulty.iter_mut().take(Self::NUM_LIMBS))
        {
            let sum = (carry as u64) + (*old_difficulty_i as u64) * (lo as u64);
            *new_difficulty_i = sum as u32;
            carry = (sum >> 32) as u32;
        }
        new_difficulty[Self::NUM_LIMBS] = carry;
        carry = 0u32;
        for (old_difficulty_i, new_difficulty_i_plus_one) in
            self.0.iter().zip(new_difficulty.iter_mut().skip(1))
        {
            let sum = (carry as u64) + (*old_difficulty_i as u64) * (hi as u64);
            let (digit, carry_bit) = new_difficulty_i_plus_one.overflowing_add(sum as u32);
            *new_difficulty_i_plus_one = digit;
            carry = ((sum >> 32) as u32) + (carry_bit as u32);
        }

        (
            Difficulty::new(new_difficulty[1..].to_owned().try_into().unwrap()),
            carry,
        )
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

impl Shr<usize> for Difficulty {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        let limb_offset = rhs / 32;
        let mut array = self
            .0
            .into_iter()
            .skip(limb_offset)
            .pad_using(Self::NUM_LIMBS, |_| 0u32)
            .collect_vec();

        let remainder = rhs % 32;
        if remainder.is_zero() {
            return Difficulty::new(array.try_into().unwrap());
        }

        let mut borrow = 0u32;
        for i in (0..Self::NUM_LIMBS).rev() {
            let new_borrow = array[i] & ((1 << remainder) - 1);
            array[i] = (array[i] >> remainder) | (borrow << (32 - remainder));
            borrow = new_borrow;
        }

        Difficulty::new(array.try_into().unwrap())
    }
}

impl ShrAssign<usize> for Difficulty {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
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

/// Estimates how many hashes were used to produce the data object.
///
/// Proof-of-work is used in the fork choice rule: when presented with
/// two forks of different height, a node will choose the one with the greater
/// amount of proof-of-work.
#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize, Arbitrary,
)]
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
/// with a few modifications such as clamping and advance correction.
/// The following diagram describes the mechanism.
///
/// ```notest
///                             --------------
///                            |              |------ new timestamp ------
///  --- new difficulty    --->|  blockchain  |------ old timestamp ----  |
/// |   (control signal)       |              |------ old difficulty -  | |
/// |                           --------------                        | | |
/// |   ---                            ---                            | | |
///  --| * |<-------------------------| * |<--------------------------  | |
///     ---                            ---                              | |
///      ^ PID                          ^  advance                      | |
///      | adjustment                   |  correction                 - v v
///      |                              |                               ---
///      |                           ------                            | + |
///     ---                         | 2^-x |                            ---
///    | + |<--- 1.0                 ------                   (process   |
///     ---                             ^      (setpoint:)    variable:) |
///      ^                              |        target         observed |
///      |                           -------      block       block time |
///      |                          | floor |    interval                v
///      |                           -------       |                 -  ---
///      |                              ^          |------------------>| + |
///      |                              |          |                    ---
///      |                            -----        |                     |
///      |                           | 1/7 |       v                     |
///      |   (P =)                    -----      -----                   |
///      |   -2^-4                      ^       | 1/x |                  |
///      |     |                        |        -----                   |
///      |     v                        |          v                     |
///      |    ---     ---------------   |         ---     absolute error |
///       ---| * |<--| clamp [-1; 4] |<----------| * |<------------------
///           ---     ---------------   relative  ---
///                                      error
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
    mut old_difficulty: Difficulty,
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
    let relative_error =
        (absolute_error as i128) * ((1i128 << 32) / (target_block_interval.0.value() as i128));
    let clamped_error = relative_error.clamp(-1 << 32, 4 << 32);

    // Errors smaller than -1 cannot occur because delta_t >= MINIMUM_BLOCK_TIME > 0.
    // Errors greater than 4 can occur but are clamped away because otherwise a
    // single arbitrarily large concrete block time can induce an arbitrarily
    // large downward adjustment to the difficulty.
    // After clamping a `u64` suffices but before clamping we might get overflow
    // for very large block times so we use i128 for the `relative_errror`.

    // Every time ADVANCE_DIFFICULTY_CORRECTION_WAIT target block times pass
    // between two blocks, the effective difficulty (the thing being compared
    // against the new block's hash) drops by a factor
    // ADVANCE_DIFFICULTY_CORRECTION_FACTOR, or drops to the minimum difficulty,
    // whichever is largest.
    let num_advance_reductions =
        relative_error >> (32 + ADVANCE_DIFFICULTY_CORRECTION_WAIT.ilog2());
    if num_advance_reductions > 0 {
        let shift_amount = ((num_advance_reductions as u128)
            * (ADVANCE_DIFFICULTY_CORRECTION_FACTOR.ilog2() as u128))
            as usize;
        old_difficulty >>= shift_amount;
    }

    // change to control signal
    // adjustment_factor = (1 + P * error)
    // const P: f64 = -1.0 / 16.0;
    let one_plus_p_times_error = (1i128 << 32) + ((-clamped_error) >> 4);
    debug_assert!(one_plus_p_times_error.is_positive());

    let lo = one_plus_p_times_error as u32;
    let hi = (one_plus_p_times_error >> 32) as u32;
    let (new_difficulty, overflow) = old_difficulty.safe_mul_fixed_point_rational(lo, hi);

    if overflow > 0 {
        Difficulty::MAXIMUM
    } else {
        new_difficulty
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use num_bigint::BigInt;
    use num_bigint::BigUint;
    use num_rational::BigRational;
    use num_traits::One;
    use num_traits::ToPrimitive;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use rand::SeedableRng;
    use rand_distr::Bernoulli;
    use rand_distr::Distribution;
    use rand_distr::Geometric;
    use test_strategy::proptest;

    use super::difficulty_control;
    use crate::models::blockchain::block::block_header::ADVANCE_DIFFICULTY_CORRECTION_FACTOR;
    use crate::models::blockchain::block::block_header::ADVANCE_DIFFICULTY_CORRECTION_WAIT;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::block::difficulty_control::Difficulty;
    use crate::models::proof_abstractions::timestamp::Timestamp;

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
        mut difficulty: Difficulty,
        proving_time: f64,
        target_block_time: f64,
        rng: &mut StdRng,
    ) -> f64 {
        let mut block_time_so_far = proving_time;
        let window_duration = target_block_time * (ADVANCE_DIFFICULTY_CORRECTION_WAIT as f64);
        let num_hashes_calculated_per_window = hash_rate * window_duration;
        for window in 0.. {
            // probability of success per Bernoulli trial
            let p_rational = BigRational::from_integer(1.into())
                / BigRational::from_integer(BigInt::from(BigUint::from(difficulty)));
            let p = p_rational.to_f64().expect(
                "difficulty-to-target conversion from `BigRational` to `f64` should succeed",
            );

            // determine whether we are successful in this time window
            let log_prob_failure = (-p).ln_1p(); // ln (1-p)
            let log_prob_collective_failure = log_prob_failure * num_hashes_calculated_per_window;
            let prob_collective_success = -log_prob_collective_failure.exp_m1(); // 1-e^x

            let success = Bernoulli::new(prob_collective_success).unwrap().sample(rng);

            // if not, advance-correct difficulty
            if !success {
                println!(
                    "window {window}: time spent mining so far is {block_time_so_far}; \
                    probability of collective success is \
                    {prob_collective_success} and success was {success}, \
                    so correcting difficulty ...",
                );
                difficulty >>= ADVANCE_DIFFICULTY_CORRECTION_FACTOR
                    .ilog2()
                    .try_into()
                    .unwrap();
                block_time_so_far += window_duration;
                continue;
            }

            // else, determine time spent hashing
            // reject samples that exceed window bounds
            let distribution = Geometric::new(p).unwrap();
            let mut num_hashes = 1u64 + distribution.sample(rng);
            let mut time_spent_guessing = (num_hashes as f64) / hash_rate;
            while time_spent_guessing > window_duration {
                num_hashes = 1u64 + distribution.sample(rng);
                time_spent_guessing = (num_hashes as f64) / hash_rate;
            }
            block_time_so_far += time_spent_guessing;
            break;
        }

        block_time_so_far
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
                let block_time = sample_block_time(
                    hash_rate,
                    difficulty,
                    proving_time,
                    target_block_time,
                    &mut rng,
                );
                block_times.push(block_time);
                let old_timestamp = new_timestamp;
                new_timestamp += Timestamp::seconds(block_time.round() as u64);

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

        // select monitored block times
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

    #[proptest(cases = 10000)]
    fn one_plus_p_times_error_is_never_negative(
        #[strategy(arb())] old_timestamp: Timestamp,
        #[strategy(Timestamp::arbitrary_after(#old_timestamp))] new_timestamp: Timestamp,
        #[strategy(arb())] old_difficulty: Difficulty,
        #[strategy(Timestamp::arbitrary_between(Timestamp::seconds(0), Timestamp::days(1)))]
        target_block_interval: Timestamp,
        #[strategy(arb())] previous_block_height: BlockHeight,
    ) {
        // Function `difficulty_control` debug-asserts that the relevant
        // quantity is positive; so we just call the function to try to
        // trigger the error.
        difficulty_control(
            new_timestamp,
            old_timestamp,
            old_difficulty,
            Some(target_block_interval),
            previous_block_height,
        );
    }

    #[test]
    #[should_panic]
    fn debug_assert_fails() {
        debug_assert!(false);
    }

    #[proptest]
    fn mul_by_fixed_point_rational_distributes(
        #[strategy(arb())] a: Difficulty,
        #[strategy(arb())] b: Difficulty,
        #[strategy(arb())] lo: u32,
        #[strategy(arb())] hi: u32,
    ) {
        let a_bui = BigUint::from(a);
        let b_bui = BigUint::from(b);
        let a_plus_b_bui = a_bui + b_bui;
        if a_plus_b_bui.clone() >= BigUint::one() << (Difficulty::NUM_LIMBS * 32) {
            // a + b generates overflow which is not caught
            // so ignore test in this case
            return Ok(());
        }

        let r = (lo as u64) + ((hi as u64) << 32);
        let r_times_a_plus_b_bui: BigUint = (a_plus_b_bui.clone() * r) >> 32;

        let (ra, ra_overflow) = a.safe_mul_fixed_point_rational(lo, hi);
        let (rb, rb_overflow) = b.safe_mul_fixed_point_rational(lo, hi);

        let r_times_a_bui = BigUint::new(
            ra.into_iter()
                .pad_using(Difficulty::NUM_LIMBS, |_| 0u32)
                .chain([ra_overflow].into_iter())
                .collect_vec(),
        );
        let r_times_b_bui = BigUint::new(
            rb.into_iter()
                .pad_using(Difficulty::NUM_LIMBS, |_| 0u32)
                .chain([rb_overflow].into_iter())
                .collect_vec(),
        );
        let r_times_a_plus_r_times_b_bui = r_times_a_bui + r_times_b_bui;

        // ignore least significant bit because it might differ due to a carry
        // from the fractional part
        prop_assert!(
            r_times_a_plus_r_times_b_bui.clone() == r_times_a_plus_b_bui.clone()
                || r_times_a_plus_r_times_b_bui + BigUint::one() == r_times_a_plus_b_bui
        );
    }

    #[proptest]
    fn shift_right_accumulates(
        #[strategy(arb())] diff: Difficulty,
        #[strategy(0usize..100)] a: usize,
        #[strategy(0usize..100)] b: usize,
    ) {
        prop_assert_eq!((diff >> a) >> b, diff >> (a + b));
        prop_assert_eq!((diff >> b) >> a, diff >> (a + b));
    }

    #[proptest]
    fn shift_right_matches_biguint(
        #[strategy(arb())] diff: Difficulty,
        #[strategy(0usize..100)] a: usize,
    ) {
        prop_assert_eq!(BigUint::from(diff) >> a, BigUint::from(diff >> a));
    }

    #[proptest]
    fn shift_right_assign_matches_shift_right(
        #[strategy(arb())] diff: Difficulty,
        #[strategy(0usize..100)] a: usize,
    ) {
        let mut running_diff = diff;
        running_diff >>= a;
        prop_assert_eq!(diff >> a, running_diff);
    }
}
