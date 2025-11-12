use std::fmt::Display;
use std::iter::Sum;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Neg;
use std::ops::Sub;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use get_size2::GetSize;
use itertools::Itertools;
use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use num_traits::Zero;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::native_currency::NativeCurrency;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::triton_vm::prelude::triton_instr;

/// Records an amount of Neptune coins. Amounts are internally represented by an
/// atomic unit called Neptune atomic units (nau), which itself is represented
/// as a 128 bit integer.
///
/// 1 Neptune coin = 10^30 * 2^2 nau.
///
/// This conversion factor was chosen such that:
///  - The largest possible amount, corresponding to 42 000 000 Neptune coins, takes 127 bits.
///    The top bit is the sign bit and is used for negative amounts (in two's complement).
///  - When expanding amounts of Neptune coins in decimal form, we can represent them exactly
///    up to 30 decimal digits.
///
/// When using `NativeCurrencyAmount` in a type script or a lock script, or even another consensus
/// program related to block validity, it is important to use `safe_add` rather than `+` as
/// the latter operation does not care about overflow. Not testing for overflow can cause
/// inflation bugs.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, Eq, Default, BFieldCodec)]
pub struct NativeCurrencyAmount(i128);

impl TasmObject for NativeCurrencyAmount {
    fn label_friendly_name() -> String {
        "NativeCurrencyAmount".to_owned()
    }

    fn compute_size_and_assert_valid_size_indicator(
        library: &mut tasm_lib::prelude::Library,
    ) -> Vec<tasm_lib::triton_vm::prelude::LabelledInstruction> {
        u128::compute_size_and_assert_valid_size_indicator(library)
    }

    fn decode_iter<Itr: Iterator<Item = tasm_lib::triton_vm::prelude::BFieldElement>>(
        iterator: &mut Itr,
    ) -> std::result::Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let inner = *u128::decode_iter(iterator)? as i128;

        std::result::Result::Ok(Box::new(NativeCurrencyAmount(inner)))
    }
}

impl NativeCurrencyAmount {
    pub(crate) const MAX_NAU: i128 = 42_000_000 * Self::conversion_factor();

    /// The maximum amount that is still valid.
    pub(crate) fn max() -> Self {
        Self(Self::MAX_NAU)
    }

    /// The minimum amount that is still valid.
    pub(crate) fn min() -> Self {
        Self(-Self::MAX_NAU)
    }

    /// The conversion factor is 10^30 * 2^2.
    /// It is such that 42 000 000 * 10^30 * 2^2 is just one bit shy of being 128 bits
    /// wide. The one shy bit is used for the sign.
    const fn conversion_factor() -> i128 {
        let mut product = 1i128;
        let ten = 10i128;
        let mut i = 0;
        while i < 30 {
            product *= ten;
            i += 1;
        }

        let two = 2i128;
        i = 0;
        while i < 2 {
            product *= two;
            i += 1;
        }
        product
    }

    /// Return the element that corresponds to 1 nau. Use in tests only.
    #[cfg(test)]
    pub fn one_nau() -> NativeCurrencyAmount {
        NativeCurrencyAmount(1i128)
    }

    /// Create an NativeCurrencyAmount object of the given number of whole coins.
    ///
    /// Note that the maximum number of whole coins is 42 million which fits
    /// within a u32.
    pub const fn coins(num_whole_coins: u32) -> NativeCurrencyAmount {
        assert!(
            num_whole_coins <= 42_000_000,
            "Number of coins must be less than 42000000"
        );
        let number: i128 = num_whole_coins as i128;
        Self(Self::conversion_factor() * number)
    }

    pub fn div_two(&mut self) {
        self.0 /= 2;
    }

    pub fn half(self) -> Self {
        Self(self.0 / 2)
    }

    /// Create a `coins` object for use in a UTXO
    pub fn to_native_coins(&self) -> Vec<Coin> {
        let dictionary = vec![Coin {
            type_script_hash: NativeCurrency.hash(),
            state: self.encode(),
        }];
        dictionary
    }

    /// Convert the amount to Neptune atomic units (nau) as a 64-bit floating
    /// point number. Note that this function loses precision!
    ///
    /// Quantities whose unit is nau are used for internal logic and are not to
    /// be used for user-facing displays.
    pub fn to_nau_f64(&self) -> f64 {
        self.0 as f64
    }

    /// Return the number of whole coins, rounded up to nearest integeer.
    /// Negative numbers are rounded up to nearest whole negative number such
    /// that -2.5 is rounded up to -2.
    ///
    /// # Panics
    ///
    /// - If the amount is outside of the range between minimum and
    ///   maximum allowed value.
    pub fn ceil_num_whole_coins(&self) -> i32 {
        assert!(
            *self <= Self::max() && *self >= Self::min(),
            "Amount must be contained between min and max"
        );

        // Manual implementation of `div_ceil`
        let conversion_factor = Self::conversion_factor();
        let term = i128::from(self.is_positive()) * (conversion_factor - 1);
        ((self.0 + term) / conversion_factor)
            .try_into()
            .expect("Any amount divided conversion factor must be a valid i32")
    }

    /// Convert the amount (of Neptune Coins) to Neptune atomic units (nau).
    ///
    /// Quantities whose unit is nau are used for internal logic and are not to
    /// be used for user-facing displays.
    pub fn to_nau(&self) -> i128 {
        self.0
    }

    /// Convert the number of Neptune atomic units (nau) to a
    /// `NativeCurrencyAmount`.
    pub fn from_nau(nau: i128) -> Self {
        Self(nau)
    }

    /// Multiply the amount by a non-negative 32-bit number.
    ///
    /// Returns `None` in the case of overflow.
    pub fn checked_scalar_mul(&self, factor: u32) -> Option<Self> {
        let factor_as_i128 = i128::from(factor);
        self.0.checked_mul(factor_as_i128).map(NativeCurrencyAmount)
    }

    /// Multiply the amount by a non-negative 32-bit number.
    ///
    /// Crashes in case of overflow.
    pub fn scalar_mul(&self, factor: u32) -> Self {
        let factor_as_i128 = i128::from(factor);
        let (res, overflow) = self.0.overflowing_mul(factor_as_i128);
        assert!(!overflow, "Overflow on scalar multiplication not allowed.");
        NativeCurrencyAmount(res)
    }

    /// Multiply a coin amount with a fraction, in a lossy manner. Result is
    /// guaranteed to not exceed `self`.
    ///
    /// # Panics
    ///
    /// If the provided fraction is not between 0 and 1 (inclusive).
    pub fn lossy_f64_fraction_mul(&self, fraction: f64) -> NativeCurrencyAmount {
        assert!(
            (0.0..=1.0).contains(&fraction),
            "fraction must be between 0 and 1"
        );

        if self.is_negative() {
            return self.neg().lossy_f64_fraction_mul(fraction);
        }

        if fraction == 1.0 {
            return *self;
        }

        let value_as_f64 = self.to_nau_f64();
        let res = fraction * value_as_f64;
        let as_i128 = match res.to_i128() {
            Some(i) => i.clamp(0, self.0),
            None => 0_i128,
        };
        Self::from_nau(as_i128)
    }

    /// Generate an iterator for the running balance, updated with each item.
    ///
    /// Note that balances cannot be negative, so this method clamps at zero.
    pub fn scan_balance<I: IntoIterator<Item = Self> + Clone>(
        balance_update_itr: &I,
        initial_balance: Self,
    ) -> impl Iterator<Item = Self> + '_ {
        balance_update_itr.clone().into_iter().scan(
            initial_balance,
            |current_balance, new_update| {
                *current_balance = if new_update.is_negative() {
                    current_balance
                        .checked_add_negative(&new_update)
                        .unwrap_or(Self::zero())
                } else {
                    *current_balance + new_update
                };
                Some(*current_balance)
            },
        )
    }

    /// Add two [`NativeCurrencyAmount`]s, of which at most one is negative.
    ///
    /// The following cases generate `None`:
    ///  - adding two negative numbers
    ///  - adding two numbers whose sum is negative
    ///  - adding two numbers whose sum is greater than the max. amount of nau.
    pub(crate) fn checked_add_negative(&self, rhs: &Self) -> Option<Self> {
        if self.is_negative() && rhs.is_negative() {
            return None;
        }

        let value = self.0.checked_add(rhs.0)?;

        if value > Self::MAX_NAU || value.is_negative() {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Return tasm code for pushing this amount to the stack.
    pub(crate) fn push_to_stack(&self) -> Vec<LabelledInstruction> {
        self.encode()
            .into_iter()
            .rev()
            .map(|b| triton_instr!(push b))
            .collect()
    }

    /// Display the `NativeCurrencyAmount` as a fractional number of coins in
    /// base 10 with `n` decimal digits after the comma.
    ///
    /// This method rounds the amount if necessary. To avoid losing precision,
    /// set `n` to `usize::MAX` or anything greater than or equal to 34, or just
    /// call [`Self::display_lossless`].
    pub fn display_n_decimals(&self, n: usize) -> String {
        if self.is_negative() {
            return "-".to_owned() + &self.neg().display_n_decimals(n);
        }

        let conversion_factor = Self::conversion_factor();

        let mut remainder = self.0;
        let integer_part = remainder / conversion_factor;
        remainder %= conversion_factor;

        let mut decimals = vec![integer_part];
        for _ in 0..n {
            remainder *= 10;
            let digit = remainder / conversion_factor;
            remainder %= conversion_factor;
            decimals.push(digit);
        }
        if (remainder * 10) / conversion_factor > 5 {
            let mut i = decimals.len() - 1;
            decimals[i] += 1;
            while decimals[i] == 10 {
                decimals[i] = 0;
                decimals[i - 1] += 1;
                if i == 1 {
                    break;
                }
                i -= 1;
            }
        }

        format!(
            "{}.{}",
            decimals[0],
            decimals.iter().skip(1).copied().join("")
        )
    }

    /// Display the `NativeCurrencyAmount` as a fractional number of coins in
    /// base 10 with enough decimal places to guarantee zero precision loss.
    ///
    /// The maximum and minimum lengths of the produced strings are 44 and 36,
    /// corresponding to `-NativeCurrencyAmount::MAX` and
    /// `NativeCurrencyAmount::from_nau(BigInt::from(1u8)).unwrap()`; see tests
    /// `display_lossless_can_produce_36_chars` and
    /// `display_lossless_can_produce_44_chars`.
    pub fn display_lossless(&self) -> String {
        self.display_n_decimals(34)
    }
}

impl NativeCurrencyAmount {
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    pub(crate) fn is_positive(&self) -> bool {
        self.0.is_positive()
    }
}

impl GetSize for NativeCurrencyAmount {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        0
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl Ord for NativeCurrencyAmount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Add for NativeCurrencyAmount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for NativeCurrencyAmount {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Sum for NativeCurrencyAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        NativeCurrencyAmount(iter.map(|a| a.0).sum())
    }
}

impl Sub for NativeCurrencyAmount {
    type Output = NativeCurrencyAmount;

    fn sub(self, _rhs: Self) -> Self::Output {
        panic!("Cannot subtract `NativeCurrencyAmount`s; use `checked_sub` instead.")
    }
}

impl CheckedSub for NativeCurrencyAmount {
    /// Return Some(self-other) if the result is positive (or zero); otherwise
    /// return None.
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        if !self.is_negative() && !v.is_negative() && self >= v {
            Some(NativeCurrencyAmount(self.0 - v.0))
        } else {
            None
        }
    }
}

impl CheckedAdd for NativeCurrencyAmount {
    /// Return Some(self+other) if (there is no i128-overflow and) the result is
    /// smaller than the maximum number of nau.
    fn checked_add(&self, v: &Self) -> Option<Self> {
        self.0.checked_add(v.0).and_then(|sum| {
            (-Self::MAX_NAU..=Self::MAX_NAU)
                .contains(&sum)
                .then_some(Self(sum))
        })
    }
}

impl Neg for NativeCurrencyAmount {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl PartialEq for NativeCurrencyAmount {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for NativeCurrencyAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Zero for NativeCurrencyAmount {
    fn zero() -> Self {
        NativeCurrencyAmount(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug, Copy, Clone)]
pub enum FloatConversionError {
    NaN,
    Infinity,
    Negative,
    Overflow,
    InvalidAmount,
}

impl TryFrom<f64> for NativeCurrencyAmount {
    type Error = FloatConversionError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        let i = if value.is_nan() {
            Err(FloatConversionError::NaN)
        } else if value.is_infinite() {
            Err(FloatConversionError::Infinity)
        } else if value < 0.0 {
            Err(FloatConversionError::Negative)
        } else if value > Self::MAX_NAU as f64 {
            Err(FloatConversionError::Overflow)
        } else {
            Ok(value as i128)
        }?;
        Ok(Self::from_nau(i))
    }
}

impl NativeCurrencyAmount {
    /// Convert a decimal string representation of a not necessarily integral
    /// amount of native currency into a `NativeCurrencyAmount` object.
    pub fn coins_from_str(s: &str) -> Result<Self, anyhow::Error> {
        let re = Regex::new(r#"^(-?)([0-9]*)\.?([0-9]*)$"#).unwrap();
        let Some((_full, substrings)) = re.captures(s).map(|c| c.extract::<3>()) else {
            bail!("invalid amount: unmatched regex");
        };
        let sign = match substrings[0] {
            "-" => num_bigint::Sign::Minus,
            "" => num_bigint::Sign::Plus,
            _ => bail!("invalid amount: matched but unrecognized sign symbol"),
        };
        let integer_part = if substrings[1].is_empty() {
            BigInt::zero()
        } else {
            BigInt::from_str(substrings[1])?
        };
        let fractional_part = if substrings[2].is_empty() {
            BigInt::zero()
        } else {
            BigInt::from_str(substrings[2])?
        };
        let power = substrings[2].len();
        let ten = BigInt::from(10_u8);
        let mut decimal_shift = BigInt::from(1_u8);
        for _ in 0..power {
            decimal_shift *= ten.clone();
        }
        let numerator = integer_part * decimal_shift.clone() + fractional_part;
        let nau = if numerator.is_zero() {
            BigInt::zero()
        } else {
            let denominator = decimal_shift;
            let conversion_factor = BigInt::from_i128(Self::conversion_factor()).unwrap();
            let nau_rational = BigRational::new(numerator * conversion_factor, denominator).round();
            match sign {
                num_bigint::Sign::Minus => -nau_rational.numer(),
                num_bigint::Sign::Plus => nau_rational.numer().to_owned(),
                num_bigint::Sign::NoSign => unreachable!(),
            }
        };

        let max_nau = BigInt::from(Self::MAX_NAU);
        ensure!(nau >= -max_nau.clone(), "amount of Neptune coins too small");
        ensure!(nau <= max_nau, "amount of Neptune coins too large");

        i128::try_from(nau)
            .map(Self)
            .map_err(|e| anyhow!("invalid amount of Neptune coins: {e:?}"))
    }
}

impl Display for NativeCurrencyAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_n_decimals(8))
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use arbitrary::Arbitrary;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest_arbitrary_interop::arb;

    use super::*;

    impl<'a> Arbitrary<'a> for NativeCurrencyAmount {
        /// Generate an arbitrary amount of NativeCurrencyAmount that is small in absolute
        /// value but can be negative.
        fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
            let nau: u128 = u.arbitrary()?;
            Ok(NativeCurrencyAmount((nau as i128) >> 10))
        }
    }

    impl NativeCurrencyAmount {
        pub(crate) fn abs(&self) -> Self {
            Self(self.0.abs())
        }

        pub(crate) fn arbitrary_non_negative() -> BoxedStrategy<Self> {
            arb::<u128>()
                .prop_map(|uint| NativeCurrencyAmount((uint >> 10) as i128))
                .boxed()
        }

        /// Generate a strategy for an Option of NativeCurrencyAmount, which if set will be
        /// a small non-negative amount.
        pub(crate) fn arbitrary_coinbase() -> BoxedStrategy<Option<Self>> {
            arb::<Option<NativeCurrencyAmount>>()
                .prop_map(|coinbase| coinbase.map(|c| c.abs()))
                .boxed()
        }

        /// Generate a strategy for a NativeCurrencyAmount anywhere between the
        /// minimum and maximum numbers (extrema included).
        #[cfg(test)]
        pub(crate) fn arbitrary_full_range() -> BoxedStrategy<Self> {
            (-Self::MAX_NAU..=Self::MAX_NAU)
                .prop_map(NativeCurrencyAmount::from_nau)
                .boxed()
        }
    }
}

#[cfg(feature = "mock-rpc")]
impl rand::distr::Distribution<NativeCurrencyAmount> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> NativeCurrencyAmount {
        NativeCurrencyAmount::from_nau(
            rng.random_range(-NativeCurrencyAmount::MAX_NAU..NativeCurrencyAmount::MAX_NAU),
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use std::cmp::max;
    use std::panic::catch_unwind;

    use get_size2::GetSize;
    use itertools::Itertools;
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest::prelude::*;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::prop_assume;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::isa::instruction::AnInstruction;
    use test_strategy::proptest;

    use super::*;
    use crate::protocol::consensus::block::INITIAL_BLOCK_SUBSIDY;

    impl NativeCurrencyAmount {
        pub(crate) fn from_raw_i128(int: i128) -> Self {
            Self(int)
        }
    }

    pub(crate) fn invalid_positive_amount() -> BoxedStrategy<NativeCurrencyAmount> {
        let i128_max = (u128::MAX >> 1) as i128;
        ((NativeCurrencyAmount::MAX_NAU + 1)..=i128_max)
            .prop_map(NativeCurrencyAmount)
            .boxed()
    }

    #[test]
    fn half_of_zero_and_one_nau() {
        assert_eq!(
            NativeCurrencyAmount::zero(),
            NativeCurrencyAmount::from_nau(1).half()
        );
        assert_eq!(
            NativeCurrencyAmount::zero(),
            NativeCurrencyAmount::from_nau(0).half()
        );
    }

    #[proptest]
    fn two_times_half_value_is_value_up_to_rounding_error(value: i128) {
        let is_odd = NativeCurrencyAmount::from_nau(value % 2);
        let value = NativeCurrencyAmount::from_nau(value);
        let half = value.half();
        prop_assert_eq!(value, half + half + is_odd);
        prop_assert_eq!(value, half.scalar_mul(2) + is_odd);
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100, .. ProptestConfig::default()
          })]
        #[test]
        fn test_string_conversion(
            number in 0..42000000u32
        ) {
            let amount = NativeCurrencyAmount::coins(number);
            let string = amount.to_string();
            let reconstructed_amount = NativeCurrencyAmount::coins_from_str(&string)
                .expect("Could not parse as number a string generated from a number.");

            assert_eq!(amount, reconstructed_amount);
        }
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig {
            cases: 5, .. ProptestConfig::default()
          })]
        #[test]
        fn test_bfe_conversion(amount in arb::<NativeCurrencyAmount>()) {
            let bfes = amount.encode();
            let reconstructed_amount = *NativeCurrencyAmount::decode(&bfes).unwrap();

            assert_eq!(amount, reconstructed_amount);
        }
    }

    #[test]
    fn test_bfe_conversion_with_option_amount() {
        proptest::proptest!(ProptestConfig::with_cases(10), |(amount in arb::<NativeCurrencyAmount>())| {
            let bfes = Some(amount).encode();
            let reconstructed_amount = *Option::<NativeCurrencyAmount>::decode(&bfes).unwrap();

            assert_eq!(Some(amount), reconstructed_amount);
        });

        let amount: Option<NativeCurrencyAmount> = None;
        let bfes = amount.encode();
        let reconstructed_amount = *Option::<NativeCurrencyAmount>::decode(&bfes).unwrap();
        assert!(reconstructed_amount.is_none());
    }

    #[test]
    fn from_coins_conversion_simple_test() {
        let a = 41000000;
        let b = 100u32;
        let a_amount: NativeCurrencyAmount = NativeCurrencyAmount::coins(a);
        let b_amount: NativeCurrencyAmount = NativeCurrencyAmount::coins(b);
        assert_eq!(a_amount + b_amount, NativeCurrencyAmount::coins(a + b));
    }

    proptest::proptest! {
        #[test]
        fn from_nau_conversion_pbt(
            a in (0u64..(1 << 63)),
            b in (0u64..(1 << 63)),
        ) {
            let a_amount: NativeCurrencyAmount = NativeCurrencyAmount::from_nau(a.into());
            let b_amount: NativeCurrencyAmount = NativeCurrencyAmount::from_nau(b.into());
            assert_eq!(
                a_amount + b_amount,
                NativeCurrencyAmount::from_nau((a + b).into())
            );
        }

        #[test]
        fn amount_scalar_mul_pbt(
            a in 0..42000000u32,
            b in 0..42000000u32
        ) {
            if u64::from(a) * u64::from(b) <= 42000000 {
                let prod_checked: NativeCurrencyAmount = NativeCurrencyAmount::coins(a * b);
                let mut prod_calculated: NativeCurrencyAmount = NativeCurrencyAmount::coins(a);
                prod_calculated = prod_calculated.scalar_mul(b);
                assert_eq!(prod_checked, prod_calculated);
            } else {assert![catch_unwind(|| NativeCurrencyAmount::coins(a).scalar_mul(b)).is_err()]}
        }
    }

    #[test]
    fn amount_simple_scalar_mul_test() {
        let fourteen: NativeCurrencyAmount = NativeCurrencyAmount::coins(14);
        let fourtytwo: NativeCurrencyAmount = NativeCurrencyAmount::coins(42);
        assert_eq!(fourtytwo, fourteen.scalar_mul(3));
    }

    #[test]
    fn simple_f64_lossy_mul_half() {
        let one_hundred = NativeCurrencyAmount::coins(100);
        let half_of_one_hundred = one_hundred.lossy_f64_fraction_mul(0.5);

        // Assert that the value is in a reasonable range, close enough.
        assert!(
            half_of_one_hundred > NativeCurrencyAmount::coins(49)
                && half_of_one_hundred < NativeCurrencyAmount::coins(51)
        );
    }

    #[test]
    fn simple_f64_lossy_mul_zero() {
        let one_hundred = NativeCurrencyAmount::coins(100);
        assert_eq!(
            NativeCurrencyAmount::zero(),
            one_hundred.lossy_f64_fraction_mul(0f64)
        );
    }

    #[test]
    fn simple_f64_lossy_mul_one() {
        let one_hundred = NativeCurrencyAmount::coins(100);
        assert_eq!(one_hundred, one_hundred.lossy_f64_fraction_mul(1f64));
    }

    #[test]
    fn get_size_test() {
        let fourteen: NativeCurrencyAmount = NativeCurrencyAmount::coins(14);
        assert_eq!(4 * 4, fourteen.get_size())
    }

    #[test]
    fn conversion_factor_is_optimal() {
        let forty_two_million = BigInt::from_i32(42_000_000).unwrap();
        let conversion_factor =
            BigInt::from_i128(NativeCurrencyAmount::conversion_factor()).unwrap();
        let two_pow_127 = BigInt::from_i8(1).unwrap() << 127;
        assert!(conversion_factor.clone() * forty_two_million.clone() < two_pow_127);

        // let's also test optimality:
        // adding another factor 5 or 2 will break this property
        let five = BigInt::from_i8(5).unwrap();
        let two = BigInt::from_i8(2).unwrap();
        assert!(conversion_factor.clone() * two * forty_two_million.clone() >= two_pow_127);
        assert!(conversion_factor * five * forty_two_million >= two_pow_127);
    }

    #[test]
    fn sign_bit_of_max_amount_is_zero() {
        let first_instruction = NativeCurrencyAmount::max().push_to_stack()[0].clone();
        let LabelledInstruction::Instruction(AnInstruction::Push(push_value)) = first_instruction
        else {
            panic!("Expected a push instruction");
        };
        let push_value: u32 = push_value
            .value()
            .try_into()
            .expect("Expected a valid u32 value");
        assert!((push_value & 0x80_00_00_00).is_zero());
    }

    #[test]
    fn sign_bit_of_min_amount_is_one() {
        let first_instruction = NativeCurrencyAmount::min().push_to_stack()[0].clone();
        let LabelledInstruction::Instruction(AnInstruction::Push(push_value)) = first_instruction
        else {
            panic!("Expected a push instruction");
        };
        let push_value: u32 = push_value
            .value()
            .try_into()
            .expect("Expected a valid u32 value");
        assert!(!(push_value & 0x80_00_00_00).is_zero());
    }

    #[test]
    fn from_decimal_test() {
        let parsed = NativeCurrencyAmount::coins_from_str("-10.125").unwrap();
        let cf = NativeCurrencyAmount::conversion_factor() >> 3;
        let fixed = -(NativeCurrencyAmount::from_nau(cf) + NativeCurrencyAmount::coins(10));
        assert_eq!(parsed.clone(), fixed);
        assert!(parsed.is_negative());
        println!("parsed: {}", parsed);

        for s in [
            "-12387.4382975",
            "823457.983247",
            "-.2349857",
            ".4356",
            "-34895.",
            "43859.",
            "0.00000000000045",
            "0.0",
            "0",
            "-0",
            "-1",
            "1",
            "01.10",
            "42000000",
            "-42000000",
        ] {
            let nc = NativeCurrencyAmount::coins_from_str(s)
                .unwrap_or_else(|e| panic!("cannot decode {} because {}", s, e));
            println!("{s}: {nc}");
        }

        for s in [
            "-12398745.2348573245.234897234",
            "--894357435.23489234",
            "+894357435.23489234",
            "++894357435.23489234",
            "42 000",
            "42'000",
            "42_000",
            "42,21",
            "79aead",
            "0x79aead",
            "84397594876458",
            "84000000.00",
            "-84000000.00",
        ] {
            println!("trying to parse {s} ...");
            assert!(
                NativeCurrencyAmount::coins_from_str(s).is_err(),
                "valid parsing: {}; parsed to: {}",
                s,
                NativeCurrencyAmount::coins_from_str(s).unwrap()
            );
        }
    }

    #[proptest]
    fn small_amounts_can_be_safely_added(
        #[strategy(arb())] a0: NativeCurrencyAmount,
        #[strategy(arb())] a1: NativeCurrencyAmount,
    ) {
        a0.checked_add(&a1).unwrap();
    }

    #[proptest]
    fn checked_add_proptest_quarter_range(lhs: i128, rhs: i128) {
        let lhs = lhs >> 2;
        let rhs = rhs >> 2;
        let expected = NativeCurrencyAmount(lhs + rhs);
        let lhs = NativeCurrencyAmount(lhs);
        let rhs = NativeCurrencyAmount(rhs);

        prop_assert_eq!(expected, lhs.checked_add(&rhs).unwrap());
    }

    #[proptest]
    fn checked_add_proptest_full_range(
        #[strategy(0..=NativeCurrencyAmount::MAX_NAU >> 1)] lhs: i128,
        #[strategy(0..=NativeCurrencyAmount::MAX_NAU >> 1)] rhs: i128,
    ) {
        let expected = NativeCurrencyAmount(lhs + rhs);
        let lhs = NativeCurrencyAmount(lhs);
        let rhs = NativeCurrencyAmount(rhs);
        prop_assert_eq!(expected, lhs.checked_add(&rhs).unwrap());
    }

    #[proptest]
    fn checked_add_proptest_limit(#[strategy(0..=NativeCurrencyAmount::MAX_NAU)] lhs: i128) {
        let rhs = NativeCurrencyAmount(NativeCurrencyAmount::MAX_NAU - lhs);
        prop_assert!(!rhs.is_negative());

        let lhs = NativeCurrencyAmount(lhs);
        let expected = NativeCurrencyAmount::max();
        prop_assert_eq!(expected, lhs.checked_add(&rhs).unwrap());
    }

    #[test]
    fn checked_add_unittest_limit() {
        let lhs = NativeCurrencyAmount(NativeCurrencyAmount::MAX_NAU >> 1);
        let rhs = NativeCurrencyAmount(NativeCurrencyAmount::MAX_NAU >> 1);

        let expected = NativeCurrencyAmount::max();
        assert_eq!(expected, lhs.checked_add(&rhs).unwrap());
    }

    #[proptest]
    fn checked_add_with_self_matches_scalar_mul_two(
        #[strategy(0..=NativeCurrencyAmount::MAX_NAU >> 1)] lhs: i128,
    ) {
        let lhs = NativeCurrencyAmount(lhs);
        prop_assert_eq!(lhs.scalar_mul(2), lhs.checked_add(&lhs).unwrap());
    }

    #[proptest]
    fn checked_add_with_self_and_self_matches_scalar_mul_three(
        #[strategy(0..=NativeCurrencyAmount::MAX_NAU >> 2)] lhs: i128,
    ) {
        let lhs = NativeCurrencyAmount(lhs);
        prop_assert_eq!(
            lhs.scalar_mul(3),
            lhs.checked_add(&lhs).unwrap().checked_add(&lhs).unwrap()
        );
    }

    #[proptest]
    fn checked_add_positive_overflow_proptest(rhs: u128) {
        let lhs = NativeCurrencyAmount(NativeCurrencyAmount::MAX_NAU);
        let rhs = NativeCurrencyAmount((rhs >> 2) as i128);
        prop_assume!(!rhs.is_zero());
        prop_assert!(lhs.checked_add(&rhs).is_none());
    }

    #[proptest]
    fn checked_add_negative_overflow_proptest(rhs: u128) {
        let lhs = NativeCurrencyAmount(-NativeCurrencyAmount::MAX_NAU);
        let rhs = -NativeCurrencyAmount((rhs >> 2) as i128);
        prop_assume!(!rhs.is_zero());
        prop_assert!(lhs.checked_add(&rhs).is_none());
    }

    #[test]
    fn checked_add_positive_overflow_unit_test() {
        let one_nau = NativeCurrencyAmount(1);
        let max_value = NativeCurrencyAmount(NativeCurrencyAmount::MAX_NAU);
        assert!(max_value.checked_add(&one_nau).is_none());
        assert!(max_value
            .checked_add(&NativeCurrencyAmount::zero())
            .is_some());
    }

    #[test]
    fn checked_add_negative_overflow_unit_test() {
        let minus_one_nau = -NativeCurrencyAmount(1);
        let min_value = -NativeCurrencyAmount(NativeCurrencyAmount::MAX_NAU);
        assert!(min_value.checked_add(&minus_one_nau).is_none());
        assert!(min_value
            .checked_add(&NativeCurrencyAmount::zero())
            .is_some());
    }

    #[test]
    fn expected_coins_static_length() {
        assert_eq!(Some(4), NativeCurrencyAmount::static_length());
    }

    #[proptest]
    fn to_and_from_nau_identity(
        #[strategy(-NativeCurrencyAmount::MAX_NAU..=NativeCurrencyAmount::MAX_NAU)] num_naus: i128,
    ) {
        let val = NativeCurrencyAmount(num_naus);
        prop_assert_eq!(val, NativeCurrencyAmount::from_nau(val.to_nau()));
    }

    #[proptest]
    fn ceil_num_whole_coins_integers_map_to_integers(#[strategy(0..42_000_000i32)] num_coins: i32) {
        let one_nau = NativeCurrencyAmount::one_nau();
        let amt = NativeCurrencyAmount::coins(num_coins as u32);
        let amt_plus = amt + one_nau;
        let amt_minus = amt.checked_sub(&one_nau).unwrap();
        prop_assert_eq!(num_coins, amt_minus.ceil_num_whole_coins());
        prop_assert_eq!(num_coins, amt.ceil_num_whole_coins());
        prop_assert_eq!(num_coins + 1, amt_plus.ceil_num_whole_coins());

        prop_assert_eq!(-num_coins, (-amt).ceil_num_whole_coins());
        prop_assert_eq!(-num_coins, (-amt_plus).ceil_num_whole_coins());
        prop_assert_eq!(-num_coins + 1, (-amt_minus).ceil_num_whole_coins());
    }

    #[test]
    fn ceil_num_whole_coins_unit_test() {
        let zero = NativeCurrencyAmount::zero();
        let one_nau = NativeCurrencyAmount::from_nau(1);
        let two_nau = NativeCurrencyAmount::from_nau(2);
        let one_coin = NativeCurrencyAmount::coins(1);
        let six_coins = NativeCurrencyAmount::coins(6);
        assert_eq!(0, zero.ceil_num_whole_coins());
        assert_eq!(1, one_nau.ceil_num_whole_coins());
        assert_eq!(1, two_nau.ceil_num_whole_coins());
        assert_eq!(
            1,
            (one_coin.checked_sub(&one_nau).unwrap()).ceil_num_whole_coins()
        );
        assert_eq!(1, one_coin.ceil_num_whole_coins());
        assert_eq!(2, (one_coin + one_nau).ceil_num_whole_coins());
        assert_eq!(
            128,
            (INITIAL_BLOCK_SUBSIDY.checked_sub(&one_nau).unwrap()).ceil_num_whole_coins()
        );
        assert_eq!(128, INITIAL_BLOCK_SUBSIDY.ceil_num_whole_coins());
        assert_eq!(
            129,
            (INITIAL_BLOCK_SUBSIDY + one_nau).ceil_num_whole_coins()
        );
        assert_eq!(
            42_000_000,
            NativeCurrencyAmount::max().ceil_num_whole_coins()
        );
        assert_eq!(6, six_coins.ceil_num_whole_coins());
        assert_eq!(7, (six_coins + one_nau).ceil_num_whole_coins());

        assert_eq!(-1, (-one_coin).ceil_num_whole_coins());
        assert_eq!(
            -42_000_000,
            NativeCurrencyAmount::min().ceil_num_whole_coins()
        );
        assert_eq!(0, (-one_nau).ceil_num_whole_coins());
        assert_eq!(0, (-two_nau).ceil_num_whole_coins());
        assert_eq!(
            0,
            (-(one_coin.checked_sub(&one_nau).unwrap())).ceil_num_whole_coins()
        );
        assert_eq!(-1, (-(one_coin + one_nau)).ceil_num_whole_coins());
    }

    #[proptest]
    fn scalar_mul_2_div_2_is_identity(
        #[strategy(-NativeCurrencyAmount::MAX_NAU/2..=NativeCurrencyAmount::MAX_NAU/2)]
        num_naus: i128,
    ) {
        let original = NativeCurrencyAmount(num_naus);
        let mut calculated = original.scalar_mul(2);
        calculated.div_two();
        prop_assert_eq!(original, calculated);
    }

    #[proptest]
    fn new_and_display_consistency_proptest(#[strategy(0u32..=42000000)] num_coins: u32) {
        let val = NativeCurrencyAmount::coins(num_coins);
        assert_eq!(format!("{val}"), format!("{num_coins}.00000000"));
    }

    #[proptest]
    fn encode_decode_identity(val: i128) {
        let val = NativeCurrencyAmount(val >> 1);
        prop_assert!(val == *NativeCurrencyAmount::decode(&val.encode()).unwrap());
    }

    #[proptest]
    fn outer_ordering_agrees_with_inner(lhs: i128, rhs: i128) {
        let inner_cmp = lhs < rhs;
        let lhs = NativeCurrencyAmount(lhs >> 1);
        let rhs = NativeCurrencyAmount(rhs >> 1);
        let outer_cmp = lhs < rhs;
        prop_assert!(inner_cmp == outer_cmp);
    }

    #[test]
    fn unsafe_amounts_fail() {
        let a0 = NativeCurrencyAmount(1i128 << 126);
        let a1 = NativeCurrencyAmount(1i128 << 126);
        assert!(a0.checked_add(&a1).is_none());
    }

    #[test]
    fn scan_balance_returns_sane_result() {
        let balance_updates =
            [64, 32, 32, 64, 32, 32, 64, 32, 32, -64, 53, 64, 32, 32].map(|i: i32| {
                if i.is_negative() {
                    -NativeCurrencyAmount::coins((-i) as u32)
                } else {
                    NativeCurrencyAmount::coins(i as u32)
                }
            });
        let expected_balances = [
            64, 96, 128, 192, 224, 256, 320, 352, 384, 320, 373, 437, 469, 501,
        ]
        .map(NativeCurrencyAmount::coins)
        .to_vec();
        let computed_balances =
            NativeCurrencyAmount::scan_balance(&balance_updates, NativeCurrencyAmount::zero())
                .collect_vec();
        assert_eq!(expected_balances, computed_balances);
    }

    #[test]
    fn can_negate_zero() {
        println!("{}", -NativeCurrencyAmount(0));
    }

    #[proptest]
    fn display_lossless_matches_parse(
        #[strategy(NativeCurrencyAmount::arbitrary_full_range())] amount: NativeCurrencyAmount,
    ) {
        let as_string = amount.display_lossless();
        let parsed = NativeCurrencyAmount::coins_from_str(&as_string).unwrap();
        prop_assert_eq!(parsed, amount);
    }

    #[proptest]
    fn add_and_assign_add_equivalence(
        #[strategy(0..=NativeCurrencyAmount::MAX_NAU >> 1)] lhs: i128,
        #[strategy(0..=NativeCurrencyAmount::MAX_NAU >> 1)] rhs: i128,
    ) {
        let lhs = NativeCurrencyAmount(lhs);
        let rhs = NativeCurrencyAmount(rhs);
        let add_result = lhs + rhs;
        let mut add_assign = lhs;
        add_assign += rhs;
        prop_assert_eq!(add_result, add_assign);
    }

    #[test]
    fn display_lossless_can_have_36_chars() {
        assert_eq!(
            36,
            NativeCurrencyAmount::from_nau(1.into())
                .display_lossless()
                .len()
        );
    }

    #[test]
    fn display_lossless_can_have_44_chars() {
        assert_eq!(44, (-NativeCurrencyAmount::max()).display_lossless().len());
    }

    #[proptest]
    fn display_agrees_with_display_8_decimals(
        #[strategy(NativeCurrencyAmount::arbitrary_full_range())] amount: NativeCurrencyAmount,
    ) {
        prop_assert_eq!(format!("{}", amount), amount.display_n_decimals(8))
    }

    #[proptest]
    fn display_large_integer_minus_epsilon_rounds_up(
        #[strategy(1_u32..42_000_000)] integer_amount: u32,
    ) {
        // Catches issue #383 [1]
        // [1]: https://github.com/Neptune-Crypto/neptune-core/issues/383

        let amount = NativeCurrencyAmount::coins(integer_amount)
            .checked_sub(&NativeCurrencyAmount::from_nau(1))
            .unwrap();
        for num_decimal_places in 0..34 {
            // note that the range 0..34 contains 8, which corresponds to
            // `amount.display()`

            let amount_as_string = amount.display_n_decimals(num_decimal_places);
            let expected_num_characters = integer_amount.to_string().len() + 1 + num_decimal_places;
            prop_assert_eq!(expected_num_characters, amount_as_string.len());

            let amount_again = NativeCurrencyAmount::coins_from_str(&amount_as_string).unwrap();
            let difference = amount
                .checked_sub(&amount_again)
                .unwrap_or_else(|| amount_again.checked_sub(&amount).unwrap());
            let mut difference_threshold = NativeCurrencyAmount::coins(1u32);
            for _ in 0..num_decimal_places {
                difference_threshold = difference_threshold.lossy_f64_fraction_mul(0.1);
            }
            difference_threshold = max(difference_threshold, NativeCurrencyAmount::from_nau(1));
            prop_assert!(difference < difference_threshold);
        }
    }
}
