use std::fmt::Display;
use std::iter::Sum;
use std::ops::Add;
use std::ops::Neg;
use std::ops::Sub;
use std::str::FromStr;

use crate::models::blockchain::type_scripts::triton_instr;
use anyhow::bail;
use arbitrary::Arbitrary;
use get_size2::GetSize;
use num_bigint::BigInt;
use num_bigint::ToBigInt;
use num_rational::BigRational;
use num_traits::CheckedAdd;
use num_traits::CheckedSub;
use num_traits::FromPrimitive;
use num_traits::One;
use num_traits::Zero;
use proptest::prelude::BoxedStrategy;
use proptest::prelude::Strategy;
use proptest_arbitrary_interop::arb;
use regex::Regex;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::native_currency::NativeCurrency;
use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

/// `NeptuneCoins` records an amount of Neptune coins. Amounts are internally represented
/// by an atomic unit called Neptune atomic units (nau), which itself is represented as a 128
/// bit integer.
///
/// 1 Neptune coin = 10^30 * 2^2 nau.
///
/// This conversion factor was chosen such that:
///  - The largest possible amount, corresponding to 42 000 000 Neptune coins, takes 127 bits.
///    The top bit is the sign bit and is used for negative amounts (in two's complement).
///  - When expanding amounts of Neptune coins in decimal form, we can represent them exactly
///    up to 30 decimal digits.
///
/// When using `NeptuneCoins` in a type script or a lock script, or even another consensus
/// program related to block validity, it is important to use `safe_add` rather than `+` as
/// the latter operation does not care about overflow. Not testing for overflow can cause
/// inflation bugs.
#[derive(Clone, Debug, Copy, Serialize, Deserialize, Eq, Default, BFieldCodec)]
pub struct NeptuneCoins(i128);

impl TasmObject for NeptuneCoins {
    fn label_friendly_name() -> String {
        "NeptuneCoins".to_owned()
    }

    fn get_field(_: &str) -> Vec<tasm_lib::triton_vm::prelude::LabelledInstruction> {
        unimplemented!()
    }

    fn get_field_with_size(_: &str) -> Vec<tasm_lib::triton_vm::prelude::LabelledInstruction> {
        unimplemented!()
    }

    fn get_field_start_with_jump_distance(
        _: &str,
    ) -> Vec<tasm_lib::triton_vm::prelude::LabelledInstruction> {
        unimplemented!()
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

        std::result::Result::Ok(Box::new(NeptuneCoins(inner)))
    }
}

impl NeptuneCoins {
    pub(crate) const MAX_NAU: i128 = 42000000 * Self::conversion_factor();

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

    /// Return the element that corresponds to 1. Use in tests only.
    pub fn one() -> NeptuneCoins {
        NeptuneCoins(1i128)
    }

    /// Create an NeptuneCoins object of the given number of coins.
    pub fn new(num_coins: u32) -> NeptuneCoins {
        assert!(
            num_coins <= 42000000,
            "Number of coins must be less than 42000000"
        );
        let number: i128 = num_coins.into();
        Self(Self::conversion_factor() * number)
    }

    pub fn div_two(&mut self) {
        self.0 /= 2;
    }

    /// Create a `coins` object for use in a UTXO
    pub fn to_native_coins(&self) -> Vec<Coin> {
        let dictionary = vec![Coin {
            type_script_hash: NativeCurrency.hash(),
            state: self.encode(),
        }];
        dictionary
    }

    /// Convert the amount to Neptune atomic units (nau) as a 64-bit floating point.
    /// Note that this function loses precision!
    pub fn to_nau_f64(&self) -> f64 {
        if self.is_zero() {
            return 0.0;
        }
        let nau = self.to_nau();
        let bit_size = nau.bits();
        let shift = if bit_size > 52 { bit_size - 52 } else { 0 };
        let (_sign, digits) = (nau >> shift).to_u64_digits();
        let top_digit = digits[0];
        let mut float = top_digit as f64;
        for _ in 0..shift {
            float *= 2.0;
        }
        float
    }

    /// Convert the amount to Neptune atomic units (nau)
    pub fn to_nau(&self) -> BigInt {
        BigInt::from_i128(self.0).unwrap()
    }

    /// Convert the number of Neptune atomic units (nau) to an amount of Neptune coins
    pub fn from_nau(nau: BigInt) -> Option<Self> {
        let (sign, digits) = nau.to_u64_digits();

        // we can't represent numbers with too many limbs
        if digits.len() > 2 {
            return None;
        }

        // flip and recurse if we are dealing with negative numbers
        if sign == num_bigint::Sign::Minus {
            let positive_nau = Self::from_nau(-nau)?;
            return Some(-positive_nau);
        }

        // pad with zeros if necessary
        let mut limbs = digits.clone();
        while limbs.len() < 2 {
            limbs.push(0);
        }

        // if the top bit is set then we can't represent this number using this struct
        if limbs.last().unwrap() >> 63 != 0 {
            return None;
        }

        // compute and return conversion
        let number = (limbs[0] as u128) | ((limbs[1] as u128) << 64);
        Some(Self(number as i128))
    }

    pub fn scalar_mul(&self, factor: u32) -> Self {
        let factor_as_i128 = factor as i128;
        let (res, overflow) = self.0.overflowing_mul(factor_as_i128);
        assert!(!overflow, "Overflow on scalar multiplication not allowed.");
        NeptuneCoins(res)
    }

    /// Multiply a coin amount with a fraction, in a lossy manner. Result is
    /// guaranteed to not exceed `self`.
    ///
    /// # Panics
    ///
    /// If the provided fraction is not between 0 and 1 (inclusive).
    pub(crate) fn lossy_f64_fraction_mul(&self, fraction: f64) -> Option<NeptuneCoins> {
        assert!((0.0..=1.0).contains(&fraction));

        if fraction == 1.0 {
            return Some(*self);
        }

        let value_as_f64 = self.0 as f64;
        let res = fraction * value_as_f64;
        let as_bigint = res
            .to_bigint()?
            .clamp(BigInt::from(0u32), BigInt::from(self.0));
        Self::from_nau(as_bigint)
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

    /// Add two [`NeptuneCoin`]s, of which at most one is negative.
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

    /// Generate tasm code for pushing this amount to the stack.
    pub(crate) fn push_to_stack(&self) -> Vec<LabelledInstruction> {
        self.encode()
            .into_iter()
            .rev()
            .map(|b| triton_instr!(push b))
            .collect()
    }
}

impl NeptuneCoins {
    pub(crate) fn abs(&self) -> Self {
        Self(self.0.abs())
    }

    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    pub(crate) fn is_positive(&self) -> bool {
        self.0.is_positive()
    }
}

impl GetSize for NeptuneCoins {
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

impl Ord for NeptuneCoins {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Add for NeptuneCoins {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sum for NeptuneCoins {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        NeptuneCoins(iter.map(|a| a.0).sum())
    }
}

impl Sub for NeptuneCoins {
    type Output = NeptuneCoins;

    fn sub(self, _rhs: Self) -> Self::Output {
        panic!("Cannot subtract `NeptuneCoin`s; use `checked_sub` instead.")
    }
}

impl CheckedSub for NeptuneCoins {
    /// Return Some(self-other) if the result is positive (or zero); otherwise
    /// return None.
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        if !self.is_negative() && !v.is_negative() && self >= v {
            Some(NeptuneCoins(self.0 - v.0))
        } else {
            None
        }
    }
}

impl CheckedAdd for NeptuneCoins {
    /// Return Some(self+other) if (there is no i128-overflow and) the result is
    /// smaller than the maximum number of nau.
    fn checked_add(&self, v: &Self) -> Option<Self> {
        self.0.checked_add(v.0).and_then(|sum| {
            if !(-Self::MAX_NAU..=Self::MAX_NAU).contains(&sum) {
                None
            } else {
                Some(Self(sum))
            }
        })
    }
}

impl Neg for NeptuneCoins {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl PartialEq for NeptuneCoins {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for NeptuneCoins {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Zero for NeptuneCoins {
    fn zero() -> Self {
        NeptuneCoins(0)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

#[derive(Debug)]
pub enum FloatConversionError {
    NaN,
    Infinity,
    Negative,
    Overflow,
    InvalidAmount,
}

impl TryFrom<f64> for NeptuneCoins {
    type Error = FloatConversionError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        let u = if value.is_nan() {
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
        let bi = BigInt::from(u);
        match Self::from_nau(bi) {
            Some(nc) => Ok(nc),
            None => Err(FloatConversionError::InvalidAmount),
        }
    }
}

impl FromStr for NeptuneCoins {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
        let ten = BigInt::from_str("10")?;
        let mut decimal_shift = BigInt::one();
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
                _ => unreachable!(),
            }
        };
        match Self::from_nau(nau) {
            Some(nc) => Ok(nc),
            None => Err(anyhow::Error::msg("invalid amount of Neptune coins")),
        }
    }
}

impl Display for NeptuneCoins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let conversion_factor = Self::conversion_factor();
        let sign = self.is_negative();
        let sign_symbol = if sign { "-" } else { "" };
        let nau = if sign { -self.0 } else { self.0 };
        let rational = (nau as f64) / (conversion_factor as f64);
        let rounded = (100.0 * rational).round();
        if rounded.is_zero() {
            write!(f, "0")
        } else {
            let mut s = format!("{}", rounded);
            while s.len() <= 2 {
                s = format!("0{s}");
            }
            let (int, flo): (&str, &str) = s.split_at(s.len() - 2);
            if flo == "00" {
                write!(f, "{}{}", sign_symbol, int)
            } else {
                write!(f, "{}{}.{}", sign_symbol, int, flo)
            }
        }
    }
}

impl<'a> Arbitrary<'a> for NeptuneCoins {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let nau: u128 = u.arbitrary()?;
        Ok(NeptuneCoins((nau as i128) >> 10))
    }
}

impl NeptuneCoins {
    pub(crate) fn arbitrary_non_negative() -> BoxedStrategy<Self> {
        arb::<u128>()
            .prop_map(|uint| NeptuneCoins((uint >> 10) as i128))
            .boxed()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::ops::ShlAssign;
    use std::str::FromStr;

    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use get_size2::GetSize;
    use itertools::Itertools;
    use num_bigint::Sign;
    use num_traits::FromPrimitive;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::prop_assume;
    use proptest_arbitrary_interop::arb;
    use rand::thread_rng;
    use rand::Rng;
    use rand::RngCore;
    use test_strategy::proptest;

    use super::*;

    impl NeptuneCoins {
        pub(crate) fn from_raw_i128(int: i128) -> Self {
            Self(int)
        }
    }

    pub(crate) fn invalid_positive_amount() -> BoxedStrategy<NeptuneCoins> {
        let i128_max = (u128::MAX >> 1) as i128;
        ((NeptuneCoins::MAX_NAU + 1)..=i128_max)
            .prop_map(NeptuneCoins)
            .boxed()
    }

    #[test]
    fn test_slice_conversion() {
        let mut rng = thread_rng();
        let sl = (0..4).map(|_| rng.next_u32() >> 1).collect_vec();
        let int = BigInt::from_slice(Sign::Plus, &sl);
        let amount = NeptuneCoins::from_nau(int.clone()).unwrap();
        assert_eq!(amount.to_nau(), int);
    }

    #[test]
    fn test_string_conversion() {
        let mut rng = thread_rng();

        for _ in 0..100 {
            let number = rng.gen_range(0..42000000);
            let amount = NeptuneCoins::new(number);
            let string = amount.to_string();
            let reconstructed_amount = NeptuneCoins::from_str(&string)
                .expect("Coult not parse as number a string generated from a number.");

            assert_eq!(amount, reconstructed_amount);
        }
    }

    #[test]
    fn test_bfe_conversion() {
        let mut rng = thread_rng();

        for _ in 0..5 {
            let amount =
                NeptuneCoins::arbitrary(&mut Unstructured::new(&rng.gen::<[u8; 32]>())).unwrap();
            let bfes = amount.encode();
            let reconstructed_amount = *NeptuneCoins::decode(&bfes).unwrap();

            assert_eq!(amount, reconstructed_amount);
        }
    }

    #[test]
    fn test_bfe_conversion_with_option_amount() {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let amount =
                NeptuneCoins::arbitrary(&mut Unstructured::new(&rng.gen::<[u8; 32]>())).unwrap();
            let bfes = Some(amount).encode();
            let reconstructed_amount = *Option::<NeptuneCoins>::decode(&bfes).unwrap();

            assert_eq!(Some(amount), reconstructed_amount);
        }

        let amount: Option<NeptuneCoins> = None;
        let bfes = amount.encode();
        let reconstructed_amount = *Option::<NeptuneCoins>::decode(&bfes).unwrap();
        assert!(reconstructed_amount.is_none());
    }

    #[test]
    fn from_coins_conversion_simple_test() {
        let a = 41000000;
        let b = 100u32;
        let a_amount: NeptuneCoins = NeptuneCoins::new(a);
        let b_amount: NeptuneCoins = NeptuneCoins::new(b);
        assert_eq!(a_amount + b_amount, NeptuneCoins::new(a + b));
    }

    #[test]
    fn from_nau_conversion_pbt() {
        let mut rng = thread_rng();
        let a: u64 = rng.gen_range(0..(1 << 63));
        let b: u64 = rng.gen_range(0..(1 << 63));
        let a_amount: NeptuneCoins = NeptuneCoins::from_nau(a.into()).unwrap();
        let b_amount: NeptuneCoins = NeptuneCoins::from_nau(b.into()).unwrap();
        assert_eq!(
            a_amount + b_amount,
            NeptuneCoins::from_nau((a + b).into()).unwrap()
        );
    }

    #[test]
    fn amount_simple_scalar_mul_test() {
        let fourteen: NeptuneCoins = NeptuneCoins::new(14);
        let fourtytwo: NeptuneCoins = NeptuneCoins::new(42);
        assert_eq!(fourtytwo, fourteen.scalar_mul(3));
    }

    #[test]
    fn simple_f64_lossy_mul_half() {
        let one_hundred = NeptuneCoins::new(100);
        let half_of_one_hundred = one_hundred.lossy_f64_fraction_mul(0.5).unwrap();

        // Assert that the value is in a reasonable range, close enough.
        assert!(
            half_of_one_hundred > NeptuneCoins::new(49)
                && half_of_one_hundred < NeptuneCoins::new(51)
        );
    }

    #[test]
    fn simple_f64_lossy_mul_zero() {
        let one_hundred = NeptuneCoins::new(100);
        assert_eq!(
            NeptuneCoins::zero(),
            one_hundred.lossy_f64_fraction_mul(0f64).unwrap()
        );
    }

    #[test]
    fn simple_f64_lossy_mul_one() {
        let one_hundred = NeptuneCoins::new(100);
        assert_eq!(
            one_hundred,
            one_hundred.lossy_f64_fraction_mul(1f64).unwrap()
        );
    }

    #[test]
    fn amount_scalar_mul_pbt() {
        let mut rng = thread_rng();
        let mut a = 6481;
        let mut b = 6481;
        while (a as u64) * (b as u64) > 42000000 {
            a = rng.gen_range(0..42000000);
            b = rng.gen_range(0..42000000);
        }

        let prod_checked: NeptuneCoins = NeptuneCoins::new(a * b);
        let mut prod_calculated: NeptuneCoins = NeptuneCoins::new(a);
        prod_calculated = prod_calculated.scalar_mul(b);
        assert_eq!(prod_checked, prod_calculated);
    }

    #[test]
    fn get_size_test() {
        let fourteen: NeptuneCoins = NeptuneCoins::new(14);
        assert_eq!(4 * 4, fourteen.get_size())
    }

    #[test]
    fn conversion_factor_is_optimal() {
        let forty_two_million = BigInt::from_i32(42000000).unwrap();
        let conversion_factor = BigInt::from_i128(NeptuneCoins::conversion_factor()).unwrap();
        let mut two_pow_127 = BigInt::one();
        two_pow_127.shl_assign(127);
        assert!(conversion_factor.clone() * forty_two_million.clone() < two_pow_127);

        // let's also test optimality:
        // adding another factor 5 or 2 will break this property
        let five = BigInt::from_i8(5).unwrap();
        let two = BigInt::from_i8(2).unwrap();
        assert!(conversion_factor.clone() * two * forty_two_million.clone() >= two_pow_127);
        assert!(conversion_factor * five * forty_two_million >= two_pow_127);
    }

    #[test]
    fn from_decimal_test() {
        let parsed = NeptuneCoins::from_str("-10.125").unwrap();
        let cf = NeptuneCoins::conversion_factor() >> 3;
        let fixed = -(NeptuneCoins::from_nau(BigInt::from_i128(cf).unwrap()).unwrap()
            + NeptuneCoins::new(10));
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
            let nc = NeptuneCoins::from_str(s)
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
                NeptuneCoins::from_str(s).is_err(),
                "valid parsing: {}; parsed to: {}",
                s,
                NeptuneCoins::from_str(s).unwrap()
            );
        }
    }

    #[proptest]
    fn small_amounts_can_be_safely_added(
        #[strategy(arb())] a0: NeptuneCoins,
        #[strategy(arb())] a1: NeptuneCoins,
    ) {
        a0.checked_add(&a1).unwrap();
    }

    #[proptest]
    fn checked_add_proptest(lhs: i128, rhs: i128) {
        let lhs = NeptuneCoins(lhs >> 1);
        let rhs = NeptuneCoins(rhs >> 1);
        prop_assert!(lhs.checked_add(&rhs).is_some());
    }

    #[proptest]
    fn checked_add_positive_overflow_proptest(rhs: u128) {
        let lhs = NeptuneCoins(NeptuneCoins::MAX_NAU);
        let rhs = NeptuneCoins((rhs >> 2) as i128);
        prop_assume!(!rhs.is_zero());
        prop_assert!(lhs.checked_add(&rhs).is_none());
    }

    #[proptest]
    fn checked_add_negative_overflow_proptest(rhs: u128) {
        let lhs = NeptuneCoins(-NeptuneCoins::MAX_NAU);
        let rhs = -NeptuneCoins((rhs >> 2) as i128);
        prop_assume!(!rhs.is_zero());
        prop_assert!(lhs.checked_add(&rhs).is_none());
    }

    #[test]
    fn checked_add_positive_overflow_unit_test() {
        let one_nau = NeptuneCoins(1);
        let max_value = NeptuneCoins(NeptuneCoins::MAX_NAU);
        assert!(max_value.checked_add(&one_nau).is_none());
        assert!(max_value.checked_add(&NeptuneCoins::zero()).is_some());
    }

    #[test]
    fn checked_add_negative_overflow_unit_test() {
        let minus_one_nau = -NeptuneCoins(1);
        let min_value = -NeptuneCoins(NeptuneCoins::MAX_NAU);
        assert!(min_value.checked_add(&minus_one_nau).is_none());
        assert!(min_value.checked_add(&NeptuneCoins::zero()).is_some());
    }

    #[test]
    fn expected_coins_static_length() {
        assert_eq!(Some(4), NeptuneCoins::static_length());
    }

    #[proptest]
    fn to_and_from_nau_identity(
        #[strategy(-NeptuneCoins::MAX_NAU..=NeptuneCoins::MAX_NAU)] num_naus: i128,
    ) {
        let val = NeptuneCoins(num_naus);
        prop_assert_eq!(val, NeptuneCoins::from_nau(val.to_nau()).unwrap());
    }

    #[proptest]
    fn scalar_mul_2_div_2_is_identity(
        #[strategy(-NeptuneCoins::MAX_NAU/2..=NeptuneCoins::MAX_NAU/2)] num_naus: i128,
    ) {
        let original = NeptuneCoins(num_naus);
        let mut calculated = original.scalar_mul(2);
        calculated.div_two();
        prop_assert_eq!(original, calculated);
    }

    #[proptest]
    fn new_and_display_consistency_proptest(#[strategy(0u32..=42000000)] num_coins: u32) {
        let val = NeptuneCoins::new(num_coins);
        assert_eq!(format!("{val}"), num_coins.to_string());
    }

    #[proptest]
    fn encode_decode_identity(val: i128) {
        let val = NeptuneCoins(val >> 1);
        prop_assert!(val == *NeptuneCoins::decode(&val.encode()).unwrap());
    }

    #[proptest]
    fn outer_ordering_agrees_with_inner(lhs: i128, rhs: i128) {
        let inner_cmp = lhs < rhs;
        let lhs = NeptuneCoins(lhs >> 1);
        let rhs = NeptuneCoins(rhs >> 1);
        let outer_cmp = lhs < rhs;
        prop_assert!(inner_cmp == outer_cmp);
    }

    #[test]
    fn unsafe_amounts_fail() {
        let a0 = NeptuneCoins(1i128 << 126);
        let a1 = NeptuneCoins(1i128 << 126);
        assert!(a0.checked_add(&a1).is_none());
    }

    #[test]
    fn scan_balance_returns_sane_result() {
        let balance_updates =
            [64, 32, 32, 64, 32, 32, 64, 32, 32, -64, 53, 64, 32, 32].map(|i: i32| {
                if i.is_negative() {
                    -NeptuneCoins::new((-i) as u32)
                } else {
                    NeptuneCoins::new(i as u32)
                }
            });
        let expected_balances = [
            64, 96, 128, 192, 224, 256, 320, 352, 384, 320, 373, 437, 469, 501,
        ]
        .map(NeptuneCoins::new)
        .to_vec();
        let computed_balances =
            NeptuneCoins::scan_balance(&balance_updates, NeptuneCoins::zero()).collect_vec();
        assert_eq!(expected_balances, computed_balances);
    }

    #[test]
    fn can_negate_zero() {
        println!("{}", -NeptuneCoins(0));
    }
}
