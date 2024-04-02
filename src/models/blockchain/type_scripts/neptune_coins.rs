use crate::models::{
    blockchain::transaction::utxo::Coin, consensus::tasm::program::ConsensusProgram,
};

use super::native_currency::NativeCurrency;
use anyhow::bail;
use arbitrary::Arbitrary;
use get_size::GetSize;
use num_bigint::BigInt;
use num_rational::BigRational;
use num_traits::{CheckedSub, FromPrimitive, One, Zero};
use rand::{rngs::StdRng, Rng, SeedableRng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    iter::Sum,
    ops::{Add, Mul, Neg, Sub},
    str::FromStr,
};
use tasm_lib::{
    structure::tasm_object::TasmObject, twenty_first::shared_math::bfield_codec::BFieldCodec,
};

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
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, BFieldCodec, TasmObject)]
pub struct NeptuneCoins(u128);

impl NeptuneCoins {
    /// The conversion factor is 10^30 * 2^2.
    /// It is such that 42 000 000 * 10^30 * 2^4 is just one bit shy of being 128 bits
    /// wide. The one shy bit is used for the sign.
    fn conversion_factor() -> u128 {
        let mut product = 1u128;
        let ten = 10u128;
        for _ in 0..30 {
            product = product.mul(ten)
        }
        let two = 2u128;
        for _ in 0..2 {
            product = product.mul(two);
        }
        product
    }

    /// Return the element that corresponds to 1. Use in tests only.
    pub fn one() -> NeptuneCoins {
        NeptuneCoins(1u128)
    }

    /// Create an Amount object of the given number of coins.
    pub fn new(num_coins: u32) -> NeptuneCoins {
        assert!(
            num_coins <= 42000000,
            "Number of coins must be less than 42000000"
        );
        let number: u128 = num_coins.into();
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
        BigInt::from_u128(self.0).unwrap()
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
            return Some(Self(u128::MAX - positive_nau.0 + 1u128));
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
        Some(Self(number))
    }

    pub fn is_negative(&self) -> bool {
        self.0 & (1 << 127) != 0
    }

    pub fn scalar_mul(&self, factor: u32) -> Self {
        let factor_as_u128 = factor as u128;
        NeptuneCoins(factor_as_u128 * self.0)
    }

    /// Add two amounts of Neptune coins but return None if the top bit in the sum is set
    /// (which would make the sum negative)
    pub fn safe_add(&self, other: NeptuneCoins) -> Option<NeptuneCoins> {
        let number = self.0 + other.0;
        if number & (1u128 << 127) == 0 {
            Some(NeptuneCoins(number))
        } else {
            None
        }
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
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        if self >= v {
            Some(NeptuneCoins(self.0 - v.0))
        } else {
            None
        }
    }
}

impl Neg for NeptuneCoins {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(u128::MAX - self.0 + 1u128)
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
        NeptuneCoins(0u128)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0u128
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
            let conversion_factor = BigInt::from_u128(Self::conversion_factor()).unwrap();
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
        let nau = if sign {
            u128::MAX - self.0 + 1u128
        } else {
            self.0
        };
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

pub fn pseudorandom_amount(seed: [u8; 32]) -> NeptuneCoins {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let number: u128 = rng.gen::<u128>() >> 10;
    NeptuneCoins(number)
}

impl<'a> Arbitrary<'a> for NeptuneCoins {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let nau: u128 = u.arbitrary()?;
        Ok(NeptuneCoins(nau >> 10))
    }
}

#[cfg(test)]
mod amount_tests {
    use arbitrary::{Arbitrary, Unstructured};
    use get_size::GetSize;
    use itertools::Itertools;
    use num_bigint::Sign;
    use num_traits::FromPrimitive;
    use proptest_arbitrary_interop::arb;
    use rand::{thread_rng, Rng, RngCore};
    use std::{ops::ShlAssign, str::FromStr};
    use test_strategy::proptest;

    use super::*;

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
        let conversion_factor = BigInt::from_u128(NeptuneCoins::conversion_factor()).unwrap();
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
        let fixed = -(NeptuneCoins::from_nau(BigInt::from_u128(cf).unwrap()).unwrap()
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
        a0.safe_add(a1).unwrap();
    }

    #[test]
    fn unsafe_amounts_fail() {
        let a0 = NeptuneCoins(1u128 << 126);
        let a1 = NeptuneCoins(1u128 << 126);
        assert!(a0.safe_add(a1).is_none());
    }
}
