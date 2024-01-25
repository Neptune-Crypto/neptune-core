use crate::prelude::twenty_first;

use anyhow::bail;
use get_size::GetSize;
use num_bigint::BigInt;
use num_traits::{CheckedSub, Signed, Zero};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::Display,
    iter::Sum,
    ops::{Add, Neg, Sub},
    str::FromStr,
};
use twenty_first::{amount::u32s::U32s, shared_math::bfield_codec::BFieldCodec};

use super::{native_coin::NATIVE_COIN_TYPESCRIPT_DIGEST, utxo::Coin};

pub trait AmountLike:
    Add
    + Sum
    + CheckedSub
    + Neg
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Zero
    + FromStr
    + Display
    + Copy
    + Serialize
    + DeserializeOwned
    + From<i32>
    + From<u32>
    + From<u64>
    + BFieldCodec
{
    fn scalar_mul(&self, factor: u64) -> Self;
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Sign {
    NonNegative,
    Negative,
}

impl Display for Sign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match *self {
            Self::NonNegative => "",
            Self::Negative => "-",
        };
        write!(f, "{}", s)
    }
}

pub const AMOUNT_SIZE_FOR_U32: usize = 4;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, BFieldCodec)]
pub struct Amount(pub U32s<AMOUNT_SIZE_FOR_U32>);

impl GetSize for Amount {
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

impl AmountLike for Amount {
    fn scalar_mul(&self, factor: u64) -> Self {
        let factor_as_u32s: U32s<AMOUNT_SIZE_FOR_U32> = factor.try_into().unwrap();
        Amount(factor_as_u32s * self.0)
    }
}

impl Ord for Amount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Amount {
    /// Return the element that corresponds to 1. Use in tests only.
    pub fn one() -> Amount {
        let mut values = [0u32; AMOUNT_SIZE_FOR_U32];
        values[0] = 1;
        Amount(U32s::new(values))
    }

    pub fn div_two(&mut self) {
        self.0.div_two();
    }

    pub fn to_native_coins(&self) -> Vec<Coin> {
        let dictionary = vec![Coin {
            type_script_hash: NATIVE_COIN_TYPESCRIPT_DIGEST,
            state: self.encode(),
        }];
        dictionary
    }
}

impl Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add for Amount {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Amount(iter.map(|a| a.0).sum())
    }
}

impl Sub for Amount {
    type Output = Amount;

    fn sub(self, _rhs: Self) -> Self::Output {
        panic!("Cannot subtract Amounts; use `checked_sub` instead.")
    }
}

impl CheckedSub for Amount {
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        if self >= v {
            Some(Amount(self.0 - v.0))
        } else {
            None
        }
    }
}

impl Neg for Amount {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::zero() - self
    }
}

impl PartialEq for Amount {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for Amount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Zero for Amount {
    fn zero() -> Self {
        Amount(U32s::<AMOUNT_SIZE_FOR_U32>::zero())
    }

    fn is_zero(&self) -> bool {
        self.0 == U32s::<AMOUNT_SIZE_FOR_U32>::zero()
    }
}

impl FromStr for Amount {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(big_int) = BigInt::from_str(s) {
            if big_int.is_positive() {
                Ok(Amount(U32s::<AMOUNT_SIZE_FOR_U32>::from(
                    big_int.to_biguint().unwrap(),
                )))
            } else if big_int.is_zero() {
                Ok(Amount::zero())
            } else {
                Ok(Amount::zero()
                    - Amount(U32s::<AMOUNT_SIZE_FOR_U32>::from(
                        big_int.neg().to_biguint().unwrap(),
                    )))
            }
        } else {
            bail!("Cannot parse string as amount.");
        }
    }
}

impl From<i32> for Amount {
    fn from(value: i32) -> Self {
        let mut limbs = [0u32; AMOUNT_SIZE_FOR_U32];
        if value < 0 {
            limbs[0] = -value as u32;
            -Amount(U32s::new(limbs))
        } else {
            limbs[0] = value as u32;
            Amount(U32s::new(limbs))
        }
    }
}

impl From<u32> for Amount {
    fn from(value: u32) -> Self {
        let mut limbs = [0u32; AMOUNT_SIZE_FOR_U32];
        limbs[0] = value;
        Amount(U32s::new(limbs))
    }
}

impl From<u64> for Amount {
    fn from(value: u64) -> Self {
        let mut limbs = [0u32; AMOUNT_SIZE_FOR_U32];
        limbs[0] = (value & (u32::MAX as u64)) as u32;
        limbs[1] = (value >> 32) as u32;
        Amount(U32s::new(limbs))
    }
}

pub fn pseudorandom_amount(seed: [u8; 32]) -> Amount {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let number: [u32; 4] = rng.gen();
    Amount(U32s::new(number))
}

#[cfg(test)]
mod amount_tests {
    use get_size::GetSize;
    use itertools::Itertools;
    use rand::{thread_rng, Rng, RngCore};
    use std::str::FromStr;

    use crate::models::blockchain::transaction::amount::{Amount, AmountLike};

    use super::*;

    #[test]
    fn test_string_conversion() {
        let mut rng = thread_rng();

        for _ in 0..100 {
            let limbs: [u32; AMOUNT_SIZE_FOR_U32] = (0..AMOUNT_SIZE_FOR_U32)
                .map(|_| rng.next_u32())
                .collect_vec()
                .try_into()
                .unwrap();
            let amount = Amount(U32s::new(limbs));
            let string = amount.to_string();
            let reconstructed_amount = Amount::from_str(&string)
                .expect("Coult not parse as number a string generated from a number.");

            assert_eq!(amount, reconstructed_amount);
        }
    }

    #[test]
    fn test_bfe_conversion() {
        let mut rng = thread_rng();

        for _ in 0..5 {
            let limbs: [u32; AMOUNT_SIZE_FOR_U32] = (0..AMOUNT_SIZE_FOR_U32)
                .map(|_| rng.next_u32())
                .collect_vec()
                .try_into()
                .unwrap();
            let amount = Amount(U32s::new(limbs));
            let bfes = amount.encode();
            let reconstructed_amount = *Amount::decode(&bfes).unwrap();

            assert_eq!(amount, reconstructed_amount);
        }
    }

    #[test]
    fn test_bfe_conversion_with_option_amount() {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let limbs: [u32; AMOUNT_SIZE_FOR_U32] = (0..AMOUNT_SIZE_FOR_U32)
                .map(|_| rng.next_u32())
                .collect_vec()
                .try_into()
                .unwrap();
            let amount = Some(Amount(U32s::new(limbs)));
            let bfes = amount.encode();
            let reconstructed_amount = *Option::<Amount>::decode(&bfes).unwrap();

            assert_eq!(amount, reconstructed_amount);
        }

        let amount: Option<Amount> = None;
        let bfes = amount.encode();
        let reconstructed_amount = *Option::<Amount>::decode(&bfes).unwrap();
        assert!(reconstructed_amount.is_none());
    }

    #[test]
    fn from_u64_conversion_simple_test() {
        let a: u64 = u32::MAX as u64;
        let b: u64 = 100u64;
        let a_amount: Amount = a.into();
        let b_amount: Amount = b.into();
        assert_eq!(a_amount + b_amount, (a + b).into());
    }

    #[test]
    fn from_u64_conversion_pbt() {
        let mut rng = thread_rng();
        let a: u64 = rng.gen_range(0..(1 << 63));
        let b: u64 = rng.gen_range(0..(1 << 63));
        let a_amount: Amount = a.into();
        let b_amount: Amount = b.into();
        assert_eq!(a_amount + b_amount, (a + b).into());
    }

    #[test]
    fn amount_simple_scalar_mul_test() {
        let fourteen: Amount = 14.into();
        let fourtytwo: Amount = 42.into();
        assert_eq!(fourtytwo, fourteen.scalar_mul(3));
    }

    #[test]
    fn amount_scalar_mul_pbt() {
        let mut rng = thread_rng();
        let a: u64 = rng.gen_range(0..u32::MAX as u64);
        let b: u64 = rng.gen_range(0..u32::MAX as u64);
        let prod_checked: Amount = (a * b).into();
        let mut prod_calculated: Amount = Into::<Amount>::into(a);
        prod_calculated = prod_calculated.scalar_mul(b);
        assert_eq!(prod_checked, prod_calculated);
    }

    #[test]
    fn get_size_test() {
        let fourteen: Amount = 14.into();
        assert_eq!(4 * 4, fourteen.get_size())
    }
}
