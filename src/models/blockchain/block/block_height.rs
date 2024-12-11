use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;
use std::ops::Sub;

use arbitrary::Arbitrary;
use get_size2::GetSize;
use num_traits::ConstZero;
use num_traits::One;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::prelude::twenty_first;

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Hash,
    BFieldCodec,
    GetSize,
    Arbitrary,
)]
pub struct BlockHeight(BFieldElement);

// Assuming a block time of 10 minutes, and a halving every three years,
// the number of blocks per halving cycle is 157680.
pub const BLOCKS_PER_GENERATION: u64 = 157680;

impl BlockHeight {
    pub fn get_generation(&self) -> u64 {
        self.0.value() / BLOCKS_PER_GENERATION
    }

    pub fn next(&self) -> Self {
        Self(self.0 + BFieldElement::one())
    }

    pub fn previous(&self) -> Self {
        Self(self.0 - BFieldElement::one())
    }

    pub const fn genesis() -> Self {
        Self(BFieldElement::ZERO)
    }

    pub fn is_genesis(&self) -> bool {
        self.0.is_zero()
    }

    pub(crate) fn arithmetic_mean(left: Self, right: Self) -> Self {
        // Calculate arithmetic mean, without risk of overflow.
        let left = left.0.value();
        let right = right.0.value();
        let ret = (left / 2) + (right / 2) + (left % 2 + right % 2) / 2;

        Self(BFieldElement::new(ret))
    }
}

impl From<BFieldElement> for BlockHeight {
    fn from(item: BFieldElement) -> Self {
        BlockHeight(item)
    }
}

impl From<BlockHeight> for BFieldElement {
    fn from(item: BlockHeight) -> BFieldElement {
        item.0
    }
}

impl From<u64> for BlockHeight {
    fn from(val: u64) -> Self {
        BlockHeight(BFieldElement::new(val))
    }
}

impl From<BlockHeight> for u64 {
    fn from(bh: BlockHeight) -> Self {
        bh.0.value()
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.value()).cmp(&(other.0.value()))
    }
}

impl Add<usize> for BlockHeight {
    type Output = BlockHeight;

    fn add(self, rhs: usize) -> Self::Output {
        Self(BFieldElement::new(self.0.value() + rhs as u64))
    }
}

impl Sub for BlockHeight {
    type Output = i128;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0.value() as i128 - rhs.0.value() as i128
    }
}

impl PartialOrd for BlockHeight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u64::from(self.0))
    }
}

#[cfg(test)]
mod test {
    use tracing_test::traced_test;

    use super::*;

    #[traced_test]
    #[tokio::test]
    async fn genesis_test() {
        assert!(BlockHeight::genesis().is_genesis());
        assert!(!BlockHeight::genesis().next().is_genesis());
    }
}
