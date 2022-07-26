use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::Display,
    ops::{Add, Sub},
};
use twenty_first::shared_math::b_field_element::BFieldElement;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeight(BFieldElement);

// Assuming a block time of 10 minutes, and a halving every three years,
// the number of blocks per halving cycle is 157680.
pub const BLOCKS_PER_GENERATION: u64 = 157680;

impl BlockHeight {
    pub fn get_generation(&self) -> u64 {
        self.0.value() / BLOCKS_PER_GENERATION
    }

    pub fn next(&self) -> Self {
        Self(self.0 + BFieldElement::ring_one())
    }

    pub fn previous(&self) -> Self {
        Self(self.0 - BFieldElement::ring_one())
    }

    pub const fn genesis() -> Self {
        Self(BFieldElement::ring_zero())
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
        write!(f, "{}", self.0)
    }
}
