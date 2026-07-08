use std::cmp::min;
use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::Add;
use std::ops::Sub;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use num_traits::ConstZero;
use num_traits::One;
use num_traits::Zero;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

/// The distance, in number of blocks, to the genesis block.
///
/// This struct wraps around a [`BFieldElement`], so the maximum block height
/// is P-1 = 2^64 - 2^32. With an average block time of 588 seconds, this
/// maximum will be reached roughly 344 trillion years after launch. Not urgent.
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
    TasmObject,
    GetSize,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct BlockHeight(BFieldElement);

// Assuming a block time of 588 seconds, and a halving every three years,
// the number of blocks per halving cycle is 160815.
pub const BLOCKS_PER_GENERATION: u64 = 160815;
pub const NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT: u64 = 21310;

impl BlockHeight {
    pub const MAX: u64 = BFieldElement::MAX;

    pub const fn new(value: BFieldElement) -> Self {
        Self(value)
    }

    pub const fn value(&self) -> u64 {
        self.0.value()
    }

    pub fn get_generation(&self) -> u64 {
        self.0
            .value()
            .saturating_add(NUM_BLOCKS_SKIPPED_BECAUSE_REBOOT)
            / BLOCKS_PER_GENERATION
    }

    pub fn next(&self) -> Self {
        Self(self.0 + BFieldElement::one())
    }

    pub fn previous(&self) -> Option<Self> {
        if self.is_genesis() {
            None
        } else {
            Some(Self(self.0 - BFieldElement::one()))
        }
    }

    pub const fn genesis() -> Self {
        Self(BFieldElement::ZERO)
    }

    pub fn is_genesis(&self) -> bool {
        self.0.is_zero()
    }

    pub fn arithmetic_mean(left: Self, right: Self) -> Self {
        // Calculate arithmetic mean, without risk of overflow.
        let left = left.0.value();
        let right = right.0.value();
        let ret = (left / 2) + (right / 2) + (left % 2 + right % 2) / 2;

        Self(BFieldElement::new(ret))
    }

    /// Subtract a number from a block height.
    //
    // *NOT* implemented as trait `CheckedSub` because of type mismatch.
    pub fn checked_sub(&self, v: u64) -> Option<Self> {
        self.0.value().checked_sub(v).map(|x| x.into())
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
        BlockHeight(BFieldElement::new(min(BFieldElement::MAX, val)))
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
        i128::from(self.0.value()) - i128::from(rhs.0.value())
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

impl Distribution<BlockHeight> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BlockHeight {
        let height = rng.random::<BFieldElement>();
        BlockHeight::new(height)
    }
}
