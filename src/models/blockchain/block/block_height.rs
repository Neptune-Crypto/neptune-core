use db_key::Key;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt::Display};
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

impl Key for BlockHeight {
    fn from_u8(key: &[u8]) -> Self {
        // First convert the slice to an array and verify that the length is correct
        let array: [u8; 8] = key
            .to_vec()
            .try_into()
            .expect("slice with incorrect length used as block height");

        // Then convert the array to a B field element and wrap in type constructore
        Self(array.into())
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        let array: [u8; 8] = self.0.into();
        f(&array)
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.value()).cmp(&(other.0.value()))
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
