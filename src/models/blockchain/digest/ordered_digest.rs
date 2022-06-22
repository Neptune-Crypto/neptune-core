use serde::Serialize;
use twenty_first::shared_math::b_field_element::BFieldElement;

use super::{Digest, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES};

// The data structure `RescuePrimeDigest` is primarily needed, so we can make
// database keys out of rescue prime digests.
#[derive(Clone, Copy, Debug, Serialize, serde::Deserialize, PartialEq)]
pub struct OrderedDigest([BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);

// Digest needs a partial ordering for the mining/PoW process, to check if
// a digest is below the difficulty threshold.
impl PartialOrd for OrderedDigest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        for i in 0..RESCUE_PRIME_OUTPUT_SIZE_IN_BFES {
            if self.0[i].value() != other.0[i].value() {
                return self.0[i].value().partial_cmp(&other.0[i].value());
            }
        }

        None
    }
}

impl OrderedDigest {
    pub const fn new(digest: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]) -> Self {
        Self(digest)
    }
}

impl From<Digest> for OrderedDigest {
    fn from(digest: Digest) -> Self {
        Self(digest.values())
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn digest_ordering() {
        let val0 = OrderedDigest::new([BFieldElement::new(0); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);
        let val1 = OrderedDigest::new([
            BFieldElement::new(14),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
            BFieldElement::new(0),
        ]);
        assert!(val0 < val1);

        let val2 = OrderedDigest::new([BFieldElement::new(14); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);
        assert!(val2 > val1);
        assert!(val2 > val0);

        let val3 = OrderedDigest::new([
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(15),
        ]);
        assert!(val3 > val2);
        assert!(val3 > val1);
        assert!(val3 > val0);

        let val4 = OrderedDigest::new([
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(14),
            BFieldElement::new(15),
            BFieldElement::new(14),
        ]);
        assert!(val4 > val3);
        assert!(val4 > val2);
        assert!(val4 > val1);
        assert!(val4 > val0);
    }
}
