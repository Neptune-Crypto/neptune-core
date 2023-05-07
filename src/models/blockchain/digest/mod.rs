pub mod ordered_digest;

use twenty_first::shared_math::digest::DIGEST_LENGTH;

pub const BYTES_PER_BFE: usize = 8;
pub const RESCUE_PRIME_DIGEST_SIZE_IN_BYTES: usize = DIGEST_LENGTH * BYTES_PER_BFE;
