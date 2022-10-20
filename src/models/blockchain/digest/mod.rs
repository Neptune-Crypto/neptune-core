pub mod ordered_digest;

use twenty_first::shared_math::rescue_prime_regular::DIGEST_LENGTH;

pub const BYTES_PER_BFE: usize = 8;
pub const DEVNET_MSG_DIGEST_SIZE_IN_BYTES: usize = 32;
pub const DEVNET_SECRET_KEY_SIZE_IN_BYTES: usize = 32;
pub const RESCUE_PRIME_DIGEST_SIZE_IN_BYTES: usize = DIGEST_LENGTH * BYTES_PER_BFE;
