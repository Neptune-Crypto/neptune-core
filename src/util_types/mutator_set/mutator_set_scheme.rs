use crate::models::blockchain::shared::Hash;
use crate::prelude::twenty_first;

use twenty_first::shared_math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use super::addition_record::AdditionRecord;
/// Generates an addition record from an item and explicit random-
/// ness. The addition record is itself a commitment to the item.
pub fn commit(item: Digest, sender_randomness: Digest, receiver_digest: Digest) -> AdditionRecord {
    let canonical_commitment =
        Hash::hash_pair(Hash::hash_pair(item, sender_randomness), receiver_digest);

    AdditionRecord::new(canonical_commitment)
}
