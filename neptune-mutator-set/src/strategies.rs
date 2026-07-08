//! Proptest strategies for mutator-set types, shared by this crate's tests and
//! by downstream crates (via the `test-helpers` feature).

use itertools::Itertools;
use proptest::collection;
use proptest::prelude::*;
use proptest_arbitrary_interop::arb;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;

use crate::ms_membership_proof::MsMembershipProof;
use crate::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::removal_record::chunk::Chunk;
use crate::removal_record::chunk_dictionary::ChunkDictionary;
use crate::removal_record::RemovalRecord;
use crate::shared::NUM_TRIALS;

prop_compose! {
    pub fn chunkdict() (dictionary in collection::vec((
        any::<u64>(), collection::vec(proptest_arbitrary_interop::arb::<Digest>(), 0..6), collection::vec(any::<u32>(), 0..17),
    ), 37)) -> ChunkDictionary {
        ChunkDictionary::new(dictionary.into_iter().map(|(key, authpath, chunk)| (
            key,
            (
                MmrMembershipProof::new(authpath),
                Chunk {
                    relative_indices: chunk,
                },
            )
        )).collect_vec())
    }
}
prop_compose! {
    pub fn chunkdict_with_leafs_limit(leafs_limit: u64) (dictionary in collection::vec((
        ..=leafs_limit, collection::vec(proptest_arbitrary_interop::arb::<Digest>(), 0..6), collection::vec(any::<u32>(), 0..17),
    ), 1..=(crate::shared::NUM_TRIALS as usize))) -> ChunkDictionary {
        ChunkDictionary::new(dictionary.into_iter().map(|(key, authpath, chunk)| (
            key,
            (
                MmrMembershipProof::new(authpath),
                Chunk {
                    relative_indices: chunk,
                },
            )
        )).collect_vec())
    }
}

pub fn absindset() -> impl Strategy<Value = AbsoluteIndexSet> {
    collection::vec(
        proptest_arbitrary_interop::arb::<u8>(),
        16_usize + (NUM_TRIALS as usize) * 4,
    )
    .prop_map(|bytes| {
        <AbsoluteIndexSet as arbitrary::Arbitrary>::arbitrary(&mut arbitrary::Unstructured::new(
            &bytes,
        ))
        .unwrap()
    })
}
prop_compose! {
    pub fn absindset_with_limit(l: u64) (inner in [..=u128::from(l); NUM_TRIALS as usize]) -> AbsoluteIndexSet {
        AbsoluteIndexSet::new(inner)
    }
}

prop_compose! {
    pub fn removalrecord() (
        absolute_indices in absindset(),
        target_chunks in chunkdict()
    ) -> RemovalRecord {RemovalRecord {absolute_indices, target_chunks}}
}

prop_compose! {
    /// a pseudorandom Merkle mountain range membership proof
    pub fn mmrmembershipproof_and_index() (len in 0..15usize) (
        authentication_path in collection::vec(arb::<Digest>(), len),
        leaf_index in any::<u64>()
    ) -> (MmrMembershipProof, u64) {
        (MmrMembershipProof {authentication_path}, leaf_index)
    }
}

prop_compose! {
    /// a pseudorandom mutator set membership proof
    pub fn msmembershipproof() (
        sender_randomness in arb::<Digest>(),
        receiver_preimage in arb::<Digest>(),
        (auth_path_aocl, aocl_leaf_index) in mmrmembershipproof_and_index(),
        target_chunks in chunkdict(),
    ) -> MsMembershipProof {
        MsMembershipProof {
            sender_randomness,
            receiver_preimage,
            aocl_leaf_index,
            auth_path_aocl,
            target_chunks,
        }
    }
}
