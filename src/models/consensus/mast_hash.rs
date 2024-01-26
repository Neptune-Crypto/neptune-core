use itertools::Itertools;
use tasm_lib::twenty_first::{
    shared_math::{b_field_element::BFieldElement, tip5::Digest},
    util_types::{
        algebraic_hasher::AlgebraicHasher,
        merkle_tree::{CpuParallel, MerkleTree},
        merkle_tree_maker::MerkleTreeMaker,
    },
};

use crate::models::blockchain::shared::Hash;

pub trait HasDiscriminant {
    fn discriminant(&self) -> usize;
}

pub trait MastHash {
    type FieldEnum: HasDiscriminant;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>>;

    fn merkle_tree(&self) -> MerkleTree<Hash> {
        let mut sequences = self.mast_sequences().to_vec();

        // pad until length is a power of two
        while sequences.len() & (sequences.len() - 1) != 0 {
            sequences.push(vec![]);
        }

        CpuParallel::from_digests(
            &sequences
                .into_iter()
                .map(|seq| Hash::hash_varlen(&seq))
                .collect_vec(),
        )
        .unwrap()
    }

    fn mast_hash(&self) -> Digest {
        self.merkle_tree().root()
    }

    fn mast_path(&self, field: Self::FieldEnum) -> Vec<Digest> {
        self.merkle_tree()
            .authentication_structure(&[field.discriminant()])
            .unwrap()
    }
}
