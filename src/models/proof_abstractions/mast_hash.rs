use itertools::Itertools;
use strum::EnumCount;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::tip5::Digest;
use tasm_lib::twenty_first::prelude::MerkleTreeMaker;

use tasm_lib::twenty_first::util_types::merkle_tree::CpuParallel;
use tasm_lib::twenty_first::util_types::merkle_tree::MerkleTree;

use crate::models::blockchain::shared::Hash;

pub trait HasDiscriminant: Clone {
    fn discriminant(&self) -> usize;
    // {
    //     self.clone() as usize
    // }
}

pub trait MastHash {
    type FieldEnum: HasDiscriminant + EnumCount;

    const MAST_HEIGHT: usize = Self::FieldEnum::COUNT.next_power_of_two().ilog2() as usize;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>>;

    fn merkle_tree(&self) -> MerkleTree {
        let mut digests = self
            .mast_sequences()
            .into_iter()
            .map(|seq| Hash::hash_varlen(&seq))
            .collect_vec();

        // pad until length is a power of two
        while digests.len() & (digests.len() - 1) != 0 {
            digests.push(Digest::default());
        }

        CpuParallel::from_digests(&digests).unwrap()
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

#[cfg(test)]
mod test {
    use strum::EnumCount;
    use strum::FromRepr;

    use super::HasDiscriminant;

    #[derive(Debug, Clone, FromRepr, EnumCount, PartialEq, Eq, PartialOrd, Ord)]
    enum TestEnum {
        A,
        B,
        C,
    }

    impl HasDiscriminant for TestEnum {
        fn discriminant(&self) -> usize {
            self.clone() as usize
        }
    }

    #[test]
    fn enum_variants_are_onto_discriminants() {
        let mut variant_set = vec![];
        let mut uint_set = vec![];
        for u in 0..TestEnum::COUNT {
            let variant = TestEnum::from_repr(u).unwrap();
            variant_set.push(variant.clone());
            uint_set.push(variant.discriminant());
        }

        variant_set.sort();
        variant_set.dedup();

        uint_set.sort();
        uint_set.dedup();

        assert_eq!(variant_set.len(), TestEnum::COUNT);
        assert_eq!(uint_set.len(), TestEnum::COUNT);
    }
}
