use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::block_appendix::BlockAppendix;
use super::block_body::BlockBody;
use super::block_header::BlockHeader;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;

/// The kernel of a block contains all data that is not proof data
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockKernel {
    pub header: BlockHeader,
    pub body: BlockBody,

    pub(crate) appendix: BlockAppendix,
}

impl BlockKernel {
    pub(crate) fn new(header: BlockHeader, body: BlockBody, appendix: BlockAppendix) -> Self {
        Self {
            header,
            body,
            appendix,
        }
    }
}

#[derive(Debug, Clone, EnumCount)]
pub enum BlockKernelField {
    Header,
    Body,
    Appendix,
}

impl HasDiscriminant for BlockKernelField {
    fn discriminant(&self) -> usize {
        self.clone() as usize
    }
}

impl MastHash for BlockKernel {
    type FieldEnum = BlockKernelField;

    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        let sequences = vec![
            self.header.mast_hash().encode(),
            self.body.mast_hash().encode(),
            self.appendix.encode(),
        ];
        sequences
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::prelude::Digest;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::twenty_first::prelude::MerkleTree;

    use super::*;
    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;
    use crate::models::blockchain::block::Block;
    use crate::models::proof_abstractions::timestamp::Timestamp;

    #[test]
    fn kernel_hash_calculation() {
        let block_primitive_witness = deterministic_block_primitive_witness();
        let invalid_block = Block::block_template_invalid_proof_from_witness(
            block_primitive_witness,
            Timestamp::now(),
            None,
        );
        let calculated = invalid_block.hash();
        let merkle_tree_leafs = [
            Tip5::hash_varlen(&invalid_block.header().mast_hash().encode()),
            Tip5::hash_varlen(&invalid_block.body().mast_hash().encode()),
            Tip5::hash_varlen(&invalid_block.appendix().encode()),
            Digest::default(),
        ];

        let mt = MerkleTree::par_new(&merkle_tree_leafs).unwrap();
        let expected_root = mt.root();
        assert_eq!(expected_root, calculated);
    }
}
