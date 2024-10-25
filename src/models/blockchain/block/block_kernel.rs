use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::block_appendix::BlockAppendix;
use super::block_body::BlockBody;
use super::block_header::BlockHeader;
use super::validity::transaction_is_valid::TransactionIsValid;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

/// The kernel of a block contains all data that is not proof data
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct BlockKernel {
    pub header: BlockHeader,
    pub body: BlockBody,

    pub(crate) appendix: BlockAppendix,
}

impl BlockKernel {
    pub(crate) fn new(header: BlockHeader, body: BlockBody) -> Self {
        // todo: populate appendix properly
        let transaction_is_valid_claim = Claim::new(TransactionIsValid.hash())
            .with_input(body.mast_hash().reversed().values().to_vec());
        let appendix = BlockAppendix::new(vec![transaction_is_valid_claim]);
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
