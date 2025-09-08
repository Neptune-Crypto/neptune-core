use std::sync::OnceLock;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::library::Library;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use self::coinbase_is_valid::CoinbaseIsValid;
use self::correct_control_parameter_update::CorrectControlParameterUpdate;
use self::correct_mmr_update::CorrectMmrUpdate;
use self::correct_mutator_set_update::CorrectMutatorSetUpdate;
use self::mmr_membership::MmrMembership;
use self::predecessor_is_valid::PredecessorIsValid;
use super::Block;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

pub mod block_primitive_witness;
pub mod block_program;
pub mod block_proof_witness;
pub mod coinbase_is_valid;
pub mod correct_control_parameter_update;
pub mod correct_mmr_update;
pub mod correct_mutator_set_update;
pub mod mmr_membership;
pub mod predecessor_is_valid;

/// The validity of a block, in the principal case, decomposes into these subclaims.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct PrincipalBlockValidationLogic {
    // program: recursive-verify-or-is-genesis, input: block kernel, output: []
    pub predecessor_is_valid: PredecessorIsValid,

    // program: verify-coinbase, input: block kernel, output: []
    pub coinbase_is_valid: CoinbaseIsValid,

    // program: update-mutator-set, input: block kernel, output: []
    pub correct_mutator_set_update: CorrectMutatorSetUpdate,

    // program: update-mmr, input: block kernel, output: []
    pub correct_mmr_update: CorrectMmrUpdate,

    // program: update-control-parameters, input: block kernel, output: []
    pub correct_control_parameter_update: CorrectControlParameterUpdate,
}

/// Alternatively, the validity of a block follows from that of a successor. This pathway
/// two subclaims, both of which are relative to the successor block.
///  1. the current block lives in the block mmr of the successor block
///  2. the successor block is valid
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct AlternativeBlockValidationLogic {
    pub mmr_membership: MmrMembership,
    pub successor_is_valid: PrincipalBlockValidationLogic,
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalBlockValidationWitness {
    pub successor: Block, // includes proof
}

impl SecretWitness for PrincipalBlockValidationWitness {
    fn standard_input(&self) -> PublicInput {
        todo!()
    }

    fn program(&self) -> Program {
        todo!()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        todo!()
    }
}

impl ConsensusProgram for PrincipalBlockValidationLogic {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        todo!()
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;

    impl ConsensusProgramSpecification for PrincipalBlockValidationLogic {
        fn source(&self) {
            todo!()
        }
    }
}
