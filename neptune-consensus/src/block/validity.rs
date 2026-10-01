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
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

mod apply_addition_record;
mod apply_addition_records;
pub mod block_primitive_witness;
pub mod block_program;
pub mod block_proof_witness;
mod block_subsidy;
mod chunk_insertions;
mod chunk_witness;
pub mod coinbase_is_valid;
mod copy_words;
pub mod correct_control_parameter_update;
pub mod correct_mmr_update;
pub mod correct_mutator_set_update;
pub mod correct_swbfi_update;
pub mod difficulty_control;
mod divined_chunk_indices;
pub mod epoch_table;
mod guesser_fee_addition_records;
mod hash_chunk_with_insertions;
mod hash_words;
mod insert_into_window;
mod meets_threshold;
pub mod mmr_membership;
mod mutate_swbfi_peaks;
mod mutator_set_hash;
mod mutator_set_hash_after_removals;
mod mutator_set_update_from_state_hash;
pub mod predecessor_is_valid;
mod removal_index_commitment;
mod removal_record_pointers;
mod removal_records_are_unique;
mod removal_records_are_unspent;
mod resolve_chunk_indices;
// Kept for the benchmark in `update_tree_leaf`; no program uses it.
#[cfg(test)]
mod roots_from_authentication_struct;
mod sorted_window_indices;
mod swbfi_peaks_after_removals;
pub mod swbfi_update_aggregation;
pub mod swbfi_update_union;
mod update_tree_leaf;
mod window_after_removals;

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

impl TritonProgram for PrincipalBlockValidationLogic {
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
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;

    impl TritonProgramSpecification for PrincipalBlockValidationLogic {
        fn source(&self) {
            todo!()
        }
    }
}
