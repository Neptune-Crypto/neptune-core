pub mod block;
pub mod shared;
pub mod transaction;
pub mod type_scripts;

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use super::*;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

    #[test]
    fn print_all_validity_program_names() {
        macro_rules! name_and_lib {
            [$($t:expr),* $(,)?] => {[$({
                let (library, _) = $t.library_and_code();
                (stringify!($t), library)
            }),*]};
        }

        let all_consensus_critical_imports = name_and_lib![
            block::validity::block_program::BlockProgram,
            transaction::validity::collect_lock_scripts::CollectLockScripts,
            transaction::validity::collect_type_scripts::CollectTypeScripts,
            transaction::validity::kernel_to_outputs::KernelToOutputs,
            transaction::validity::merge::Merge,
            type_scripts::native_currency::NativeCurrency,
            transaction::validity::removal_records_integrity::RemovalRecordsIntegrity,
            transaction::validity::single_proof::SingleProof,
            type_scripts::time_lock::TimeLock,
            transaction::validity::update::Update,
            // todo: what about those?
            // block_validity::coinbase_is_valid::CoinbaseIsValid,
            // block_validity::correct_control_parameter_update::CorrectControlParameterUpdate,
            // block_validity::correct_mmr_update::CorrectMmrUpdate,
            // block_validity::correct_mutator_set_update::CorrectMutatorSetUpdate,
            // block_validity::mmr_membership::MmrMembership,
            // block_validity::predecessor_is_valid::PredecessorIsValid,
            // block_validity::PrincipalBlockValidationLogic,
        ]
        .into_iter()
        .flat_map(|(name, lib)| [vec![format!("\n{name}")], lib.get_all_snippet_names()].concat())
        .unique()
        .join("\n");

        println!("{all_consensus_critical_imports}");
    }
}
