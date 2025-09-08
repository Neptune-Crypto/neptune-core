pub mod block;
pub mod consensus_rule_set;
pub mod transaction;
pub mod type_scripts;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use itertools::Itertools;

    use super::*;
    use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

    #[test]
    fn print_all_validity_program_names() {
        macro_rules! name_and_lib {
            [$($t:expr),* $(,)?] => {[$({
                let (library, _) = $t.library_and_code();
                let snippet_names = library
                    .get_all_snippet_names()
                    .into_iter()
                    .map(annotate_with_sign_off_status)
                    .collect_vec();
                (stringify!($t), snippet_names)
            }),*]};
        }

        /// Annotate a snippet name with a somewhat dramatic visualization of the
        /// sign-off status.
        fn annotate_with_sign_off_status(name: String) -> String {
            let Some(snippet) = tasm_lib::exported_snippets::name_to_snippet(&name) else {
                return format!("⚠ {name}");
            };

            let sign_offs = snippet.sign_offs();
            if sign_offs.is_empty() {
                return format!("🅾 {name}");
            }

            format!("{} {name}", sign_offs.len())
        }

        let all_consensus_critical_imports = name_and_lib![
            block::validity::block_program::BlockProgram,
            transaction::validity::collect_lock_scripts::CollectLockScripts,
            transaction::validity::collect_type_scripts::CollectTypeScripts,
            transaction::validity::kernel_to_outputs::KernelToOutputs,
            type_scripts::native_currency::NativeCurrency,
            transaction::validity::removal_records_integrity::RemovalRecordsIntegrity,
            transaction::validity::single_proof::SingleProof,
            type_scripts::time_lock::TimeLock,
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
        .flat_map(|(name, snippet_names)| [vec![format!("\n{name}")], snippet_names].concat())
        .unique()
        .join("\n");

        println!("{all_consensus_critical_imports}");
    }
}
