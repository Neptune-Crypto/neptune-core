use macro_rules_attr::apply;
use neptune_consensus::consensus_rule_set::ConsensusRuleSet;
use neptune_consensus::transaction::validity::tasm::single_proof::update_branch::test_helpers::deterministic_update_witness_additions_and_removals;
use neptune_consensus::transaction::validity::tasm::single_proof::update_branch::test_helpers::deterministic_update_witness_only_additions_to_mutator_set;
use neptune_mempool::transaction_kernel_id::Txid;

use crate::tests::shared_tokio_runtime;

#[apply(shared_tokio_runtime)]
async fn txid_is_constant_under_tx_updates_only_additions() {
    let consensus_rule_set = ConsensusRuleSet::HardforkGamma;
    let update_witness =
        deterministic_update_witness_only_additions_to_mutator_set(4, 4, 4, consensus_rule_set)
            .await;
    assert_eq!(
        update_witness.old_kernel().txid(),
        update_witness.new_kernel().txid(),
        "Txid function must agree before and after transaction update"
    );
}

#[apply(shared_tokio_runtime)]
async fn txid_is_constant_under_tx_updates_additions_and_removals() {
    let consensus_rule_set = ConsensusRuleSet::HardforkGamma;
    let update_witness =
        deterministic_update_witness_additions_and_removals(4, 4, 4, consensus_rule_set).await;
    assert_eq!(
        update_witness.old_kernel().txid(),
        update_witness.new_kernel().txid(),
        "Txid function must agree before and after transaction update"
    );
}
