use macro_rules_attr::apply;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::triton_vm::error::InstructionError;
use tasm_lib::triton_vm::isa::error::AssertionError;
use tracing_test::traced_test;

use crate::api::export::TxInputs;
use crate::api::export::TxOutputList;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::network::Network;
use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::error::CreateProofError;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::tasm::prover_job::ProverJobError;
use crate::protocol::proof_abstractions::tasm::prover_job::VmProcessError;
use crate::protocol::proof_abstractions::triton_vm_job_queue::vm_job_queue;
use crate::state::transaction::transaction_details::TransactionDetails;
use crate::tests::shared_tokio_runtime;

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn disallow_empty_transaction_with_non_zero_fee() {
    // Ensure that we cannot create a transaction with non-zero fee when
    // transaction has no inputs or outputs.
    let network = Network::Main;
    let genesis = Block::genesis(network);

    let msa = genesis.mutator_set_accumulator_after().unwrap();
    let now = network.launch_date() + Timestamp::hours(12);
    let cheated_fee = NativeCurrencyAmount::coins(100);
    let fee_tx = TransactionDetails::new_without_coinbase(
        TxInputs::default(),
        TxOutputList::default(),
        cheated_fee,
        now,
        msa.clone(),
        network,
    );

    let fee_tx = fee_tx.primitive_witness();
    let consensus_rule_set = ConsensusRuleSet::Reboot;
    let fee_sp_error = produce_single_proof(
        &fee_tx,
        vm_job_queue(),
        TritonVmProofJobOptions::default(),
        consensus_rule_set,
    )
    .await
    .unwrap_err();
    let CreateProofError::ProverJobError(ProverJobError::TritonVmProverFailed(
        VmProcessError::TritonVmFailed(InstructionError::AssertionFailed(AssertionError {
            id: error_id,
            ..
        })),
    )) = fee_sp_error
    else {
        panic!("Expected Triton VM prover error");
    };

    assert_eq!(Some(NativeCurrency::NO_INFLATION_VIOLATION), error_id);
}
