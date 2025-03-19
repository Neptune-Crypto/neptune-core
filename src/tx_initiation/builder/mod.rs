//! Some example usage of these builders.
//!
//! -----------
//!
//! use case:  caller provides proof.
//!
//! given:
//!   1. tx_inputs:     TxInputList  (from GlobalState::select_inputs(tx_outputs.total_native_currency_amount()))
//!   2. tx_outputs:    TxOutputList
//!   3. msa:           MutatorSetAccumulator
//!   4. change_policy: ChangePolicy
//!   5. tx_proof:      TransactionProof
//!
//! let tx_details = TransactionDetailsBuilder::new()
//!  .inputs( tx_inputs )
//!  .outputs( tx_outputs )
//!  .mutator_set_accumulator(msa),
//!  .change_policy(change_policy)
//!  .build()?;
//!
//! let transaction = TransactionBuilder::new()
//!  .transaction_details(tx_details)
//!  .proof(tx_proof)
//!  .build();
//!
//! ------------
//!
//! use case: caller does not provide proof
//!
//! given:
//!   1. tx_inputs:      TxInputList  (from GlobalState::select_inputs(tx_outputs.total_native_currency_amount()))
//!   2. tx_outputs:     TxOutputList
//!   3. msa:            MutatorSetAccumulator
//!   4. change_policy:  ChangePolicy
//!   5. cli:            &CliArgs  (from GlobalStateLock)
//!   6. job_queue:      Arc<TritonVmJobQueue> (cloned from GlobalStateLock)
//!
//! let tx_details = TransactionDetailsBuilder::new()
//!  .inputs( tx_inputs )
//!  .outputs( tx_outputs )
//!  .mutator_set_accumulator(msa),
//!  .change_policy(change_policy)
//!  .build()?;
//!
//! let tx_proof = TransactionProofBuilder::new()
//!  .transaction_details(tx_details.clone())              // Rc clone
//!  .job_queue(job_queue)
//!  .proof_job_options(cli.proof_job_options())
//!  .tx_proving_capability(cli.proving_capability())
//!  .build().await?;
//!
//! let transaction = TransactionBuilder::new()
//!  .transaction_details(tx_details)
//!  .proof(tx_proof)
//!  .build();

pub mod transaction_builder;
pub mod transaction_details_builder;
pub mod transaction_proof_builder;
pub mod tx_output_list_builder;
