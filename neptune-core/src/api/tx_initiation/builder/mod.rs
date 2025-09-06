//! provides builders for generating a neptune transaction.
//!
//! these builders are quite flexible, if a little verbose to use.  The [initiator](super::initiator) and [send](super::send)
//! APIs use the builders internally.
//!
//! note that these builders support sharing an already acquired read or write lock
//! over global-state.  Or alternatively, builders that require a lock can obtain on
//! their own.  This is facilitated by [StateLock](crate::api::export::StateLock).
//!
//! Here is a typical transaction initiation sequence using the builder API.
//!
//! note: the above example fn is copied from the implementation of [TransactionSender::send()](super::send::TransactionSender::send()).
//!
//! ```rust
//! # use std::sync::Arc;
//! # use neptune_cash::application::triton_vm_job_queue::vm_job_queue;
//! # use neptune_cash::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
//! # use neptune_cash::api::tx_initiation::builder::transaction_details_builder::TransactionDetailsBuilder;
//! # use neptune_cash::api::tx_initiation::builder::transaction_builder::TransactionBuilder;
//! # use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
//! # use neptune_cash::api::tx_initiation::builder::tx_artifacts_builder::TxCreationArtifactsBuilder;
//! # use neptune_cash::api::tx_initiation::builder::tx_output_list_builder::TxOutputListBuilder;
//! # use neptune_cash::api::tx_initiation::builder::tx_input_list_builder::TxInputListBuilder;
//! # use neptune_cash::api::export::TransactionProofType;
//! # use neptune_cash::api::export::ReceivingAddress;
//! # use neptune_cash::api::export::NativeCurrencyAmount;
//! # use neptune_cash::api::export::ChangePolicy;
//! # use neptune_cash::api::export::GlobalStateLock;
//! # use neptune_cash::api::export::InputSelectionPolicy;
//! # use neptune_cash::api::export::StateLock;
//! # use neptune_cash::api::export::Timestamp;
//! # use neptune_cash::api::export::TxCreationArtifacts;
//!
//! async fn send_transaction(gsl: &mut GlobalStateLock, recipient: ReceivingAddress, amount: NativeCurrencyAmount, change_policy: ChangePolicy, fee: NativeCurrencyAmount) -> anyhow::Result<TxCreationArtifacts> {
//!
//!    // acquire lock.  write-lock is only needed if we must generate a
//!    // new change receiving address.  However, that is also the most common
//!    // scenario.
//!    let mut state_lock = match change_policy {
//!        ChangePolicy::RecoverToNextUnusedKey { .. } => StateLock::write_guard(gsl).await,
//!        _ => StateLock::read_guard(gsl).await,
//!    };
//!
//!    let timestamp = Timestamp::now();
//!
//!    // generate outputs
//!    let tx_outputs = TxOutputListBuilder::new()
//!        .output((recipient, amount))
//!        .build(&state_lock)
//!        .await;
//!
//!    // select inputs
//!    let tx_inputs = TxInputListBuilder::new()
//!        .spendable_inputs(
//!            state_lock
//!                .gs()
//!                .wallet_spendable_inputs(timestamp)
//!                .await
//!                .into_iter()
//!                .collect(),
//!        )
//!        .policy(InputSelectionPolicy::Random)
//!        .spend_amount(tx_outputs.total_native_coins() + fee)
//!        .build();
//!
//!    // generate tx details (may add change output)
//!    let tx_details = TransactionDetailsBuilder::new()
//!        .timestamp(timestamp)
//!        .inputs(tx_inputs.into_iter().into())
//!        .outputs(tx_outputs)
//!        .fee(fee)
//!        .change_policy(change_policy)
//!        .build(&mut state_lock)
//!        .await?;
//!    drop(state_lock); // release lock asap.
//!
//!    // use cli options for building proof, but override proof-type
//!    let options = TritonVmProofJobOptionsBuilder::new()
//!        .template(&gsl.cli().into())
//!        .proof_type(TransactionProofType::PrimitiveWitness)
//!        .build();
//!
//!    // generate simplistic PrimitiveWitness "proof"
//!    // This exposes secrets, so tx cannot be broadcast until
//!    // proof is upgraded to ProofCollection.
//!    let proof = TransactionProofBuilder::new()
//!        .transaction_details(&tx_details)
//!        .job_queue(vm_job_queue())
//!        .proof_job_options(gsl.cli().into())
//!        .build()
//!        .await?;
//!
//!    // assemble transaction
//!    let transaction = TransactionBuilder::new()
//!        .transaction_details(&tx_details)
//!        .transaction_proof(proof)
//!        .build()?;
//!
//!    // assemble artifacts
//!    let artifacts = TxCreationArtifactsBuilder::new()
//!        .transaction_details(tx_details)
//!        .transaction(transaction)
//!        .build()?;
//!
//!    // record and broadcast tx
//!    gsl.api().tx_initiator()
//!        .record_and_broadcast_transaction(&artifacts)
//!        .await?;
//!
//!    Ok(artifacts)
//! }
//! ```
//!
//! # case: Client generates `SingleProof` outside neptune-core
//!
//! In this case the proof generation step can be changed to:
//!
//! ```
//! # use std::sync::Arc;
//! # use neptune_cash::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
//! # use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
//! # use neptune_cash::api::export::TransactionProofType;
//! # use neptune_cash::api::export::TransactionProof;
//! # use neptune_cash::api::export::TransactionDetails;
//! # use neptune_cash::api::export::GlobalStateLock;
//! # use neptune_cash::application::triton_vm_job_queue::vm_job_queue;
//!
//! # async fn example(tx_details: TransactionDetails, gsl: GlobalStateLock) -> anyhow::Result<TransactionProof> {
//!
//! // specify target proof-type = SingleProof
//! let options = TritonVmProofJobOptionsBuilder::new()
//!     .template(&gsl.cli().into())
//!     .proof_type(TransactionProofType::SingleProof)
//!     .build();
//!
//! // This will take minutes even on a very powerful machine.
//! let proof = TransactionProofBuilder::new()
//!     .transaction_details(&tx_details)
//!     .job_queue(vm_job_queue())
//!     .proof_job_options(options)
//!     .build()
//!     .await?;
//! # Ok(proof)
//! # }
//! ```
pub mod proof_builder;
pub mod transaction_builder;
pub mod transaction_details_builder;
pub mod transaction_proof_builder;
pub mod triton_vm_proof_job_options_builder;
pub mod tx_artifacts_builder;
pub mod tx_input_list_builder;
pub mod tx_output_list_builder;
