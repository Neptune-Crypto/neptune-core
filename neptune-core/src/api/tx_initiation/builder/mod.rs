//! provides builders for generating a neptune transaction.
//!
//! these builders are quite flexible, if a little verbose to use.  The [initiator](super::initiator) and [send](super::send)
//! APIs use the builders internally.
//!
//! note that these builders support sharing an already acquired read or write lock
//! over global-state.  Or alternatively, builders that require a lock can obtain on
//! their own.  This is facilitated by [StateLock](crate::api::export::StateLock).

pub mod input_selector;
pub mod proof_builder;
pub mod transaction_builder;
pub mod transaction_details_builder;
pub mod transaction_proof_builder;
pub mod triton_vm_proof_job_options_builder;
pub mod tx_artifacts_builder;
pub mod tx_output_list_builder;
