//! This module implements a builder for [TritonVmProofJobOptions]

use crate::application::config::network::Network;
use crate::application::config::triton_vm_env_vars::TritonVmEnvVars;
use crate::application::triton_vm_job_queue::TritonVmJobPriority;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::tasm::prover_job::ProverJobSettings;
use crate::state::transaction::tx_proving_capability::TxProvingCapability;

/// a builder for [TritonVmProofJobOptions]
///
/// Example: (using defaults)
///
/// ```
/// use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
///
/// TritonVmProofJobOptionsBuilder::new().build();
/// ```
///
/// Example: (using defaults from cli Args)
///
/// ```
/// use neptune_cash::api::export::Args;
/// use neptune_cash::api::export::TransactionProofType;
/// use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
///
/// let args = Args::default();
/// TritonVmProofJobOptionsBuilder::new()
///     .template(&args.as_proof_job_options())
///     .proof_type(TransactionProofType::SingleProof)
///     .build();
/// ```
///
/// Example: (setting all fields)
///
/// ```
/// use neptune_cash::api::export::TritonVmJobPriority;
/// use neptune_cash::api::export::Network;
/// use neptune_cash::api::export::TxProvingCapability;
/// use neptune_cash::api::export::TransactionProofType;
/// use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
///
/// let (_tx, cancel_job_rx) = tokio::sync::watch::channel(());
///
/// TritonVmProofJobOptionsBuilder::new()
///     .job_priority(TritonVmJobPriority::Normal)
///     .cancel_job_rx(cancel_job_rx)
///     .max_log2_padded_height_for_proofs(23)  // 2^23
///     .network(Network::Testnet(0))
///     .proving_capability(TxProvingCapability::ProofCollection)
///     .proof_type(TransactionProofType::PrimitiveWitness)
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct TritonVmProofJobOptionsBuilder {
    // these are from TritonVmProofJobOptions
    job_priority: Option<TritonVmJobPriority>,
    cancel_job_rx: Option<tokio::sync::watch::Receiver<()>>,

    // these are from ProverJobSettings
    max_log2_padded_height_for_proofs: Option<u8>,
    network: Option<Network>,
    tx_proving_capability: Option<TxProvingCapability>,
    proof_type: Option<TransactionProofType>,
    triton_vm_env_vars: TritonVmEnvVars,
}

impl TritonVmProofJobOptionsBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// add template to set default values of all fields.
    ///
    /// in particular cli_args::Args can be used for this purpose.
    ///
    /// Example:
    ///
    /// ```
    /// use neptune_cash::api::export::Args;
    /// use neptune_cash::api::export::TransactionProofType;
    /// use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    ///
    /// let args = Args::default();
    /// TritonVmProofJobOptionsBuilder::new()
    ///     .template(&args.as_proof_job_options())
    ///     .proof_type(TransactionProofType::SingleProof)
    ///     .build();
    /// ```
    pub fn template(mut self, template: &TritonVmProofJobOptions) -> Self {
        self.job_priority = Some(template.job_priority);
        self.cancel_job_rx = template.cancel_job_rx.clone();
        self.prover_job_settings(&template.job_settings)
    }

    /// add prover job settings
    ///
    /// this will set all fields from [ProverJobSettings] at once.
    pub fn prover_job_settings(mut self, js: &ProverJobSettings) -> Self {
        self.max_log2_padded_height_for_proofs = js.max_log2_padded_height_for_proofs;
        self.network = Some(js.network);
        self.tx_proving_capability = Some(js.tx_proving_capability);
        self.proof_type = Some(js.proof_type);
        self.triton_vm_env_vars = js.triton_vm_env_vars.clone();
        self
    }

    /// add job priority
    ///
    /// see [TritonVmProofJobOptions::job_priority].
    ///
    /// default: [TritonVmJobPriority::default()]
    pub fn job_priority(mut self, job_priority: TritonVmJobPriority) -> Self {
        self.job_priority = Some(job_priority);
        self
    }

    /// add cancel_job_rx
    ///
    /// see [TritonVmProofJobOptions::cancel_job_rx].
    ///
    /// default: None
    ///
    /// Example:
    ///
    /// ```
    /// use neptune_cash::api::export::TransactionDetails;
    /// use neptune_cash::api::export::TransactionProof;
    /// use neptune_cash::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    /// use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    /// use neptune_cash::application::triton_vm_job_queue::vm_job_queue;
    /// use std::time::Duration;
    ///
    /// async fn prove_with_timeout(tx_details: TransactionDetails, timeout: Duration) -> anyhow::Result<TransactionProof> {
    ///
    ///     // create job cancellation channel
    ///     let (cancel_job_tx, cancel_job_rx) = tokio::sync::watch::channel(());
    ///
    ///     // create proof job options, providing cancellation receiver.
    ///     let options = TritonVmProofJobOptionsBuilder::new()
    ///         .cancel_job_rx(cancel_job_rx)
    ///         .build();
    ///
    ///     // create future for building the proof
    ///     let build_future =
    ///         TransactionProofBuilder::new()
    ///             .transaction_details(&tx_details)
    ///             .job_queue(vm_job_queue())
    ///             .proof_job_options(options)
    ///             .build();
    ///
    ///     // start building proof and cancel job if it has not completed
    ///     // after 10 seconds elapse.
    ///     tokio::select! {
    ///         _ = tokio::time::sleep(timeout) => {
    ///             cancel_job_tx.send(());
    ///             anyhow::bail!("proving exceeded timeout. job cancelled.")
    ///         }
    ///         result = build_future => {
    ///             Ok(result?)
    ///         }
    ///     }
    /// }
    /// ```
    pub fn cancel_job_rx(mut self, cancel_job_rx: tokio::sync::watch::Receiver<()>) -> Self {
        self.cancel_job_rx = Some(cancel_job_rx);
        self
    }

    /// add max_log2_padded_height_for_proofs
    ///
    /// see [cli_args::Args::max_log2_padded_height_for_proofs](crate::application::config::cli_args::Args::max_log2_padded_height_for_proofs).
    ///
    /// default: None (no limit)
    pub fn max_log2_padded_height_for_proofs(mut self, max: u8) -> Self {
        self.max_log2_padded_height_for_proofs = Some(max);
        self
    }

    /// add network
    ///
    /// default: [Network::default()]
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// specify the machine's proving capability.
    ///
    /// It is important to set the device's [TxProvingCapability] so that weak
    /// devices will not attempt to build proofs they are not capable of.
    ///
    /// default: [TxProvingCapability::default()]
    pub fn proving_capability(mut self, tx_proving_capability: TxProvingCapability) -> Self {
        self.tx_proving_capability = Some(tx_proving_capability);
        self
    }

    /// specify the target proof type.
    ///
    /// Usually it is desirable build the best proof the hardware is capable of.
    /// Therefore this field defaults to the proving-capability if not provided.
    ///
    /// default: [Self::proving_capability()]
    pub fn proof_type(mut self, proof_type: TransactionProofType) -> Self {
        self.proof_type = Some(proof_type);
        self
    }

    /// generate the [TritonVmProofJobOptions]
    pub fn build(self) -> TritonVmProofJobOptions {
        let Self {
            job_priority,
            cancel_job_rx,
            max_log2_padded_height_for_proofs,
            network,
            tx_proving_capability,
            proof_type,
            triton_vm_env_vars,
        } = self;

        let job_priority = job_priority.unwrap_or_default();
        let network = network.unwrap_or_default();
        let tx_proving_capability = tx_proving_capability.unwrap_or_default();
        let proof_type = proof_type.unwrap_or(tx_proving_capability.into());

        let job_settings = ProverJobSettings {
            max_log2_padded_height_for_proofs,
            network,
            tx_proving_capability,
            proof_type,
            triton_vm_env_vars,
        };

        TritonVmProofJobOptions {
            job_priority,
            job_settings,
            cancel_job_rx,
        }
    }
}
