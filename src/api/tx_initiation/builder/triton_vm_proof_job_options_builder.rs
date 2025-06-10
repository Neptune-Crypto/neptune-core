//! This module implements a builder for [TritonVmProofJobOptions]

use crate::config_models::network::Network;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::tasm::prover_job::ProverJobSettings;
use crate::models::state::vm_proving_capability::VmProvingCapability;
use crate::triton_vm_job_queue::TritonVmJobPriority;

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
///     .proving_capability(TransactionProofType::SingleProof)
///     .build();
/// ```
///
/// Example: (setting all fields)
///
/// ```
/// use neptune_cash::api::export::TritonVmJobPriority;
/// use neptune_cash::api::export::Network;
/// use neptune_cash::api::export::VmProvingCapability;
/// use neptune_cash::api::export::TransactionProofType;
/// use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
///
/// let (_tx, cancel_job_rx) = tokio::sync::watch::channel(());
///
/// TritonVmProofJobOptionsBuilder::new()
///     .job_priority(TritonVmJobPriority::Normal)
///     .cancel_job_rx(cancel_job_rx)
///     .network(Network::Testnet)
///     .proving_capability(TransactionProofType::ProofCollection)
///     .build();
/// ```
#[derive(Debug, Default)]
pub struct TritonVmProofJobOptionsBuilder {
    // these are from TritonVmProofJobOptions
    job_priority: Option<TritonVmJobPriority>,
    cancel_job_rx: Option<tokio::sync::watch::Receiver<()>>,

    // these are from ProverJobSettings
    network: Option<Network>,
    vm_proving_capability: Option<VmProvingCapability>,
}

impl TritonVmProofJobOptionsBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// add template to set default values of all fields. (optional)
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
    ///     .proving_capability(TransactionProofType::SingleProof)
    ///     .build();
    /// ```
    pub fn template(mut self, template: &TritonVmProofJobOptions) -> Self {
        self.job_priority = Some(template.job_priority);
        self.cancel_job_rx = template.cancel_job_rx.clone();
        self.prover_job_settings(&template.job_settings)
    }

    /// add prover job settings (optional)
    ///
    /// this will set all fields from [ProverJobSettings] at once.
    pub fn prover_job_settings(mut self, js: &ProverJobSettings) -> Self {
        self.network = Some(js.network);
        self.vm_proving_capability = Some(js.vm_proving_capability);
        self
    }

    /// add job priority (optional)
    ///
    /// see [TritonVmProofJobOptions::job_priority].
    ///
    /// default: [TritonVmJobPriority::default()]
    pub fn job_priority(mut self, job_priority: TritonVmJobPriority) -> Self {
        self.job_priority = Some(job_priority);
        self
    }

    /// add cancel_job_rx (optional)
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
    /// use neptune_cash::api::export::TransactionProofType;
    /// use neptune_cash::api::tx_initiation::builder::transaction_proof_builder::TransactionProofBuilder;
    /// use neptune_cash::api::tx_initiation::builder::triton_vm_proof_job_options_builder::TritonVmProofJobOptionsBuilder;
    /// use neptune_cash::triton_vm_job_queue::vm_job_queue;
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
    ///             .transaction_proof_type(TransactionProofType::SingleProof)
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

    /// add network (optional)
    ///
    /// default: [Network::default()]
    pub fn network(mut self, network: Network) -> Self {
        self.network = Some(network);
        self
    }

    /// specify the machine's proving capability. (optional)
    ///
    /// It is important to set the device's [VmProvingCapability] so that weak
    /// devices will not attempt to build proofs they are not capable of.
    ///
    /// default: [VmProvingCapability::default()]
    pub fn proving_capability(
        mut self,
        vm_proving_capability: impl Into<VmProvingCapability>,
    ) -> Self {
        self.vm_proving_capability = Some(vm_proving_capability.into());
        self
    }

    /// generate the [TritonVmProofJobOptions]
    pub fn build(self) -> TritonVmProofJobOptions {
        let Self {
            job_priority,
            cancel_job_rx,
            network,
            vm_proving_capability,
        } = self;

        let job_priority = job_priority.unwrap_or_default();
        let network = network.unwrap_or_default();
        let vm_proving_capability = vm_proving_capability.unwrap_or_default();

        let job_settings = ProverJobSettings {
            network,
            vm_proving_capability,
        };

        TritonVmProofJobOptions {
            job_priority,
            job_settings,
            cancel_job_rx,
        }
    }
}
