use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::transaction_proof::TransactionProofType;
use neptune_consensus::transaction::validity::neptune_proof::Proof;
use neptune_consensus::transaction::TransactionProof;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mempool::transaction_kernel_id::TransactionKernelId;
use neptune_primitives::timestamp::Timestamp;
use neptune_wallet::change_policy::ChangePolicy;
use rand::rngs::StdRng;
use rand::RngExt;
use rand::SeedableRng;

use crate::api::tx_initiation::builder::input_selector::InputSelectionPolicy;
use crate::api::tx_initiation::builder::tx_output_list_builder::OutputFormat;
use crate::api::tx_initiation::error::CreateTxError;
use crate::api::tx_initiation::error::SendError;
use crate::api::tx_initiation::initiator::TransactionInitiator;
use crate::application::loops::main_loop::proof_upgrader::PrimitiveWitnessToSingleProof;
use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
use crate::RPCServerToMain;

impl TransactionInitiator {
    /// Increase the fee of a transaction in the mempool by `amount`, paid for
    /// by this node's wallet.
    ///
    /// Creates a "fee transaction" with no outputs other than change, and
    /// schedules a job that proves it, merges it with the target transaction,
    /// and broadcasts the result. The fee transaction itself is never shared.
    ///
    /// Returns as soon as the job is scheduled.
    pub async fn bump_fee(
        &mut self,
        target: TransactionKernelId,
        amount: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<(), BumpFeeError> {
        let job = self.bump_fee_job(target, amount, timestamp).await?;
        self.global_state_lock
            .rpc_server_to_main_tx()
            .send(RPCServerToMain::PerformTxProofUpgrade(Box::new(job)))
            .await
            .map_err(|_| SendError::NotBroadcast)?;

        Ok(())
    }

    /// Create and record the fee transaction for [`Self::bump_fee`], and
    /// return the job that completes the fee bump. The caller must run it.
    pub(crate) async fn bump_fee_job(
        &mut self,
        target: TransactionKernelId,
        amount: NativeCurrencyAmount,
        timestamp: Timestamp,
    ) -> Result<UpgradeJob, BumpFeeError> {
        if !amount.is_positive() {
            return Err(BumpFeeError::NonPositiveAmount);
        }

        // Both the fee transaction and the merger need a single proof.
        let cli = self.global_state_lock.cli();
        if !cli.network.use_mock_proof()
            && !cli
                .proving_capability()
                .can_prove(TransactionProofType::SingleProof)
        {
            return Err(BumpFeeError::CannotProve);
        }

        // Fail early, before the wallet is touched.
        self.bump_fee_target(target).await?;

        // No outputs: everything but the fee goes back to us as change.
        let fee_tx = self
            .construct_transaction_mutable_state(
                Vec::<OutputFormat>::new(),
                ChangePolicy::default(),
                amount,
                timestamp,
                false,
                InputSelectionPolicy::default(),
            )
            .await?;
        if fee_tx.details.contains_lustrations() {
            return Err(SendError::Tx(CreateTxError::RequiresLustration).into());
        }
        let fee_kernel = &fee_tx.transaction.kernel;

        // Read target again, as a block may have arrived in the meantime.
        let (target_kernel, target_single_proof) = self.bump_fee_target(target).await?;
        if target_kernel.mutator_set_hash != fee_kernel.mutator_set_hash {
            return Err(BumpFeeError::TargetNotSynced);
        }

        let (consensus_rule_set, shuffle_seed) = {
            let state = self.global_state_lock.lock_guard().await;
            let block_height = state.chain.tip().header().height;
            let seed = state.wallet_state.wallet_entropy.shuffle_seed(block_height);
            let mut rng: StdRng = SeedableRng::from_seed(seed);
            (state.consensus_rule_set(), rng.random())
        };
        if target_kernel.inputs.len() + fee_kernel.inputs.len()
            > consensus_rule_set.max_num_inputs()
            || target_kernel.outputs.len() + fee_kernel.outputs.len()
                > consensus_rule_set.max_num_outputs()
            || target_kernel.announcements.len() + fee_kernel.announcements.len()
                > consensus_rule_set.max_num_announcements()
        {
            return Err(BumpFeeError::TargetTooBig);
        }

        // Inserts the witness-backed fee transaction into the mempool, which
        // reserves its inputs but does not share it. The merged transaction
        // replaces it there. Should the fee bump fail, it is left to expire
        // like any other witness-backed transaction; no cleanup is attempted.
        self.global_state_lock
            .record_own_transaction(&fee_tx)
            .await
            .map_err(SendError::from)?;

        let primitive_witness = fee_tx.transaction.proof.clone().into_primitive_witness();
        Ok(UpgradeJob::BumpFee {
            fee_transaction: PrimitiveWitnessToSingleProof { primitive_witness },
            target_kernel,
            target_single_proof,
            shuffle_seed,
        })
    }

    /// The kernel and single proof of the mempool transaction whose fee is to
    /// be bumped.
    async fn bump_fee_target(
        &self,
        target: TransactionKernelId,
    ) -> Result<(TransactionKernel, Proof), BumpFeeError> {
        let state = self.global_state_lock.lock_guard().await;
        let Some(tx) = state.mempool().get(target) else {
            return Err(BumpFeeError::TargetNotInMempool(target));
        };
        let TransactionProof::SingleProof(single_proof) = &tx.proof else {
            return Err(BumpFeeError::TargetNotSingleProof((&tx.proof).into()));
        };
        if tx.kernel.mutator_set_hash != state.chain.tip_mutator_set_after().hash() {
            return Err(BumpFeeError::TargetNotSynced);
        }

        Ok((tx.kernel.clone(), single_proof.clone()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BumpFeeError {
    #[error("Fee must be bumped by a positive amount.")]
    NonPositiveAmount,

    #[error("Bumping a fee requires this node to be able to produce single proofs.")]
    CannotProve,

    #[error("Target transaction {0} is not in mempool.")]
    TargetNotInMempool(TransactionKernelId),

    #[error(
        "Only single proof-backed transactions can have their fees bumped. Proof type was: {0}."
    )]
    TargetNotSingleProof(TransactionProofType),

    #[error("Target transaction is not synced to the tip yet. Try again later.")]
    TargetNotSynced,

    #[error("Target transaction is too big to be merged with a fee-paying transaction.")]
    TargetTooBig,

    #[error(transparent)]
    Send(#[from] SendError),
}
