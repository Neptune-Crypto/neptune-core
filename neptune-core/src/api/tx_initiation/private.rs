// private module. module docs not needed.
use std::sync::Arc;

use super::error;
use crate::protocol::consensus::transaction::transaction_proof::TransactionProofType;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::GlobalStateLock;
use crate::RPCServerToMain;

pub(super) struct TransactionInitiatorPrivate {
    global_state_lock: GlobalStateLock,
}

impl TransactionInitiatorPrivate {
    pub(super) fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    // note: not pub, as one should never call broadcast without
    // recording first.
    pub(super) async fn broadcast_transaction(
        &self,
        transaction: Arc<Transaction>,
    ) -> Result<(), error::SendError> {
        // Send BroadcastTx message to main
        let response = self
            .global_state_lock
            .rpc_server_to_main_tx()
            .send(RPCServerToMain::BroadcastTx(transaction))
            .await;

        if let Err(e) = response {
            tracing::error!("Could not send Tx to main task: error: {}", e.to_string());
            return Err(error::SendError::NotBroadcast);
        };

        Ok(())
    }

    pub(super) async fn check_proceed_with_send(
        &self,
        fee: NativeCurrencyAmount,
    ) -> Result<(), error::SendError> {
        if self.global_state_lock.cli().no_transaction_initiation {
            tracing::warn!(
                "Cannot initiate transaction because `--no-transaction-initiation` flag is set."
            );
            return Err(error::SendError::Unsupported);
        }

        // abort early on negative fee
        if fee.is_negative() {
            tracing::warn!("Cannot send negative-fee transaction.");
            return Err(error::CreateTxError::NegativeFee.into());
        }

        let capability = self.global_state_lock.cli().proving_capability();
        let proof_type = TransactionProofType::ProofCollection;
        let network = self.global_state_lock.cli().network;
        if !network.use_mock_proof() && !capability.can_prove(proof_type) {
            tracing::warn!(
                "Cannot initiate transaction because transaction proving capability is too weak."
            );
            return Err(error::CreateProofError::TooWeak {
                proof_type,
                capability,
            }
            .into());
        }

        self.check_rate_limit().await
    }

    // check if send would exceed the send rate-limit (per block)
    pub(super) async fn check_rate_limit(&self) -> Result<(), error::SendError> {
        // send rate limiting only applies below height 25000
        // which is approx 5.6 months after launch.
        // after that, the training wheel come off.
        const RATE_LIMIT_UNTIL_HEIGHT: u64 = 25000;
        let state = self.global_state_lock.lock_guard().await;

        if state.chain.light_state().header().height < RATE_LIMIT_UNTIL_HEIGHT.into() {
            const RATE_LIMIT: usize = 2;
            let tip_digest = state.chain.light_state().hash();
            let send_count_at_tip = state
                .wallet_state
                .count_sent_transactions_at_block(tip_digest)
                .await;
            tracing::debug!(
                "send-tx rate-limit check:  found {} sent-tx at current tip.  limit = {}",
                send_count_at_tip,
                RATE_LIMIT
            );
            if send_count_at_tip >= RATE_LIMIT {
                let height = state.chain.light_state().header().height;
                let e = error::SendError::RateLimit {
                    height,
                    tip_digest,
                    max: RATE_LIMIT,
                };
                tracing::warn!("{}", e.to_string());
                return Err(e);
            }
        }
        Ok(())
    }
}
