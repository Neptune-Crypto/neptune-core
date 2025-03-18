// private module.  no need for module docs.

use tasm_lib::prelude::Digest;

use super::error::RegTestError;
use crate::api::export::Timestamp;
use crate::models::blockchain::block::mock_block_generator::MockBlockGenerator;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::GlobalStateLock;
use crate::RPCServerToMain;

/// provides an API for interacting with regtest mode
#[derive(Debug)]
pub struct RegTest {
    worker: RegTestPrivate,
}

impl From<GlobalStateLock> for RegTest {
    fn from(gsl: GlobalStateLock) -> Self {
        Self {
            worker: RegTestPrivate::new(gsl),
        }
    }
}

// these methods just call a worker method, so the public API
// is easy to read and digest.  Please keep it that way.
//
// future methods are planned. see:
//
// https://github.com/Neptune-Crypto/neptune-core/issues/539
//
// they will provide functionality similar to bitcoin-core, eg:
//
// generatetoaddress: This RPC creates a specified number of blocks and sends the block rewards to a provided address, enabling rapid chain advancement for testing.
// generate: This RPC mines a specified number of blocks, but offers less control over the recipient address compared to generatetoaddress.
// generateblock: This RPC mines a block and allows the caller to specify the block template.
// setmocktime: This RPC allows manual manipulation of the blockchain's apparent timestamp, facilitating testing of time-sensitive consensus rules.
// invalidateblock: This RPC removes a block from the current best chain, enabling the simulation of blockchain reorganizations.
// reconsiderblock: This RPC reconsiders whether a block should be part of the best chain, often used in conjunction with invalidateblock to test chain selection logic.
//
impl RegTest {
    /// mine a series of blocks to the node's wallet. (regtest network only)
    ///
    /// These blocks can be generated quickly because they do not have
    /// a real ZK proof.  they have a mock "proof" that is simply trusted
    /// by recipients and will validate without error.
    ///
    /// Mock proofs are allowed only on the regtest network, for development purposes.
    ///
    /// The timestamp of each block will be the current system time, meaning
    /// that they will be temporally very close to eachother.
    pub async fn mine_regtest_blocks_to_wallet(
        &mut self,
        n_blocks: u32,
    ) -> Result<(), RegTestError> {
        self.worker.mine_regtest_blocks_to_wallet(n_blocks).await
    }

    /// mine a single block to the node's wallet with a custom timestamp
    ///
    /// note: the timestamp must be within the allowed range for new blocks
    /// as compared to the current tip block.
    ///
    /// These blocks can be generated quickly because they do not have
    /// a real ZK proof.  they have a mock "proof" that is simply trusted
    /// by recipients and will validate without error.
    ///
    /// Mock proofs are allowed only on the regtest network, for development purposes.
    pub async fn mine_regtest_block_to_wallet(
        &mut self,
        timestamp: Timestamp,
    ) -> Result<Digest, RegTestError> {
        self.worker.mine_regtest_block_to_wallet(timestamp).await
    }
}

#[derive(Debug)]
struct RegTestPrivate {
    global_state_lock: GlobalStateLock,
}

impl RegTestPrivate {
    // this type should not be instantiated directly, but instead retrieved via
    // GlobalStateLock::tx_initiator()
    fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    async fn mine_regtest_blocks_to_wallet(&mut self, n_blocks: u32) -> Result<(), RegTestError> {
        for _ in 0..n_blocks {
            self.mine_regtest_block_to_wallet(Timestamp::now()).await?;
        }
        Ok(())
    }

    async fn mine_regtest_block_to_wallet(
        &mut self,
        timestamp: Timestamp,
    ) -> Result<Digest, RegTestError> {
        let gsl = &mut self.global_state_lock;

        if !gsl.cli().network.is_regtest() {
            return Err(RegTestError::WrongNetwork);
        }

        let gs = gsl.lock_guard().await;

        let tip_block = gs.chain.light_state_clone();

        let next_block_height = tip_block.header().height + 1;
        let guesser_fraction = 0.5;
        let fee_notification_policy = Default::default();
        let composer_parameters = gs.wallet_state.composer_parameters(
            next_block_height,
            guesser_fraction,
            fee_notification_policy,
        );

        let guesser_key = gs
            .wallet_state
            .wallet_entropy
            .guesser_spending_key(tip_block.hash());

        drop(gs);

        let (block, composer_tx_outputs) = MockBlockGenerator::mock_successor_with_pow(
            tip_block,
            composer_parameters,
            guesser_key,
            timestamp,
            rand::random(), // seed.
        )
        .await?;

        let composer_tx_outputs: Vec<_> = composer_tx_outputs.into();

        // tbd: maybe mock block should return these
        let expected_utxos =
            composer_tx_outputs
                .into_iter()
                .filter_map(|o| match (o.is_offchain(), o.is_owned()) {
                    (true, true) => Some(o.into_expected_utxo(UtxoNotifier::OwnMinerComposeBlock)),
                    _ => None,
                });

        // note: guesser utxos will be found by
        // WalletState::update_wallet_state_with_new_block() inside this call.
        //
        // gsl.set_new_self_composed_tip(block.clone(), expected_utxos)
        //     .await?;
        gsl.lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos)
            .await;

        let block_hash = block.hash();

        // inform main-loop.  to add to mempool and broadcast.
        gsl.rpc_server_to_main_tx()
            .send(RPCServerToMain::ProofOfWorkSolution(Box::new(block)))
            .await
            .map_err(|_| {
                tracing::warn!("Receiver in mining loop closed prematurely");
                RegTestError::Failed("internal error. block not added to blockchain".into())
            })?;

        Self::wait_until_block_in_chain(&self.global_state_lock, block_hash).await?;

        Ok(block_hash)
    }

    pub async fn wait_until_block_in_chain(
        gsl: &GlobalStateLock,
        block_hash: Digest,
    ) -> Result<(), RegTestError> {
        let start = std::time::Instant::now();
        while gsl.lock_guard().await.chain.light_state().hash() != block_hash {
            if start.elapsed() > std::time::Duration::from_secs(5) {
                // last chance.  maybe another block buried ours.  we will do an expensive check.
                if gsl
                    .lock_guard()
                    .await
                    .chain
                    .archival_state()
                    .block_belongs_to_canonical_chain(block_hash)
                    .await
                {
                    return Ok(());
                }
                // todo: something better.
                return Err(RegTestError::Failed(
                    "block not in blockchain after 5 seconds".into(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }
}
