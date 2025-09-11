use tasm_lib::prelude::Digest;

use super::error::RegTestError;
use crate::api::export::Timestamp;
use crate::protocol::consensus::block::mock_block_generator::MockBlockGenerator;
use crate::protocol::consensus::block::Block;
use crate::protocol::shared::SIZE_20MB_IN_BYTES;
use crate::state::mining::block_proposal::BlockProposal;
use crate::state::wallet::expected_utxo::ExpectedUtxo;
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
    pub async fn mine_blocks_to_wallet(
        &mut self,
        n_blocks: u32,
        mine_mempool_txs: bool,
    ) -> Result<(), RegTestError> {
        self.worker
            .mine_blocks_to_wallet(n_blocks, mine_mempool_txs)
            .await
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
    pub async fn mine_block_to_wallet(
        &mut self,
        timestamp: Timestamp,
        mine_mempool_sp_txs: bool,
    ) -> Result<Digest, RegTestError> {
        self.worker
            .mine_block_to_wallet(timestamp, rand::random(), mine_mempool_sp_txs)
            .await
    }

    /// Compose a block with a mocked proof and set it as current block
    /// proposal
    pub async fn set_self_composed_proposal(&mut self, timestamp: Timestamp, seed: [u8; 32]) {
        self.worker
            .set_self_composed_proposal(timestamp, seed)
            .await
    }
}

#[derive(Debug)]
struct RegTestPrivate {
    global_state_lock: GlobalStateLock,
}

impl RegTestPrivate {
    fn new(global_state_lock: GlobalStateLock) -> Self {
        Self { global_state_lock }
    }

    async fn set_self_composed_proposal(&mut self, timestamp: Timestamp, seed: [u8; 32]) {
        let include_mempool_txs = true;
        let find_valid_pow = false;
        let (block_proposal, composer_utxos) = self
            .compose(timestamp, seed, include_mempool_txs, find_valid_pow)
            .await;

        self.global_state_lock
            .lock_guard_mut()
            .await
            .mining_state
            .block_proposal = BlockProposal::OwnComposition((block_proposal, composer_utxos));
    }

    async fn compose(
        &self,
        timestamp: Timestamp,
        seed: [u8; 32],
        include_mempool_txs: bool,
        find_valid_pow: bool,
    ) -> (Block, Vec<ExpectedUtxo>) {
        let gsl = &self.global_state_lock;

        assert!(
            gsl.cli().network.use_mock_proof(),
            "Must use mock-proof network"
        );

        let gs = gsl.lock_guard().await;

        let tip_block = gs.chain.light_state_clone();

        let next_block_height = tip_block.header().height + 1;
        let fee_notification_policy = Default::default();
        let guesser_fraction = gs.cli().guesser_fraction;
        let overridden_coinbase_distribution = gs.mining_state.overridden_coinbase_distribution();
        let composer_parameters = gs.wallet_state.composer_parameters(
            next_block_height,
            guesser_fraction,
            fee_notification_policy,
            overridden_coinbase_distribution,
        );

        let guesser_key = gs.wallet_state.wallet_entropy.guesser_fee_key();

        // retrieve selected tx from mempool for block inclusion.
        let txs_from_mempool = if include_mempool_txs {
            gs.mempool.get_transactions_for_block_composition(
                SIZE_20MB_IN_BYTES,
                Some(gsl.cli().max_num_compose_mergers.get()),
            )
        } else {
            vec![]
        };

        drop(gs);

        let (mut block, composer_tx_outputs) = MockBlockGenerator::mock_successor_no_pow(
            tip_block.clone(),
            composer_parameters.clone(),
            guesser_key.to_address().into(),
            timestamp,
            seed,
            txs_from_mempool,
            gsl.cli().network,
        );

        if find_valid_pow {
            block.satisfy_mock_pow(tip_block.header().difficulty, rand::random());
        }

        (
            block,
            composer_parameters.extract_expected_utxos(composer_tx_outputs),
        )
    }

    // see description in [RegTest]
    async fn mine_blocks_to_wallet(
        &mut self,
        n_blocks: u32,
        mine_mempool_sp_txs: bool,
    ) -> Result<(), RegTestError> {
        for _ in 0..n_blocks {
            self.mine_block_to_wallet(Timestamp::now(), rand::random(), mine_mempool_sp_txs)
                .await?;
        }
        Ok(())
    }

    // see description in [RegTest]
    async fn mine_block_to_wallet(
        &mut self,
        timestamp: Timestamp,
        seed: [u8; 32],
        include_mempool_txs: bool,
    ) -> Result<Digest, RegTestError> {
        let find_valid_pow = true;
        let (block, expected_utxos) = self
            .compose(timestamp, seed, include_mempool_txs, find_valid_pow)
            .await;

        self.global_state_lock
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos)
            .await;

        let block_hash = block.hash();

        // inform main-loop.  to add to mempool and broadcast.
        //
        // todo: ideally we would pass a listener here to wait on, so that
        // once the block is added we get notified, rather than polling.
        self.global_state_lock.rpc_server_to_main_tx()
            .send(RPCServerToMain::ProofOfWorkSolution(Box::new(block)))
            .await
            .map_err(|_| {
                tracing::warn!("channel send failed. channel 'rpc_server_to_main' closed unexpectedly. main_loop may have terminated prematurely.");
                RegTestError::Failed("internal error. block not added to blockchain".into())
            })?;

        // wait until the main-loop has actually added the block to the canonical chain
        // or 5 second timeout happens.
        //
        // otherwise, wallet balance might not (yet) see coinbase funds, etc.
        //
        // note: temporary until listener approach is implemented.
        Self::wait_until_block_in_chain(&self.global_state_lock, block_hash).await?;

        Ok(block_hash)
    }

    // waits (polls) until block is found in canonical chain or 5 second timeout occurs.
    //
    // note: temporary until listener approach is implemented.
    async fn wait_until_block_in_chain(
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
                return Err(RegTestError::Failed(
                    "block not in blockchain after 5 seconds".into(),
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }
}
