use std::sync::Arc;

use anyhow::bail;
use anyhow::Result;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use tasm_lib::triton_vm::proof::Proof;

use crate::mine_loop::composer_parameters::ComposerParameters;
use crate::mine_loop::prepare_coinbase_transaction_stateless;
use crate::models::blockchain::block::validity::block_primitive_witness::BlockPrimitiveWitness;
use crate::models::blockchain::block::validity::block_program::BlockProgram;
use crate::models::blockchain::block::validity::block_proof_witness::BlockProofWitness;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::block::BlockProof;
use crate::models::blockchain::block::Network;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::verifier::cache_true_claim;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::address::hash_lock_key::HashLockKey;
use crate::models::state::wallet::transaction_output::TxOutputList;

#[derive(Debug, Clone, Copy)]
pub(crate) struct MockBlockGenerator;

impl MockBlockGenerator {
    /// Create a fake block proposal; will pass `is_valid` but fail pow-check. Will
    /// be a valid block except for proof and PoW.
    pub async fn mock_block_from_tx_without_pow(
        predecessor: Block,
        tx: Transaction,
        guesser_key: HashLockKey,
    ) -> Block {
        let timestamp = tx.kernel.timestamp;

        let primitive_witness = BlockPrimitiveWitness::new(predecessor, tx);

        let body = primitive_witness.body().to_owned();
        let mut header =
            primitive_witness.header(timestamp, Some(Network::RegTest.target_block_interval()));
        header.guesser_digest = guesser_key.after_image();
        let (appendix, proof) = {
            let block_proof_witness = BlockProofWitness::produce(primitive_witness);
            let appendix = block_proof_witness.appendix();
            let claim = BlockProgram::claim(&body, &appendix);
            cache_true_claim(claim).await;
            (appendix, BlockProof::SingleProof(Proof(vec![])))
        };

        Block::new(header, body, appendix, proof)
    }

    /// Create a block from a transaction without the hassle of proving but such
    /// that it appears valid.
    pub async fn mock_block_from_tx(
        predecessor: Arc<Block>,
        tx: Transaction,
        guesser_key: HashLockKey,
        seed: [u8; 32],
    ) -> Block {
        let mut block =
            Self::mock_block_from_tx_without_pow((*predecessor).clone(), tx, guesser_key).await;

        let mut rng = StdRng::from_seed(seed);

        // mining (guessing) loop.
        while !block.has_proof_of_work(predecessor.header()) {
            let nonce = rng.random();
            block.set_header_nonce(nonce);
        }

        block
    }

    /// Create a `Transaction` from `TransactionDetails` such that verification
    /// seems to pass but without the hassle of producing a proof for it. Behind the
    /// scenes, this method updates the true claims cache, such that the call to
    /// `triton_vm::verify` will be by-passed.
    async fn mock_transaction_from_details(
        transaction_details: &TransactionDetails,
    ) -> Transaction {
        let kernel = PrimitiveWitness::from_transaction_details(transaction_details).kernel;

        let claim = SingleProof::claim(kernel.mast_hash());
        cache_true_claim(claim).await;

        Transaction {
            kernel,
            proof: TransactionProof::SingleProof(Proof(vec![])),
        }
    }

    /// Merge two transactions for tests, without the hassle of proving but such
    /// that the result seems valid.
    async fn merge_mock_transactions(
        lhs: Transaction,
        rhs: Transaction,
        shuffle_seed: [u8; 32],
    ) -> Result<Transaction> {
        let TransactionProof::SingleProof(lhs_proof) = lhs.proof else {
            bail!("merge error: arguments must be singleproof transactions")
        };
        let TransactionProof::SingleProof(rhs_proof) = rhs.proof else {
            bail!("merge error: arguments must be singleproof transactions")
        };
        let merge_witness = MergeWitness::from_transactions(
            lhs.kernel,
            lhs_proof,
            rhs.kernel,
            rhs_proof,
            shuffle_seed,
        );
        let new_kernel = merge_witness.new_kernel.clone();

        let claim = SingleProof::claim(new_kernel.mast_hash());
        cache_true_claim(claim).await;

        Ok(Transaction {
            kernel: new_kernel,
            proof: TransactionProof::SingleProof(Proof(vec![])),
        })
    }

    /// Create a block-transaction with a bogus proof but such that `verify` passes.
    /// note: pub(crate) for now so we don't expose ComposerParameters.
    pub async fn create_mock_block_transaction(
        network: Network,
        predecessor_block: &Block,
        composer_parameters: ComposerParameters,
        timestamp: Timestamp,
        shuffle_seed: [u8; 32],
        mut selected_mempool_txs: Vec<Transaction>,
    ) -> Result<(Transaction, TxOutputList)> {
        let (composer_txos, transaction_details) = prepare_coinbase_transaction_stateless(
            predecessor_block,
            composer_parameters,
            timestamp,
            network,
        )?;

        let coinbase_transaction = Self::mock_transaction_from_details(&transaction_details).await;

        let mut block_transaction = coinbase_transaction;
        if selected_mempool_txs.is_empty() {
            // create the nop-tx and merge into the coinbase transaction to set the
            // merge bit to allow the tx to be included in a block.
            let nop_details = TransactionDetails::nop(
                predecessor_block.mutator_set_accumulator_after(),
                timestamp,
                network,
            );
            let nop_transaction = Self::mock_transaction_from_details(&nop_details).await;

            selected_mempool_txs = vec![nop_transaction];
        }

        let mut rng = StdRng::from_seed(shuffle_seed);
        for tx_to_include in selected_mempool_txs {
            block_transaction =
                Self::merge_mock_transactions(block_transaction, tx_to_include, rng.random())
                    .await?;
        }

        Ok((block_transaction, composer_txos))
    }

    /// Create a mock block with coinbase going to self.
    ///
    /// For reg-test mode purposes.
    ///
    /// The block will be valid both in terms of PoW and and will pass the
    /// Block::is_valid() function.
    ///
    /// The associated (claim, proof) pair will pass `triton_vm::verify`,
    /// only if the network is regtest.  (The proof is mocked).
    pub async fn mock_successor_with_pow(
        predecessor: Arc<Block>,
        composer_parameters: ComposerParameters,
        guesser_key: HashLockKey,
        timestamp: Timestamp,
        seed: [u8; 32],
        mempool_tx: Vec<Transaction>,
        network: Network,
    ) -> Result<(Block, TxOutputList)> {
        let with_valid_pow = true;
        let mut rng = StdRng::from_seed(seed);

        let (block_tx, composer_tx_outputs) = Self::create_mock_block_transaction(
            network,
            &predecessor,
            composer_parameters,
            timestamp,
            rng.random(),
            mempool_tx,
        )
        .await?;

        let prev = predecessor.clone();

        let block = if with_valid_pow {
            Self::mock_block_from_tx(predecessor, block_tx, guesser_key, rng.random()).await
        } else {
            Self::mock_block_from_tx_without_pow((*predecessor).clone(), block_tx, guesser_key)
                .await
        };

        tracing::debug!(
            "new mock block has height: {}, prev block height: {}",
            block.header().height,
            prev.header().height
        );

        assert_eq!(block.header().height, prev.header().height + 1);

        Ok((block, composer_tx_outputs))
    }
}
