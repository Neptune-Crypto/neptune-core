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
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::blockchain::transaction::validity::tasm::single_proof::merge_branch::MergeWitness;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TransactionProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::verifier::cache_true_claim;
use crate::models::state::transaction_details::TransactionDetails;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::transaction_output::TxOutputList;

#[derive(Debug, Clone, Copy)]
pub(crate) struct MockBlockGenerator;

impl MockBlockGenerator {
    /// Create a fake block proposal; will pass `is_valid` but fail pow-check. Will
    /// be a valid block except for proof and PoW.
    pub async fn mock_block_proposal_from_tx(predecessor: Block, tx: Transaction) -> Block {
        let timestamp = tx.kernel.timestamp;

        let primitive_witness = BlockPrimitiveWitness::new(predecessor, tx);

        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(timestamp, None);
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
        seed: [u8; 32],
    ) -> Block {
        let mut block = Self::mock_block_proposal_from_tx((*predecessor).clone(), tx).await;

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
            bail!("arguments must be bogus singleproof transactions")
        };
        let TransactionProof::SingleProof(rhs_proof) = rhs.proof else {
            bail!("arguments must be bogus singleproof transactions")
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
        )?;

        let coinbase_transaction = Self::mock_transaction_from_details(&transaction_details).await;

        let mut block_transaction = coinbase_transaction;
        if selected_mempool_txs.is_empty() {
            // create the nop-tx and merge into the coinbase transaction to set the
            // merge bit to allow the tx to be included in a block.
            let nop_details = TransactionDetails::nop(
                predecessor_block.mutator_set_accumulator_after(),
                timestamp,
            );
            let nop_transaction = Self::mock_transaction_from_details(&nop_details).await;

            selected_mempool_txs = vec![nop_transaction];
        }

        let mut rng = StdRng::from_seed(shuffle_seed);
        for tx_to_include in selected_mempool_txs {
            block_transaction =
                Self::merge_mock_transactions(block_transaction, tx_to_include, rng.random())
                    .await
                    .expect("Must be able to merge transactions in mining context");
        }

        Ok((block_transaction, composer_txos))
    }

    async fn mock_block_successor(
        predecessor: Arc<Block>,
        composer_address: ReceivingAddress,
        timestamp: Timestamp,
        seed: [u8; 32],
        with_valid_pow: bool,
    ) -> Result<(Block, TxOutputList)> {
        let mut rng = StdRng::from_seed(seed);

        let composer_parameters = ComposerParameters::new(composer_address, rng.random(), 0.5f64);
        let (block_tx, composer_tx_outputs) = Self::create_mock_block_transaction(
            &*predecessor,
            composer_parameters,
            timestamp,
            rng.random(),
            vec![],
        )
        .await?;

        let block = if with_valid_pow {
            Self::mock_block_from_tx(predecessor, block_tx, rng.random()).await
        } else {
            Self::mock_block_proposal_from_tx((*predecessor).clone(), block_tx).await
        };

        Ok((block, composer_tx_outputs))
    }

    pub async fn mock_successor_without_pow(
        predecessor: Arc<Block>,
        composer_address: ReceivingAddress,
        timestamp: Timestamp,
        seed: [u8; 32],
    ) -> Result<(Block, TxOutputList)> {
        Self::mock_block_successor(predecessor, composer_address, timestamp, seed, false).await
    }

    // pub async fn mock_successor(
    //     predecessor: Arc<Block>,
    //     composer_address: ReceivingAddress,
    //     timestamp: Timestamp,
    //     seed: [u8; 32],
    // ) -> Result<(Block, TxOutputList)> {
    //     Self::mock_block_successor(predecessor, composer_address, timestamp, seed, true).await
    // }
    /*
        /// Create a block with coinbase going to self. For testing purposes.
        ///
        /// The block will be valid both in terms of PoW and and will pass the
        /// Block::is_valid() function. However, the associated (claim, proof) pair will
        /// will not pass `triton_vm::verify`, as its validity is only mocked.
        // pub async fn mock_block(
        //     state_lock: &GlobalStateLock,
        //     seed: [u8; 32],
        // ) -> Block {
        //     let current_tip = state_lock.lock_guard().await.chain.light_state().clone();
        //     mock_successor(
        //         &current_tip,
        //         current_tip.header().timestamp + Timestamp::hours(1),
        //         seed,
        //     )
        //     .await
        // }

        /// Create a deterministic sequence of valid blocks.
        ///
        /// Sequence is N-long. Every block i with i > 0 has block i-1 as its
        /// predecessor; block 0 has the `predecessor` argument as predecessor. Every
        /// block is valid in terms of both `is_valid` and `has_proof_of_work`. But
        /// the STARK proofs are mocked.
        // pub async fn mock_sequence_of_blocks<const N: usize>(
        //     predecessor: Arc<Block>,
        //     block_interval: Timestamp,
        //     seed: [u8; 32],
        // ) -> [Arc<Block>; N] {
        //     Self::mock_sequence_of_blocks_dyn(predecessor, block_interval, seed, N)
        //         .await
        //         .try_into()
        //         .unwrap()
        // }

        /// Create a deterministic sequence of valid blocks.
        ///
        /// Sequence is N-long. Every block i with i > 0 has block i-1 as its
        /// predecessor; block 0 has the `predecessor` argument as predecessor. Every
        /// block is valid in terms of both `is_valid` and `has_proof_of_work`. But
        /// the STARK proofs are mocked.
        // pub async fn mock_sequence_of_blocks_dyn(
        //     mut predecessor: Arc<Block>,
        //     block_interval: Timestamp,
        //     seed: [u8; 32],
        //     n: usize,
        // ) -> Vec<Arc<Block>> {
        //     let mut blocks = vec![];
        //     let mut rng: StdRng = SeedableRng::from_seed(seed);
        //     for _ in 0..n {
        //         let block = Self::mock_successor(
        //             predecessor.clone(),
        //             predecessor.header().timestamp + block_interval,
        //             rng.random(),
        //         )
        //         .await;
        //         predecessor = Arc::new(block);
        //         blocks.push(predecessor.clone());
        //     }
        //     blocks
        // }
    */
}
