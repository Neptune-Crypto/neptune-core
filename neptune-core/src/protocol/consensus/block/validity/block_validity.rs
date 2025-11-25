use std::collections::HashMap;
use std::sync::OnceLock;

use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::verify_mmr_successor::VerifyMmrSuccessor;
use tasm_lib::prelude::*;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;

use crate::api::export::NativeCurrencyAmount;
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::protocol::consensus::block::block_body::BlockBodyField;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::BlockHeaderField;
use crate::protocol::consensus::block::block_kernel::BlockKernelField;
use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::block::BlockField;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

#[derive(Clone, Debug, TasmObject, BFieldCodec)]
pub struct BlockValidityWitness {
    grandparent_difficulty: Difficulty,
    parent_block: Block,
    current_header: BlockHeader,
    current_body: BlockBody,
}

#[derive(Clone, Debug, TasmObject, BFieldCodec)]
struct BlockValidityWitnessMemory {
    parent_block_mmra: MmrAccumulator,
    current_block_mmra: MmrAccumulator,
    mmr_sucessor_proof: MmrSuccessorProof,
    current_coinbase: Option<NativeCurrencyAmount>,
}

impl From<&BlockValidityWitness> for BlockValidityWitnessMemory {
    fn from(value: &BlockValidityWitness) -> Self {
        let parent_block_mmra = value.parent_block.body().block_mmr_accumulator.clone();
        let mmr_sucessor_proof = MmrSuccessorProof::new_from_batch_append(
            &parent_block_mmra,
            &vec![value.current_header.prev_block_digest],
        );
        let current_block_mmra = value.current_body.block_mmr_accumulator.clone();
        Self {
            parent_block_mmra,
            current_block_mmra,
            mmr_sucessor_proof,
            current_coinbase: value.current_body.transaction_kernel.coinbase,
        }
    }
}

impl SecretWitness for BlockValidityWitness {
    fn standard_input(&self) -> PublicInput {
        // All header values are fed as standard-input, except for those that
        // the guesser is intended to change. This binds all header values to
        // the block proof. Multi-word values must be reversed because of the
        // stream/stack/encoding discrepancy.
        let current_header = &self.current_header;

        let current_prev_block_digest = current_header
            .prev_block_digest
            .reversed()
            .values()
            .to_vec();
        let mut cum_pow = current_header.cumulative_proof_of_work.encode();
        cum_pow.reverse();

        let mut difficulty = current_header.difficulty.encode();
        difficulty.reverse();

        let current_body_digest = self.current_body.mast_hash().reversed().values().to_vec();

        let input = [
            vec![current_header.version],
            vec![current_header.height.into()],
            current_prev_block_digest,
            vec![current_header.timestamp.0],
            cum_pow,
            difficulty,
            current_body_digest,
        ]
        .concat();

        PublicInput::new(input)
    }

    fn program(&self) -> Program {
        BlockValidity.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let parent_kernel = &self.parent_block.kernel;
        let parent_header = &parent_kernel.header;
        let parent_body = &parent_kernel.body;
        let current_body = &self.current_body;

        let digest_to_input = |digest: Digest| digest.reversed().values().to_vec();
        let encoding_to_input = |mut words: Vec<BFieldElement>| {
            words.reverse();
            words
        };

        let parent_kernel_digest = digest_to_input(parent_kernel.mast_hash());
        let parent_header_digest = digest_to_input(parent_header.mast_hash());
        let parent_difficulty = encoding_to_input(parent_header.difficulty.encode());
        let parent_cum_pow = encoding_to_input(parent_header.cumulative_proof_of_work.encode());
        let parent_body_digest = digest_to_input(parent_body.mast_hash());

        let nd_tokens = [
            parent_kernel_digest,
            parent_header_digest,
            vec![parent_header.height.into()],
            vec![parent_header.timestamp.0],
            parent_difficulty,
            parent_cum_pow,
            parent_body_digest,
            vec![current_body.transaction_kernel.timestamp.0],
        ]
        .concat();

        let mut ram = HashMap::default();
        let witness_in_memory: BlockValidityWitnessMemory = self.into();
        encode_to_memory(
            &mut ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &witness_in_memory,
        );

        let mut nd = NonDeterminism {
            individual_tokens: nd_tokens,
            digests: Default::default(),
            ram,
        };

        nd.digests
            .extend_from_slice(&self.parent_block.mast_path(BlockField::Kernel));
        nd.digests
            .extend_from_slice(&parent_kernel.mast_path(BlockKernelField::Header));
        nd.digests
            .extend_from_slice(&parent_header.mast_path(BlockHeaderField::Height));
        nd.digests
            .extend_from_slice(&parent_header.mast_path(BlockHeaderField::Timestamp));
        nd.digests
            .extend_from_slice(&parent_header.mast_path(BlockHeaderField::Difficulty));
        nd.digests
            .extend_from_slice(&parent_header.mast_path(BlockHeaderField::CumulativeProofOfWork));
        nd.digests
            .extend_from_slice(&parent_kernel.mast_path(BlockKernelField::Body));
        nd.digests
            .extend_from_slice(&parent_body.mast_path(BlockBodyField::BlockMmrAccumulator));
        nd.digests
            .extend_from_slice(&current_body.mast_path(BlockBodyField::BlockMmrAccumulator));

        VerifyMmrSuccessor::update_nondeterminism(&mut nd, &witness_in_memory.mmr_sucessor_proof);

        nd.digests
            .extend_from_slice(&current_body.mast_path(BlockBodyField::TransactionKernel));
        nd.digests.extend_from_slice(
            &current_body
                .transaction_kernel
                .mast_path(TransactionKernelField::Timestamp),
        );
        nd.digests.extend_from_slice(
            &current_body
                .transaction_kernel
                .mast_path(TransactionKernelField::Coinbase),
        );

        nd
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BlockValidity;

impl ConsensusProgram for BlockValidity {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        // TODO: build!
        (Library::default(), triton_asm!())
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;
    use tasm_lib::twenty_first::prelude::Mmr;

    use super::*;
    use crate::api::export::BlockHeight;
    use crate::api::export::Network;
    use crate::api::export::Timestamp;
    use crate::protocol::consensus::block::block_body::BlockBodyField;
    use crate::protocol::consensus::block::block_header::BlockHeaderField;
    use crate::protocol::consensus::block::block_kernel::BlockKernel;
    use crate::protocol::consensus::block::block_kernel::BlockKernelField;
    use crate::protocol::consensus::block::block_validation_error::BlockValidationError;
    use crate::protocol::consensus::block::difficulty_control::difficulty_control;
    use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
    use crate::protocol::consensus::block::BlockField;
    use crate::protocol::consensus::block::INITIAL_BLOCK_SUBSIDY;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
    use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
    use crate::protocol::proof_abstractions::mast_hash::MastHash;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::builtins::decode_from_memory;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::tests::shared::blocks::invalid_empty_block;

    #[test]
    fn rust_shadowing_genesis_block() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let block1 = invalid_empty_block(&genesis, network);
        let block2 = invalid_empty_block(&block1, network);
        let block_validity_witness = BlockValidityWitness {
            grandparent_difficulty: genesis.header().difficulty,
            parent_block: block1,
            current_header: block2.kernel.header,
            current_body: block2.kernel.body,
        };
        let std_in = block_validity_witness.standard_input();
        let nd = block_validity_witness.nondeterminism();
        let expected_output = block_validity_witness.output();
        let rust_output = BlockValidity.run_rust(&std_in, nd).unwrap();

        assert_eq!(expected_output, rust_output);
    }

    impl BlockValidity {
        /// Mimic behavior of [`Block::validate`] in a simulated Triton VM
        /// environment. On errors, this method must return the same errors
        /// as that of [`Block::validate`].
        fn validate_mimicker(&self) -> Result<(), BlockValidationError> {
            // Network parameters are assumed to match main net's
            let network = Network::Main;
            let minimum_block_interval = network.minimum_block_time().to_millis();
            let target_block_interval = network.target_block_interval();

            let current_version: BFieldElement = tasm::tasmlib_io_read_stdin___bfe();
            let current_height: BFieldElement = tasm::tasmlib_io_read_stdin___bfe();
            let current_prev_block_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let current_timestamp: BFieldElement = tasm::tasmlib_io_read_stdin___bfe();
            let current_cum_pow = tasm::tasmlib_io_read_stdin___u192();
            let current_difficulty = tasm::tasmlib_io_read_stdin___u160();
            let current_body_digest = tasm::tasmlib_io_read_stdin___digest();

            /* Divine in parent header digest and prove its correctness */
            let parent_kernel_digest = tasm::tasmlib_io_read_secin___digest();
            tasm::tasmlib_hashing_merkle_verify(
                current_prev_block_digest,
                BlockField::Kernel as u32,
                Tip5::hash(&parent_kernel_digest),
                Block::MAST_HEIGHT as u32,
            );

            let parent_header_digest = tasm::tasmlib_io_read_secin___digest();
            tasm::tasmlib_hashing_merkle_verify(
                parent_kernel_digest,
                BlockKernelField::Header as u32,
                Tip5::hash(&parent_header_digest),
                BlockKernel::MAST_HEIGHT as u32,
            );

            // 0.a)
            /* Verify height field */
            let parent_height = tasm::tasmlib_io_read_secin___bfe();
            tasm::tasmlib_hashing_merkle_verify(
                parent_header_digest,
                BlockHeaderField::Height as u32,
                Tip5::hash(&parent_height),
                BlockHeader::MAST_HEIGHT as u32,
            );

            if parent_height + bfe!(1) != current_height {
                return Err(BlockValidationError::BlockHeight);
            }

            // 0.d)
            /* Verify timestamp field */
            let parent_timestamp = tasm::tasmlib_io_read_secin___bfe();
            tasm::tasmlib_hashing_merkle_verify(
                parent_header_digest,
                BlockHeaderField::Timestamp as u32,
                Tip5::hash(&parent_timestamp),
                BlockHeader::MAST_HEIGHT as u32,
            );

            // Use Triton VM's "split" to get a u64 representation of timestamp
            if current_timestamp.value() < parent_timestamp.value() + minimum_block_interval {
                return Err(BlockValidationError::MinimumBlockTime);
            }

            // 0.e)
            /* Verify difficulty field */
            let parent_difficulty = tasm::tasmlib_io_read_secin___u160();
            tasm::tasmlib_hashing_merkle_verify(
                parent_header_digest,
                BlockHeaderField::Difficulty as u32,
                Tip5::hash(&parent_difficulty),
                BlockHeader::MAST_HEIGHT as u32,
            );

            // TODO: We have to write this as a "tasm" implementation to mimic
            // divination in div_mod implementation for u160s in tasmlib.
            let parent_difficulty = Difficulty::new(parent_difficulty);
            let expected_difficulty = difficulty_control(
                Timestamp(current_timestamp),
                Timestamp(parent_timestamp),
                parent_difficulty,
                target_block_interval,
                parent_height.into(),
            );

            let current_difficulty = Difficulty::new(current_difficulty);
            if expected_difficulty != current_difficulty {
                return Err(BlockValidationError::Difficulty);
            }

            // 0.f)
            /* Verify cumulative pow field */
            let parent_cum_pow = tasm::tasmlib_io_read_secin___u192();
            tasm::tasmlib_hashing_merkle_verify(
                parent_header_digest,
                BlockHeaderField::CumulativeProofOfWork as u32,
                Tip5::hash(&parent_cum_pow),
                BlockHeader::MAST_HEIGHT as u32,
            );

            let parent_cum_pow = ProofOfWork::new(parent_cum_pow);
            let expected_cum_pow = parent_cum_pow + parent_difficulty;
            let current_cum_pow = ProofOfWork::new(current_cum_pow);
            if expected_cum_pow != current_cum_pow {
                return Err(BlockValidationError::CumulativeProofOfWork);
            }

            /* Divine in parent body digest */
            let parent_body_digest = tasm::tasmlib_io_read_secin___digest();
            tasm::tasmlib_hashing_merkle_verify(
                parent_kernel_digest,
                BlockKernelField::Body as u32,
                Tip5::hash(&parent_body_digest),
                BlockKernel::MAST_HEIGHT as u32,
            );

            // 0.c
            // Verify correct update of MMR accumulator using
            //`verify_mmr_successor_proof` combined with an assertion about the
            // number of leafs. This is used instead of mutating the MMR
            // accumulator using the `append` method since we don't want to
            // mutate the part of memory where the witness lives -- since this
            // would become a huge mess when executing in Triton VM, Thor
            // believes.
            let memory_witness: BlockValidityWitnessMemory =
                decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);
            let parent_block_mmra = &memory_witness.parent_block_mmra;
            tasm::tasmlib_hashing_merkle_verify(
                parent_body_digest,
                BlockBodyField::BlockMmrAccumulator as u32,
                Tip5::hash(parent_block_mmra),
                BlockBody::MAST_HEIGHT as u32,
            );

            let current_block_mmra = memory_witness.current_block_mmra;
            tasm::tasmlib_hashing_merkle_verify(
                current_body_digest,
                BlockBodyField::BlockMmrAccumulator as u32,
                Tip5::hash(&current_block_mmra),
                BlockBody::MAST_HEIGHT as u32,
            );

            tasm::verify_mmr_successor_proof(
                parent_block_mmra,
                &current_block_mmra,
                &memory_witness.mmr_sucessor_proof,
            );

            assert!(parent_block_mmra.num_leafs() + 1 == current_block_mmra.num_leafs());

            // Extra sanity check on height/block MMR relationship.
            assert!(current_block_mmra.num_leafs() == current_height.value());

            /* 2: Transaction validation */

            // 2.f)
            /* Verify block timestamp >= tx timestamp */
            println!("Verify current_tx_kernel_digest");
            let current_tx_kernel_digest = tasm::tasmlib_io_read_secin___digest();
            tasm::tasmlib_hashing_merkle_verify(
                current_body_digest,
                BlockBodyField::TransactionKernel as u32,
                Tip5::hash(&current_tx_kernel_digest),
                BlockBody::MAST_HEIGHT as u32,
            );

            println!("Verify current_tx_timestamp");
            let current_tx_timestamp = tasm::tasmlib_io_read_secin___bfe();
            tasm::tasmlib_hashing_merkle_verify(
                current_tx_kernel_digest,
                TransactionKernelField::Timestamp as u32,
                Tip5::hash(&current_tx_timestamp),
                TransactionKernel::MAST_HEIGHT as u32,
            );

            if current_tx_timestamp.value() > current_timestamp.value() {
                return Err(BlockValidationError::TransactionTimestamp);
            }

            let current_height: BlockHeight = current_height.into();
            let current_generation = current_height.get_generation();
            let block_subsidy = INITIAL_BLOCK_SUBSIDY.to_nau() >> current_generation;

            println!("Verify current_coinbase");
            let current_coinbase = memory_witness.current_coinbase;
            tasm::tasmlib_hashing_merkle_verify(
                current_tx_kernel_digest,
                TransactionKernelField::Coinbase as u32,
                Tip5::hash(&current_coinbase),
                TransactionKernel::MAST_HEIGHT as u32,
            );
            let current_coinbase = current_coinbase.unwrap_or(NativeCurrencyAmount::zero());
            if current_coinbase.is_negative() {
                return Err(BlockValidationError::NegativeCoinbase);
            }

            if current_coinbase.to_nau() > block_subsidy {
                return Err(BlockValidationError::CoinbaseTooBig);
            }

            // 2.j)
            // 2.k)
            // 2.l)

            Ok(())
        }
    }

    impl ConsensusProgramSpecification for BlockValidity {
        fn source(&self) {
            self.validate_mimicker().unwrap()
        }
    }
}
