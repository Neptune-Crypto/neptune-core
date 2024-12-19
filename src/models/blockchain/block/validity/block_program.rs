use std::sync::OnceLock;

use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::block_proof_witness::BlockProofWitness;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_body::BlockBodyField;
use crate::models::blockchain::block::BlockAppendix;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::builtins::verify_stark;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

/// Verifies that all claims listed in the appendix are true.
///
/// The witness for this program is [`BlockProofWitness`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlockProgram;

impl BlockProgram {
    const ILLEGAL_FEE: i128 = 1_000_210;

    pub(crate) fn claim(block_body: &BlockBody, appendix: &BlockAppendix) -> Claim {
        Claim::new(Self.hash())
            .with_input(block_body.mast_hash().reversed().values().to_vec())
            .with_output(appendix.claims_as_output())
    }

    pub(crate) fn verify(block_body: &BlockBody, appendix: &BlockAppendix, proof: &Proof) -> bool {
        let claim = Self::claim(block_body, appendix);
        triton_vm::verify(Stark::default(), &claim, proof)
    }
}

impl ConsensusProgram for BlockProgram {
    fn source(&self) {
        let block_body_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let block_witness: BlockProofWitness = tasmlib::decode_from_memory(start_address);
        let claims: Vec<Claim> = block_witness.claims;
        let proofs: Vec<Proof> = block_witness.proofs;

        let block_body = &block_witness.block_body;

        let txk_mast_hash: Digest = tasmlib::tasmlib_io_read_secin___digest();

        let fee = &block_body.transaction_kernel.fee;
        let fee_hash = Tip5::hash(fee);
        tasmlib::tasmlib_hashing_merkle_verify(
            txk_mast_hash,
            TransactionKernelField::Fee as u32,
            fee_hash,
            TransactionKernel::MAST_HEIGHT as u32,
        );

        let txk_mast_hash_as_leaf = Tip5::hash(&txk_mast_hash);
        tasmlib::tasmlib_hashing_merkle_verify(
            block_body_digest,
            BlockBodyField::TransactionKernel as u32,
            txk_mast_hash_as_leaf,
            BlockBody::MAST_HEIGHT as u32,
        );

        assert!(!fee.is_negative());
        assert!(*fee <= NeptuneCoins::max());

        let mut i = 0;
        while i < claims.len() {
            tasmlib::tasmlib_io_write_to_stdout___digest(Tip5::hash(&claims[i]));
            verify_stark(Stark::default(), &claims[i], &proofs[i]);

            i += 1;
        }
    }

    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let block_body_field = field!(BlockProofWitness::block_body);
        let body_field_kernel = field!(BlockBody::transaction_kernel);
        let kernel_field_fee = field!(TransactionKernel::fee);
        let block_witness_field_claims = field!(BlockProofWitness::claims);
        let block_witness_field_proofs = field!(BlockProofWitness::proofs);

        let merkle_verify = library.import(Box::new(MerkleVerify));
        let coin_size = NeptuneCoins::static_length().unwrap();
        let hash_fee = library.import(Box::new(HashStaticSize { size: coin_size }));
        let push_max_amount = NeptuneCoins::max().push_to_stack();
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let verify_fee_legality = triton_asm!(
            // _ [bbd] *w [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push {TransactionKernel::MAST_HEIGHT}
            // _ [bbd] *w [txkmh] [txkmh] txkm_height

            push {TransactionKernelField::Fee as u32}
            // _ [bbd] *w [txkmh] [txkmh] txkm_height fee_leaf_index

            dup 12 {&block_body_field} {&body_field_kernel} {&kernel_field_fee}
            // _ [bbd] *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee

            dup 0 addi {coin_size - 1} read_mem {coin_size} pop 1
            // _ [bbd] *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee [fee]

            {&push_max_amount}
            call {u128_lt}
            push 0 eq
            // _ [bbd] *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee (max >= fee)

            assert error_id {Self::ILLEGAL_FEE}
            // _ [bbd] *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee

            call {hash_fee} pop 1
            // _ [bbd] *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee_hash]

            call {merkle_verify}
            // _ [bbd] *w [txkmh]

            push 0
            push 0
            push 0
            push 0
            push 1
            dup 9
            dup 9
            dup 9
            dup 9
            dup 9
            // _ [bbd] *w [txkmh] 0 0 0 0 1 [txkmh]
            // _ [bbd] *w [txkmh] [padded-txkmh] <-- rename

            sponge_init
            sponge_absorb
            sponge_squeeze

            pick 5 pop 1
            pick 5 pop 1
            pick 5 pop 1
            pick 5 pop 1
            pick 5 pop 1
            // _ [bbd] *w [txkmh] [txkmh_hash]

            dup 15
            dup 15
            dup 15
            dup 15
            dup 15
            // _ [bbd] *w [txkmh] [txkmh_hash] [bbd]

            push {BlockBody::MAST_HEIGHT}
            push {BlockBodyField::TransactionKernel as u32}
            // _ [bbd] *w [txkmh] [txkmh_hash] [bbd] block_body_mast_height txk_leaf_index

            pick 11
            pick 11
            pick 11
            pick 11
            pick 11
            // _ [bbd] *w [txkmh] [bbd] block_body_mast_height txk_leaf_index [txkmh_hash]

            call {merkle_verify}
            // _ [bbd] *w [txkmh]
        );

        let hash_varlen = library.import(Box::new(HashVarlen));
        let print_claim_hash = triton_asm!(
            // _ *claim[i]_si

            read_mem 1
            addi 2
            // _ claim[i]_si *claim[i]

            dup 0
            place 2
            place 1
            // _ *claim[i] *claim[i] claim[i]_si

            call {hash_varlen}
            // _ *claim[i] [hash(claim)]

            write_io {Digest::LEN}
            // _ *claim[i]
        );

        let verify_all_claims_loop = "verify_all_claims_loop".to_string();

        let verify_all_claims_function = triton_asm! {
            // INVARIANT: _ [bbd] *claim[i]_si *proof[i]_si N i
            {verify_all_claims_loop}:

                // terminate if done
                dup 1 dup 1 eq skiz return

                dup 3
                // _ [bbd] *claim[i]_si *proof[i]_si N i *claim[i]_si

                {&print_claim_hash}
                // _ [bbd] *claim[i]_si *proof[i]_si N i *claim[i]

                dup 3 addi 1
                // _ [bbd] *claim[i]_si *proof[i]_si N i *claim[i] *proof[i]

                call {stark_verify}
                // _ [bbd] *claim[i]_si *proof[i]_si N i

                // update pointers and counter
                pick 3 read_mem 1 addi 1 add
                // _ [bbd] *proof[i]_si N i *claim[i+1]_si

                pick 3 read_mem 1 addi 1 add
                // _ [bbd] N i *claim[i+1]_si *proof[i+1]_si

                pick 3
                pick 3 addi 1
                // _ [bbd] *claim[i+1]_si *proof[i+1]_si N (i+1)

                recurse
        };

        let code = triton_asm! {
            // _

            read_io 5
            // _ [block_body_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint block_witness_ptr = stack[0]
            // _ [bbd] *w

            divine {Digest::LEN}
            // _ [bbd] *w [txkmh]

            {&verify_fee_legality}
            // _ [bbd] *w [txkmh]

            pop {Digest::LEN}
            // _ [bbd] *w

            /* verify appendix claims */
            dup 0 {&block_witness_field_claims}
            hint claims = stack[0]
            swap 1 {&block_witness_field_proofs}
            hint proofs = stack[1]
            // _ [bbd] *claims *proofs

            dup 1 read_mem 1 pop 1
            // _ [bbd] *claims *proofs N

            pick 2 addi 1
            pick 2 addi 1
            pick 2
            // _ [bbd] *claim[0] *proof[0] N

            push 0
            // _ [bbd] *claim[0] *proof[0] N 0

            call {verify_all_claims_loop}
            // _ [bbd] *claim[0] *proof[0] N N

            pop 4
            pop 5
            // _

            halt

            {&verify_all_claims_function}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use itertools::Itertools;
    use tasm_lib::triton_vm::vm::PublicInput;
    use tracing_test::traced_test;
    use triton_vm::prelude::Digest;

    use super::*;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::block::BlockPrimitiveWitness;
    use crate::models::blockchain::block::TritonVmProofJobOptions;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::proof_abstractions::SecretWitness;

    #[traced_test]
    #[test]
    fn block_program_halts_gracefully() {
        let block_primitive_witness = deterministic_block_primitive_witness();
        let block_body_mast_hash_as_input = PublicInput::new(
            block_primitive_witness
                .body()
                .mast_hash()
                .reversed()
                .values()
                .to_vec(),
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let block_proof_witness = rt
            .block_on(BlockProofWitness::produce(
                block_primitive_witness,
                &TritonVmJobQueue::dummy(),
            ))
            .unwrap();

        let block_program_nondeterminism = block_proof_witness.nondeterminism();
        let rust_output = BlockProgram
            .run_rust(
                &block_body_mast_hash_as_input,
                block_program_nondeterminism.clone(),
            )
            .unwrap();
        let tasm_output = match BlockProgram
            .run_tasm(&block_body_mast_hash_as_input, block_program_nondeterminism)
        {
            Ok(std_out) => std_out,
            Err(err) => panic!("{err:?}"),
        };

        assert_eq!(rust_output, tasm_output);

        let expected_output = block_proof_witness
            .claims()
            .iter()
            .flat_map(|appendix_claim| Tip5::hash(appendix_claim).values().to_vec())
            .collect_vec();
        assert_eq!(
            expected_output, tasm_output,
            "tasm output must equal rust output"
        );
    }

    // TODO: Add test that verifies that double spends *within* one block is
    //       disallowed.

    #[traced_test]
    #[test]
    fn disallow_double_spends_across_blocks() {
        let current_pw = deterministic_block_primitive_witness();
        let tx = current_pw.transaction().to_owned();
        assert!(
            !tx.kernel.inputs.is_empty(),
            "Transaction in double-spend test cannot be empty"
        );
        let predecessor = current_pw.predecessor_block().to_owned();
        let mock_now = predecessor.header().timestamp + Timestamp::months(12);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let current_block = rt
            .block_on(Block::block_template_from_block_primitive_witness(
                current_pw,
                mock_now,
                Digest::default(),
                None,
                &TritonVmJobQueue::dummy(),
                TritonVmProofJobOptions::default(),
            ))
            .unwrap();

        assert!(current_block.is_valid(&predecessor, mock_now));

        let mutator_set_update = current_block.mutator_set_update();
        let updated_tx = rt
            .block_on(
                Transaction::new_with_updated_mutator_set_records_given_proof(
                    tx.kernel,
                    &predecessor.mutator_set_accumulator_after(),
                    &mutator_set_update,
                    tx.proof.into_single_proof(),
                    &TritonVmJobQueue::dummy(),
                    TritonVmJobPriority::default().into(),
                ),
            )
            .unwrap();
        assert!(rt.block_on(updated_tx.is_valid()));

        let mock_later = mock_now + Timestamp::hours(3);
        let next_pw = BlockPrimitiveWitness::new(current_block.clone(), updated_tx);
        let next_block = rt
            .block_on(Block::block_template_from_block_primitive_witness(
                next_pw,
                mock_later,
                Digest::default(),
                None,
                &TritonVmJobQueue::dummy(),
                TritonVmProofJobOptions::default(),
            ))
            .unwrap();
        assert!(!next_block.is_valid(&current_block, mock_later));
    }
}
