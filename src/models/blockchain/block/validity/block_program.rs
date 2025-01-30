use std::sync::OnceLock;

use itertools::Itertools;
use tasm_lib::field;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::isa::triton_instr;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::Tip5;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tracing::debug;

use super::block_proof_witness::BlockProofWitness;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_body::BlockBodyField;
use crate::models::blockchain::block::BlockAppendix;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::builtins::verify_stark;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::verifier::verify;

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

    pub(crate) async fn verify(
        block_body: &BlockBody,
        appendix: &BlockAppendix,
        proof: &Proof,
    ) -> bool {
        let claim = Self::claim(block_body, appendix);
        let proof_clone = proof.clone();

        debug!("** Calling triton_vm::verify to verify block proof ...");
        let verdict = verify(claim, proof_clone).await;
        debug!("** Call to triton_vm::verify to verify block proof completed; verdict: {verdict}.");

        verdict
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
        let txk_mast_hash_as_leaf = Tip5::hash(&txk_mast_hash);
        tasmlib::tasmlib_hashing_merkle_verify(
            block_body_digest,
            BlockBodyField::TransactionKernel as u32,
            txk_mast_hash_as_leaf,
            BlockBody::MAST_HEIGHT as u32,
        );

        // Verify fee is legal
        let fee = &block_body.transaction_kernel.fee;
        let fee_hash = Tip5::hash(fee);
        tasmlib::tasmlib_hashing_merkle_verify(
            txk_mast_hash,
            TransactionKernelField::Fee as u32,
            fee_hash,
            TransactionKernel::MAST_HEIGHT as u32,
        );

        assert!(!fee.is_negative());
        assert!(*fee <= NativeCurrencyAmount::max());

        // Verify that merge bit is set
        let merge_bit_hash = Tip5::hash(&1);
        tasmlib::tasmlib_hashing_merkle_verify(
            txk_mast_hash,
            TransactionKernelField::MergeBit as u32,
            merge_bit_hash,
            TransactionKernel::MAST_HEIGHT as u32,
        );

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
        let coin_size = NativeCurrencyAmount::static_length().unwrap();
        let hash_fee = library.import(Box::new(HashStaticSize { size: coin_size }));
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();
        let u128_lt = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let hash_from_stack_digest = library.import(Box::new(HashFromStack::new(DataType::Digest)));
        let verify_fee_legality = triton_asm!(
            // _ *w [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push {TransactionKernel::MAST_HEIGHT}
            // _ *w [txkmh] [txkmh] txkm_height

            push {TransactionKernelField::Fee as u32}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index

            dup 12 {&block_body_field} {&body_field_kernel} {&kernel_field_fee}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee

            dup 0 addi {coin_size - 1} read_mem {coin_size} pop 1
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee [fee]

            {&push_max_amount}
            call {u128_lt}
            push 0 eq
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee (max >= fee)

            assert error_id {Self::ILLEGAL_FEE}
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index *fee

            call {hash_fee} pop 1
            // _ *w [txkmh] [txkmh] txkm_height fee_leaf_index [fee_hash]

            call {merkle_verify}
            // _ *w [txkmh]
        );

        let hash_of_one = Tip5::hash(&1);
        let push_hash_of_one = hash_of_one
            .values()
            .into_iter()
            .rev()
            .map(|b| triton_instr!(push b))
            .collect_vec();
        let verify_set_merge_bit = triton_asm!(
            // _ [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push {TransactionKernel::MAST_HEIGHT}
            // _ [txkmh] [txkmh] txkm_height

            push {TransactionKernelField::MergeBit as u32}
            // _ [txkmh] [txkmh] txkm_height leaf_index

            {&push_hash_of_one}
            // _ [txkmh] [txkmh] txkm_height fee_leaf_index [merge_bit_hash (true)]

            call {merkle_verify}
            // _ [txkmh]
        );

        let authenticate_txkmh = triton_asm!(
            // _ [bbd] *w [txkmh]

            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            call {hash_from_stack_digest}
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

            {&authenticate_txkmh}
            // _ [bbd] *w [txkmh]

            {&verify_fee_legality}
            // _ [bbd] *w [txkmh]

            {&verify_set_merge_bit}
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
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::vm::PublicInput;
    use tracing_test::traced_test;

    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::mine_loop::composer_parameters::ComposerParameters;
    use crate::mine_loop::create_block_transaction_stateless;
    use crate::models::blockchain::block::validity::block_primitive_witness::test::deterministic_block_primitive_witness;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::block::TritonVmProofJobOptions;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::proof_abstractions::SecretWitness;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::transaction_output::TxOutput;
    use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;

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
            .block_on(BlockProofWitness::produce(block_primitive_witness))
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
    #[tokio::test]
    async fn disallow_double_spends_across_blocks() {
        async fn mine_tx(
            tx: Transaction,
            predecessor: &Block,
            composer_parameters: ComposerParameters,
            timestamp: Timestamp,
            rng: &mut StdRng,
        ) -> Block {
            let (block_tx, _) = create_block_transaction_stateless(
                predecessor,
                composer_parameters,
                timestamp,
                rng.gen(),
                &TritonVmJobQueue::dummy(),
                (TritonVmJobPriority::Normal, None).into(),
                vec![tx],
            )
            .await
            .unwrap();

            Block::compose(
                predecessor,
                block_tx,
                timestamp,
                None,
                &TritonVmJobQueue::dummy(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap()
        }

        let network = Network::Main;
        let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
        let alice_wallet = WalletSecret::devnet_wallet();
        let alice = mock_genesis_global_state(
            network,
            3,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

        let alice_key = alice_wallet.nth_generation_spending_key_for_tests(0);
        let fee = NativeCurrencyAmount::coins(1);
        let tx_output = TxOutput::offchain_native_currency(
            NativeCurrencyAmount::coins(1),
            rng.gen(),
            alice_key.to_address().into(),
            false,
        );

        let genesis_block = Block::genesis(network);
        let now = genesis_block.header().timestamp + Timestamp::months(12);
        let (tx, _) = alice
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                vec![tx_output].into(),
                alice_key.into(),
                UtxoNotificationMedium::OffChain,
                fee,
                now,
                TxProvingCapability::SingleProof,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();
        let composer_parameters = alice
            .lock_guard()
            .await
            .composer_parameters(alice_key.to_address().into());
        let block1 = mine_tx(
            tx.clone(),
            &genesis_block,
            composer_parameters.clone(),
            now,
            &mut rng,
        )
        .await;

        // Update transaction, stick it into block 2, and verify that block 2
        // is invalid.
        let later = now + Timestamp::months(1);
        let tx = Transaction::new_with_updated_mutator_set_records_given_proof(
            tx.kernel,
            &genesis_block.mutator_set_accumulator_after(),
            &block1.mutator_set_update(),
            tx.proof.into_single_proof(),
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
            Some(later),
        )
        .await
        .unwrap();

        let block2 = mine_tx(tx, &block1, composer_parameters, later, &mut rng).await;
        assert!(
            !block2.is_valid(&block1, later).await,
            "Block doing a double-spend must be invalid."
        );
    }
}
