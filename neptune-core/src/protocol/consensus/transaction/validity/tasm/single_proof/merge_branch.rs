pub mod authenticate_coinbase_fields;

use std::cmp::max;
use std::sync::Arc;

use anyhow::Result;
use authenticate_coinbase_fields::AuthenticateCoinbaseFields;
use itertools::Itertools;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::list::higher_order::inner_function::InnerFunction;
use tasm_lib::list::higher_order::inner_function::RawCode;
use tasm_lib::list::higher_order::map::ChainMap;
use tasm_lib::list::higher_order::map::Map;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tracing::info;

use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::prelude::triton_vm::prelude::triton_asm;
use crate::protocol::consensus::block::block_transaction::BlockOrRegularTransaction;
use crate::protocol::consensus::block::block_transaction::BlockOrRegularTransactionKernel;
use crate::protocol::consensus::block::block_transaction::BlockTransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
use crate::protocol::consensus::transaction::validity::single_proof::SingleProof;
use crate::protocol::consensus::transaction::validity::single_proof::SingleProofWitness;
use crate::protocol::consensus::transaction::validity::single_proof::DISCRIMINANT_FOR_MERGE;
use crate::protocol::consensus::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::protocol::consensus::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::protocol::consensus::transaction::validity::tasm::hash_removal_record_index_sets::HashRemovalRecordIndexSets;
use crate::protocol::consensus::transaction::BFieldCodec;
use crate::protocol::consensus::transaction::Proof;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::transaction::TransactionKernel;
use crate::protocol::consensus::transaction::TransactionKernelProxy;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::protocol::proof_abstractions::timestamp::Timestamp;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::triton_vm::prelude::NonDeterminism;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;

// Dictated by the witness type of SingleProof
const MERGE_WITNESS_ADDRESS: BFieldElement = BFieldElement::new(2);

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub struct MergeWitness {
    // This field, exceptionally, *CAN* contain packed `RemovalRecord`s.
    pub(crate) left_kernel: TransactionKernel,
    pub(crate) right_kernel: TransactionKernel,

    // This field, exceptionally, *CAN* contain packed `RemovalRecord`s.
    pub(crate) new_kernel: TransactionKernel,
    pub(crate) left_proof: Proof,
    pub(crate) right_proof: Proof,
}

impl MergeWitness {
    pub(crate) fn for_composition(
        left: BlockOrRegularTransaction,
        right: Transaction,
        shuffle_seed: [u8; 32],
    ) -> Self {
        let left_kernel = left.kernel();
        let right_kernel = right.kernel;

        let TransactionProof::SingleProof(left_proof) = left.proof() else {
            panic!("cannot merge transactions that are not supported by singleproof");
        };
        let TransactionProof::SingleProof(right_proof) = right.proof else {
            panic!("cannot merge transactions that are not supported by singleproof");
        };

        assert!(
            right_kernel.coinbase.is_none(),
            "Coinbase transaction must be left hand side"
        );

        let new_kernel =
            Self::new_block_transaction_kernel(&left_kernel, &right_kernel, shuffle_seed);

        Self {
            left_kernel: left_kernel.into(),
            right_kernel,
            new_kernel: new_kernel.into(),
            left_proof,
            right_proof,
        }
    }

    /// Generate a `MergeWitness` from two transactions (kernels plus proofs).
    /// Assumes the transactions can be merged. Takes randomness for shuffling
    /// the concatenations of inputs, outputs, and announcements.
    pub(crate) fn from_transactions(
        left: Transaction,
        right: Transaction,
        shuffle_seed: [u8; 32],
    ) -> Self {
        let left_kernel = left.kernel;
        let right_kernel = right.kernel;

        let TransactionProof::SingleProof(left_proof) = left.proof else {
            panic!("cannot merge transactions that are not supported by singleproof");
        };
        let TransactionProof::SingleProof(right_proof) = right.proof else {
            panic!("cannot merge transactions that are not supported by singleproof");
        };

        assert!(
            left_kernel.coinbase.is_none() && right_kernel.coinbase.is_none(),
            "Cannot use this function for coinbase transactions"
        );

        let new_kernel = Self::new_kernel(&left_kernel, &right_kernel, shuffle_seed);

        Self {
            left_kernel,
            right_kernel,
            new_kernel,
            left_proof,
            right_proof,
        }
    }

    /// Compute the [`Transaction`] (with [`SingleProof`]) resulting from this
    /// merger. Generates the proof for the merged transaction.
    pub(crate) async fn merge(
        self,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Result<Transaction> {
        let new_kernel = self.new_kernel.clone();

        let new_single_proof_witness = SingleProofWitness::from_merge(self);
        let new_single_proof_claim = new_single_proof_witness.claim();
        info!("Start: creating new single proof through merge");
        let new_single_proof = SingleProof
            .prove(
                new_single_proof_claim,
                new_single_proof_witness.nondeterminism(),
                triton_vm_job_queue,
                proof_job_options,
            )
            .await?;

        info!("Done: creating new single proof through merge");

        Ok(Transaction {
            kernel: new_kernel,
            proof: TransactionProof::SingleProof(new_single_proof),
        })
    }

    fn new_block_transaction_kernel(
        left_kernel: &BlockOrRegularTransactionKernel,
        right_kernel: &TransactionKernel,
        shuffle_seed: [u8; 32],
    ) -> BlockTransactionKernel {
        let lhs = match left_kernel {
            BlockOrRegularTransactionKernel::Regular(regular) => regular.clone(),
            BlockOrRegularTransactionKernel::Block(block_transaction_kernel) => {
                let transaction_kernel: TransactionKernel = block_transaction_kernel.clone().into();
                let inputs = RemovalRecordList::try_unpack(transaction_kernel.inputs.clone())
                    .expect(
                    "inputs must be packed for block transactions when required by merge version",
                );
                TransactionKernelModifier::default()
                    .inputs(inputs)
                    .modify(transaction_kernel)
            }
        };

        let mut new_kernel = Self::new_kernel(&lhs, right_kernel, shuffle_seed);

        let inputs = RemovalRecordList::pack(new_kernel.inputs.clone());
        new_kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(new_kernel);

        BlockTransactionKernel::try_from(new_kernel).expect("merge bit should be set")
    }

    /// Generate a new transaction kernel from two transactions.
    ///
    /// Assumes the [`RemovalRecord`](crate::util_types::mutator_set::removal_record::RemovalRecord)s
    /// in both arguments are not packed.
    pub(super) fn new_kernel(
        left_kernel: &TransactionKernel,
        right_kernel: &TransactionKernel,
        shuffle_seed: [u8; 32],
    ) -> TransactionKernel {
        assert_eq!(
            left_kernel.mutator_set_hash, right_kernel.mutator_set_hash,
            "Attempted to merge transaction kernel with non-matching mutator set hashes"
        );
        assert!(
            !right_kernel.fee.is_negative(),
            "attempting to merge with RHS transaction whose fee is negative; negative fees only allowed on LHS"
        );
        assert!(
            right_kernel.coinbase.is_none(),
            "Coinbase only allowed in LHS transaction"
        );
        let mut rng: StdRng = SeedableRng::from_seed(shuffle_seed);

        let old_coinbase = left_kernel.coinbase;

        let mut inputs = [left_kernel.inputs.clone(), right_kernel.inputs.clone()].concat();
        inputs.shuffle(&mut rng);
        let mut outputs = [left_kernel.outputs.clone(), right_kernel.outputs.clone()].concat();
        outputs.shuffle(&mut rng);
        let mut announcements = [
            left_kernel.announcements.clone(),
            right_kernel.announcements.clone(),
        ]
        .concat();
        announcements.shuffle(&mut rng);

        TransactionKernelProxy {
            inputs,
            outputs,
            announcements,
            fee: left_kernel.fee + right_kernel.fee,
            coinbase: old_coinbase,
            timestamp: max(left_kernel.timestamp, right_kernel.timestamp),
            mutator_set_hash: left_kernel.mutator_set_hash,
            merge_bit: true,
        }
        .into_kernel()
    }

    pub(crate) fn populate_nd_streams(
        &self,
        nondeterminism: &mut NonDeterminism,
        single_proof_program_hash: Digest,
    ) {
        // txk digests come from secin / individual tokens
        nondeterminism.individual_tokens.extend(
            [
                self.left_kernel.mast_hash().reversed().values().to_vec(),
                self.right_kernel.mast_hash().reversed().values().to_vec(),
            ]
            .concat(),
        );

        // update nondeterminism in accordance with proof-verification
        let verify_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());
        let left_claim = Claim::new(single_proof_program_hash)
            .with_input(self.left_kernel.mast_hash().reversed().values());
        let right_claim = Claim::new(single_proof_program_hash)
            .with_input(self.right_kernel.mast_hash().reversed().values());

        verify_snippet.update_nondeterminism(nondeterminism, &self.left_proof, &left_claim);
        verify_snippet.update_nondeterminism(nondeterminism, &self.right_proof, &right_claim);

        // set digests
        let digests = [
            self.left_kernel.mast_path(TransactionKernelField::Inputs),
            self.right_kernel.mast_path(TransactionKernelField::Inputs),
            self.new_kernel.mast_path(TransactionKernelField::Inputs),
            //
            self.left_kernel.mast_path(TransactionKernelField::Outputs),
            self.right_kernel.mast_path(TransactionKernelField::Outputs),
            self.new_kernel.mast_path(TransactionKernelField::Outputs),
            self.left_kernel
                .mast_path(TransactionKernelField::Announcements),
            self.right_kernel
                .mast_path(TransactionKernelField::Announcements),
            self.new_kernel
                .mast_path(TransactionKernelField::Announcements),
            self.left_kernel.mast_path(TransactionKernelField::Fee),
            self.right_kernel.mast_path(TransactionKernelField::Fee),
            self.new_kernel.mast_path(TransactionKernelField::Fee),
            //
            self.left_kernel.mast_path(TransactionKernelField::Coinbase),
            self.right_kernel
                .mast_path(TransactionKernelField::Coinbase),
            self.new_kernel.mast_path(TransactionKernelField::Coinbase),
            //
            self.left_kernel
                .mast_path(TransactionKernelField::Timestamp),
            self.right_kernel
                .mast_path(TransactionKernelField::Timestamp),
            self.new_kernel.mast_path(TransactionKernelField::Timestamp),
            //
            self.left_kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            self.right_kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            self.new_kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            //
            self.new_kernel.mast_path(TransactionKernelField::MergeBit),
        ]
        .concat();
        nondeterminism.digests.extend(digests);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MergeBranch;

impl MergeBranch {
    const RIGHT_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT: i128 = 1_000_070;
    const NEW_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT: i128 = 1_000_071;
}

impl BasicSnippet for MergeBranch {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "single_proof_program_digest".to_owned()),
            (DataType::Digest, "new_tx_kernel_digest".to_owned()),
            (DataType::VoidPointer, "single_proof_witness".to_owned()),
            (DataType::Bfe, "discriminant".to_owned()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "single_proof_program_digest".to_owned()),
            (DataType::Digest, "new_tx_kernel_digest".to_owned()),
            (DataType::VoidPointer, "single_proof_witness".to_owned()),
            (DataType::Bfe, "minus_1".to_owned()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_single_proof_merge_branch".to_owned()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let authenticate_txk_input_field = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Inputs,
        )));
        let authenticate_txk_output_field = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Outputs,
        )));
        let authenticate_txk_pub_announcement_field = library.import(Box::new(
            AuthenticateTxkField(TransactionKernelField::Announcements),
        ));
        let authenticate_txk_fee_field =
            library.import(Box::new(AuthenticateTxkField(TransactionKernelField::Fee)));
        let hash_1_removal_record_index_set =
            library.import(Box::new(HashRemovalRecordIndexSets::<1>));
        let hash_2_removal_record_index_sets =
            library.import(Box::new(HashRemovalRecordIndexSets::<2>));
        let multiset_equality = library.import(Box::new(MultisetEqualityDigests));

        debug_assert!(AdditionRecord::static_length().is_some());
        let hash_transaction_output = RawCode::new(
            triton_asm! {
                hash_tx_output:
                    push 0 push 0 push 0 push 0 push 0
                    pick 9 pick 9 pick 9 pick 9 pick 9
                    hash
                    return
            },
            DataType::Digest, // addition record
            DataType::Digest,
        );
        let hash_1_list_of_outputs = library.import(Box::new(Map::new(InnerFunction::RawCode(
            hash_transaction_output.clone(),
        ))));
        let hash_2_lists_of_outputs = library.import(Box::new(ChainMap::<2>::new(
            InnerFunction::RawCode(hash_transaction_output),
        )));

        let hash_varlen = library.import(Box::new(HashVarlen));
        let hash_announcement = RawCode::new(
            triton_asm! {hash_announcement: call {hash_varlen} return },
            DataType::Tuple(vec![DataType::VoidPointer, DataType::Bfe]),
            DataType::Digest,
        );
        let hash_1_list_of_announcements = library.import(Box::new(Map::new(
            InnerFunction::RawCode(hash_announcement.clone()),
        )));
        let hash_2_lists_of_announcements = library.import(Box::new(ChainMap::<2>::new(
            InnerFunction::RawCode(hash_announcement),
        )));

        let digest_len = u32::try_from(Digest::LEN).unwrap();
        let left_txk_mast_hash_alloc = library.kmalloc(digest_len);
        let right_txk_mast_hash_alloc = library.kmalloc(digest_len);
        let new_txk_mast_hash_alloc = library.kmalloc(digest_len);

        let assert_coinbase_rules = library.import(Box::new(AuthenticateCoinbaseFields::new(
            left_txk_mast_hash_alloc,
            right_txk_mast_hash_alloc,
            new_txk_mast_hash_alloc,
        )));

        let neptune_coins_size = NativeCurrencyAmount::static_length().unwrap();
        let kernel_field_fee = field!(TransactionKernel::fee);
        let overflowing_add_u128 = library.import(Box::new(
            crate::tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd,
        ));
        let compare_u128 = DataType::U128.compare();
        let lt_u128 = library.import(Box::new(crate::tasm_lib::arithmetic::u128::lt::Lt));
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();

        let assert_new_fee_is_sum_of_left_and_right = triton_asm!(
            // _ *left_txk *right_txk *new_txk

            // 1. get left fee
            // 2. authenticate against left kernel mast hash
            // 3. same right, but also check non-negativity
            // 4. add fees
            // 5. authenticate against new kernel mast hash

            /* 1. */
            dup 2 {&kernel_field_fee}
            // _ *left_txk *right_txk *new_txk *left_fee


            /* 2. */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *left_txk *right_txk *new_txk *left_fee [left_txkmh]

            dup 5
            push {neptune_coins_size}
            // _ *left_txk *right_txk *new_txk *left_fee [left_txkmh] *left_fee size

            call {authenticate_txk_fee_field}
            // _ *left_txk *right_txk *new_txk *left_fee

            /* 3. */
            dup 2 {&kernel_field_fee}
            // _ *left_txk *right_txk *new_txk *left_fee *right_fee

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            //  _ *left_txk *right_txk *new_txk *left_fee *right_fee [right_txkmh]

            dup 5
            push {neptune_coins_size}
            call {authenticate_txk_fee_field}
            // _ *left_txk *right_txk *new_txk *left_fee *right_fee

            dup 0 addi {neptune_coins_size-1}
            read_mem {neptune_coins_size} pop 1
            // _ *left_txk *right_txk *new_txk *left_fee *right_fee [right_fee]

            {&push_max_amount}
            // _ *left_txk *right_txk *new_txk *left_fee *right_fee [right_fee] [max_amount]

            /* Ensure right fee is less than or equal to max amount, also guarantees that right
               fee is not negative. */
            call {lt_u128}
            // _ *left_txk *right_txk *new_txk *left_fee *right_fee (max_amount < right_fee)

            push 0 eq
            // _ *left_txk *right_txk *new_txk *left_fee *right_fee (max_amount >= right_fee)

            assert error_id {Self::RIGHT_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT}

            /* 4. */
            addi {neptune_coins_size -1}
            read_mem {neptune_coins_size}
            pop 1
            // _ *left_txk *right_txk *new_txk *left_fee [right_fee;4]

            pick {neptune_coins_size}
            // _ *left_txk *right_txk *new_txk [right_fee;4] *left_fee

            addi {neptune_coins_size -1}
            read_mem {neptune_coins_size}
            pop 1
            // _ *left_txk *right_txk *new_txk [right_fee;4] [left_fee;4]

            call {overflowing_add_u128}
            // _ *left_txk *right_txk *new_txk [calculated_new_fee;4] overflow

            // The left fee can be negative, in which case there will be
            // overflow when performing u128 addition.
            pop 1
            // _ *left_txk *right_txk *new_txk [calculated_new_fee;4]

            dup 3
            dup 3
            dup 3
            dup 3
            {&push_max_amount}
            // _ *left_txk *right_txk *new_txk [calculated_new_fee;4] [new_fee] [max_amount]

            call {lt_u128}
            // _ *left_txk *right_txk *new_txk [calculated_new_fee;4] (max_amount < new_fee)

            push 0 eq
            // _ *left_txk *right_txk *new_txk [calculated_new_fee;4] (max_amount >= new_fee)

            assert error_id {Self::NEW_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT}

            /* 5. */
            dup {neptune_coins_size}
            {&kernel_field_fee}
            addi {neptune_coins_size -1}
            read_mem {neptune_coins_size}
            // _ *left_txk *right_txk *new_txk [calculated_new_fee;4] [read_new_fee;4] (*new_fee-1)

            addi 1
            place {2*neptune_coins_size}
            // _ *left_txk *right_txk *new_txk *new_fee [calculated_new_fee;4] [read_new_fee;4]

            {&compare_u128}
            // _ *left_txk *right_txk *new_txk *new_fee (calculated_new_fee == read_new_fee)

            assert
            // _ *left_txk *right_txk *new_txk *new_fee

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *left_txk *right_txk *new_txk *new_fee [new_txkmh]

            pick {Digest::LEN}
            // _ *left_txk *right_txk *new_txk [new_txkmh] *new_fee

            push {neptune_coins_size}
            call {authenticate_txk_fee_field}
            // _ *left_txk *right_txk *new_txk
        );

        let lt_u64 = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));
        let kernel_field_timestamp = field!(TransactionKernel::timestamp);
        let authenticate_kernel_field_timestamp = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Timestamp,
        )));
        let timestamp_size = Timestamp::static_length().unwrap();

        let assert_new_timestamp_is_max_of_left_and_right = triton_asm! {
            // _ *merge_witness *l_txk *r_txk *n_txk

            // read left timestamp
            dup 2 {&kernel_field_timestamp}
            read_mem 1 addi 1
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp *left_timestamp

            // authenticate left timestamp against left txkmh
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp *left_timestamp [left_txkmh]

            pick {Digest::LEN}
            push {timestamp_size}
            call {authenticate_kernel_field_timestamp}
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp

            // read right timestamp
            dup 2 {&kernel_field_timestamp}
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp *right_timestamp
            read_mem 1 addi 1
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp right_timestamp *right_timestamp

            // authenticate right timestamp
            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp right_timestamp *right_timestamp [right_txkmh]

            pick {Digest::LEN}
            push {timestamp_size}
            call {authenticate_kernel_field_timestamp}
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp right_timestamp

            // compute max
            dup 1 split
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp right_timestamp lhi llo

            dup 2 split
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp right_timestamp lhi llo rhi rlo

            call {lt_u64}
            // _ *merge_witness *l_txk *r_txk *n_txk right_timestamp_hi right_timestamp_lo left_timestamp_hi left_timestamp_lo (right_timestamp < left_timestamp)
            // _ *merge_witness *l_txk *r_txk *n_txk left_timestamp right_timestamp (r<l)

            pick 2 dup 1 mul place 2
            // _ *merge_witness *l_txk *r_txk *n_txk ((r<l)*left_timestamp) right_timestamp (r<l)

            push 0 eq mul
            // _ *merge_witness *l_txk *r_txk *n_txk ((r<l)*left_timestamp) ((r>=l)*right_timestamp)

            add
            // _ *merge_witness *l_txk *r_txk *n_txk max_timestamp


            // read new kernel timestamp
            dup 1 {&kernel_field_timestamp}
            // _ *merge_witness *l_txk *r_txk *n_txk max_timestamp *new_timestamp

            read_mem 1 addi 1
            // _ *merge_witness *l_txk *r_txk *n_txk max_timestamp new_timestamp *new_timestamp

            place 2 eq assert
            // _ *merge_witness *l_txk *r_txk *n_txk *new_timestamp

            // authenticate new timestamp
            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk *new_timestamp [new_txkmh]

            pick {Digest::LEN}
            push {timestamp_size}
            call {authenticate_kernel_field_timestamp}
            // _ *merge_witness *l_txk *r_txk *n_txk

        };

        let kernel_field_mutator_set_hash = field!(TransactionKernel::mutator_set_hash);
        let compare_digests = DataType::Digest.compare();
        let authenticate_kernel_field_mutator_set_hash = library.import(Box::new(
            AuthenticateTxkField(TransactionKernelField::MutatorSetHash),
        ));

        let assert_all_kernels_agree_on_mutator_set_hash = triton_asm! {
            // _ *merge_witness *l_txk *r_txk *n_txk

            // read left msh
            dup 2 {&kernel_field_mutator_set_hash}
            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            addi 1
            place {Digest::LEN}
            // _ *merge_witness *l_txk *r_txk *n_txk *left_msh [left_msh]

            // authenticate against left txkmh
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk *left_msh [left_msh] [left_txkmh]

            pick {2*Digest::LEN}
            push {Digest::LEN}
            call {authenticate_kernel_field_mutator_set_hash}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh]

            // read right msh
            dup 6 {&kernel_field_mutator_set_hash}
            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            addi 1
            place {Digest::LEN}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *right_msh [right_msh]

            // assert equal
            dup 10 dup 10 dup 10 dup 10 dup 10
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *right_msh [right_msh] [left_msh]

            {&compare_digests} assert
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *right_msh

            // authenticate against right txkmh
            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *right_msh [right_txkmh]

            pick {Digest::LEN}
            push {Digest::LEN}
            call {authenticate_kernel_field_mutator_set_hash}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh]

            // read new msh
            dup 5 {&kernel_field_mutator_set_hash}
            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            addi 1
            place {Digest::LEN}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *new_msh [new_msh]

            // assert equal
            dup 10 dup 10 dup 10 dup 10 dup 10
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *new_msh [new_msh] [left_msh]

            {&compare_digests} assert
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *new_msh

            // authenticate against new txkmh
            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh] *new_msh [new_txkmh]

            pick {Digest::LEN}
            push {Digest::LEN}
            call {authenticate_kernel_field_mutator_set_hash}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh]

            pop 5
            // _ *merge_witness *l_txk *r_txk *n_txk
        };

        let hash_of_one = Tip5::hash(&1);
        let push_hash_of_one = hash_of_one
            .values()
            .into_iter()
            .rev()
            .map(|b| triton_instr!(push b))
            .collect_vec();
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let assert_new_merge_bit_set = triton_asm! {
            // _

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ [new_txkmh]

            push {TransactionKernel::MAST_HEIGHT}

            push {TransactionKernelField::MergeBit as u32}

            {&push_hash_of_one}
            // _ [new_txkmh] height index [hash_of_one]

            call {merkle_verify}
            // _
        };

        let audit_witness =
            library.import(Box::new(VerifyNdSiIntegrity::<MergeWitness>::default()));

        let entrypoint = self.entrypoint();
        triton_asm! {
            {entrypoint}:
            // _ [program_digest] [new_txk_digest] *spw disc

            place 11
            place 10
            // _ disc *spw [program_digest] [new_txk_digest]
            // _ [program_digest] [new_txk_digest] <-- rename

            push {MERGE_WITNESS_ADDRESS}
            hint  merge_witness: Pointer = stack[0]
            // _ [program_digest] [new_txk_digest] *merge_witness

            dup 0
            call {audit_witness}
            // _ [program_digest] [new_txk_digest] *merge_witness witness_size

            pop 1
            // _ [program_digest] [new_txk_digest] *merge_witness

            place 10
            // _ *merge_witness [program_digest] [new_txk_digest]
            push {new_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ *merge_witness [program_digest]

            divine {Digest::LEN}
            hint  left_tx_kernel_digest: Digest = stack[0..5]
            // _ *merge_witness [program_digest] [left_txk_digest]

            dup 4 dup 4 dup 4 dup 4 dup 4
            push {left_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ *merge_witness [program_digest] [left_txk_digest]

            dup 9 dup 9 dup 9 dup 9 dup 9
            call {generate_single_proof_claim}
            hint  left_claim: Pointer = stack[0]
            // _ *merge_witness [program_digest] *left_claim

            divine {Digest::LEN}
            hint  right_tx_kernel_digest: Digest = stack[0..5]
            // _ *merge_witness [program_digest] *left_claim [right_txk_digest]

            dup 4 dup 4 dup 4 dup 4 dup 4
            push {right_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ *merge_witness [program_digest] *left_claim [right_txk_digest]

            dup 10 dup 10 dup 10 dup 10 dup 10
            call {generate_single_proof_claim}
            hint  right_claim: Pointer = stack[0]
            // _ *merge_witness [program_digest] *left_claim *right_claim

            place 6
            place 5
            // _ *merge_witness *right_claim *left_claim [program_digest]
            // _ *merge_witness *right_claim *left_claim pd4 pd3 pd2 pd1 pd0

            place 7
            place 7
            place 7
            place 7
            place 7
            // _ pd4 pd3 pd2 pd1 pd0 *merge_witness *right_claim *left_claim
            // _ [program_digest] *merge_witness *right_claim *left_claim <-- rename
            // _ *merge_witness *right_claim *left_claim <-- rename

            dup 2
            {&field!(MergeWitness::left_proof)}
            // _ *merge_witness *right_claim *left_claim *left_proof

            call {stark_verify}
            // _ *merge_witness *right_claim

            dup 1
            {&field!(MergeWitness::right_proof)}
            // _ *merge_witness *right_claim *right_proof

            call {stark_verify}
            // _ *merge_witness
            /* Now, left and right transaction kernel MAST hashes are authenticated */


            /* Now, check values in new kernel */
            dup 0
            {&field!(MergeWitness::left_kernel)}
            hint  left_tx_kernel: Pointer = stack[0]
            dup 1
            {&field!(MergeWitness::right_kernel)}
            hint  right_tx_kernel: Pointer = stack[0]
            dup 2
            {&field!(MergeWitness::new_kernel)}
            hint  new_tx_kernel: Pointer = stack[0]
            // _ *merge_witness *left_tx_kernel *right_tx_kernel *new_tx_kernel

            /* new inputs are a permutation of the operands' inputs' concatenation */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest]
            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest] *l_txk_in size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [left_txk_digest] *l_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [right_txk_digest]
            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [right_txk_digest] *r_txk_in size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [right_txk_digest] *r_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [new_txk_digest]

            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [new_txk_digest] *n_txk_in size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in *n_txk_in [new_txk_digest] *n_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in *n_txk_in

            call {hash_1_removal_record_index_set}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in *n_txk_in_digests

            place 2
            call {hash_2_removal_record_index_sets}
            // _ *merge_witness *l_txk *r_txk *n_txk *n_txk_in_digests *lr_in_digests

            call {multiset_equality}
            assert
            // _ *merge_witness *l_txk *r_txk *n_txk


            /* new outputs are a permutation of the operands' outputs' concatenation */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest] *l_txk_out size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [left_txk_digest] *l_txk_out size
            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [right_txk_digest]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [right_txk_digest] *r_txk_out size

            dup 1
            place 7
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [right_txk_digest] *r_txk_out size

            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [new_txk_digest]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [new_txk_digest] *n_txk_out size

            dup 1
            place 7
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out *n_txk_out [new_txk_digest] *n_txk_out size

            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out *n_txk_out

            /* left + right outputs must equal new outputs */
            call {hash_1_list_of_outputs}
            place 2
            call {hash_2_lists_of_outputs}
            call {multiset_equality}
            assert
            // _ *merge_witness *l_txk *r_txk *n_txk

            /* Check integrity of announcement fields */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest]
            dup 7
            {&field_with_size!(TransactionKernel::announcements)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest] *l_txk_pa size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa [left_txk_digest] *l_txk_pa size
            call {authenticate_txk_pub_announcement_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa [right_txk_digest]
            dup 7
            {&field_with_size!(TransactionKernel::announcements)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa [right_txk_digest] *r_txk_pa size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa [right_txk_digest] *r_txk_pa size
            call {authenticate_txk_pub_announcement_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa [new_txk_digest]

            dup 7
            {&field_with_size!(TransactionKernel::announcements)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa [new_txk_digest] *n_txk_pa size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa *n_txk_pa [new_txk_digest] *n_txk_pa size
            call {authenticate_txk_pub_announcement_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa *n_txk_pa

            /* left + right announcements must equal new announcements */
            call {hash_1_list_of_announcements}
            place 2
            call {hash_2_lists_of_announcements}
            call {multiset_equality}
            assert
            // _ *merge_witness *l_txk *r_txk *n_txk

            /* New kernel fee must be sum of old fees */
            {&assert_new_fee_is_sum_of_left_and_right}
            // _ *merge_witness *l_txk *r_txk *n_txk

            dup 2
            dup 2
            dup 2
            call {assert_coinbase_rules}
            // _ *merge_witness *l_txk *r_txk *n_txk

            {&assert_new_timestamp_is_max_of_left_and_right}
            // _ *merge_witness *l_txk *r_txk *n_txk

            {&assert_all_kernels_agree_on_mutator_set_hash}
            // _ *merge_witness *l_txk *r_txk *n_txk

            {&assert_new_merge_bit_set}
            // _ *merge_witness *l_txk *r_txk *n_txk

            pop 4
            // _
            // _ disc *spw [program_digest]

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ disc *spw [program_digest] [new_txk_digest]

            pick 10
            pick 11
            // _ [program_digest] [new_txk_mhash] *spw disc

            addi {-(DISCRIMINANT_FOR_MERGE as isize) - 1}
            // _ [program_digest] [new_txk_mhash] *spw -1

            return
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use itertools::Itertools;
    use num_traits::CheckedAdd;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use strum::EnumCount;

    use super::*;
    use crate::api::export::Network;
    use crate::application::triton_vm_job_queue::TritonVmJobQueue;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::validity::single_proof::produce_single_proof;
    use crate::protocol::consensus::transaction::PrimitiveWitness;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl MergeWitness {
        pub fn branch_source(&self, single_proof_program_digest: Digest, new_txk_digest: Digest) {
            // divine the witness for this proof
            let mw = tasm::decode_from_memory::<MergeWitness>(MERGE_WITNESS_ADDRESS);

            // divine the left and right kernels of the operand transactions
            let left_txk_digest = tasm::tasmlib_io_read_secin___digest();
            let right_txk_digest = tasm::tasmlib_io_read_secin___digest();

            // verify the proofs of the operand transactions
            let left_claim = Claim::new(single_proof_program_digest)
                .with_input(left_txk_digest.reversed().values().to_vec());
            let right_claim = Claim::new(single_proof_program_digest)
                .with_input(right_txk_digest.reversed().values().to_vec());

            tasm::verify_stark(Stark::default(), &left_claim, &mw.left_proof);
            tasm::verify_stark(Stark::default(), &right_claim, &mw.right_proof);

            let tree_height = TransactionKernelField::COUNT.next_power_of_two().ilog2();

            // new inputs are a permutation of the operands' inputs' concatenation
            // up to chunk dictionaries.
            let left_inputs: &Vec<RemovalRecord> = &mw.left_kernel.inputs;
            let right_inputs: &Vec<RemovalRecord> = &mw.right_kernel.inputs;
            let new_inputs: &Vec<RemovalRecord> = &mw.new_kernel.inputs;

            let assert_input_integrity = |merkle_root, inputs| {
                let leaf_index = TransactionKernelField::Inputs as u32;
                let leaf = Tip5::hash(inputs);
                tasm::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
            };
            assert_input_integrity(left_txk_digest, left_inputs);
            assert_input_integrity(right_txk_digest, right_inputs);
            assert_input_integrity(new_txk_digest, new_inputs);

            let to_merge_inputs = left_inputs
                .iter()
                .chain(right_inputs)
                .map(|rr| rr.absolute_indices.to_vec())
                .map(|v| Tip5::hash(&v))
                .sorted()
                .collect_vec();
            let merged_inputs = new_inputs
                .iter()
                .map(|rr| rr.absolute_indices.to_vec())
                .map(|v| Tip5::hash(&v))
                .sorted()
                .collect_vec();
            assert_eq!(to_merge_inputs, merged_inputs);

            // new outputs are a permutation of the operands' outputs' concatenation
            let left_outputs = &mw.left_kernel.outputs;
            let right_outputs = &mw.right_kernel.outputs;
            let new_outputs = &mw.new_kernel.outputs;

            let assert_output_integrity = |merkle_root, outputs| {
                let leaf_index = TransactionKernelField::Outputs as u32;
                let leaf = Tip5::hash(outputs);
                tasm::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height)
            };
            assert_output_integrity(left_txk_digest, left_outputs);
            assert_output_integrity(right_txk_digest, right_outputs);
            assert_output_integrity(new_txk_digest, new_outputs);

            let to_merge_outputs = left_outputs
                .iter()
                .chain(right_outputs)
                .map(Tip5::hash)
                .sorted()
                .collect_vec();
            let merged_outputs = new_outputs.iter().map(Tip5::hash).sorted().collect_vec();
            assert_eq!(to_merge_outputs, merged_outputs);

            // new announcements is a permutation of operands' public
            // announcements' concatenation
            let left_announcements = &mw.left_kernel.announcements;
            let right_announcements = &mw.right_kernel.announcements;
            let new_announcements = &mw.new_kernel.announcements;

            let assert_announcement_integrity = |merkle_root, announcements| {
                let leaf_index = TransactionKernelField::Announcements as u32;
                let leaf = Tip5::hash(announcements);
                tasm::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
            };
            assert_announcement_integrity(left_txk_digest, left_announcements);
            assert_announcement_integrity(right_txk_digest, right_announcements);
            assert_announcement_integrity(new_txk_digest, new_announcements);

            let to_merge_announcements = left_announcements
                .iter()
                .chain(right_announcements)
                .map(Tip5::hash)
                .sorted()
                .collect_vec();
            let merged_announcements = new_announcements
                .iter()
                .map(Tip5::hash)
                .sorted()
                .collect_vec();
            assert_eq!(to_merge_announcements, merged_announcements);

            // new fee is sum of operand fees
            let left_fee = mw.left_kernel.fee;
            let right_fee = mw.right_kernel.fee;
            assert!(!right_fee.is_negative());
            let new_fee = if left_fee.is_negative() {
                left_fee.checked_add_negative(&right_fee).unwrap()
            } else {
                left_fee.checked_add(&right_fee).unwrap()
            };

            let assert_fee_integrity = |merkle_root, fee| {
                let leaf_index = TransactionKernelField::Fee as u32;
                let leaf = Tip5::hash(fee);
                tasm::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
            };
            assert_fee_integrity(left_txk_digest, &left_fee);
            assert_fee_integrity(right_txk_digest, &right_fee);
            assert_fee_integrity(new_txk_digest, &new_fee);

            let left_coinbase = mw.left_kernel.coinbase;
            let right_coinbase = mw.right_kernel.coinbase;
            let new_coinbase = left_coinbase.or(right_coinbase);

            // if a coinbase is set, it must be the left one
            assert!(right_coinbase.is_none());

            let assert_coinbase_integrity = |merkle_root, coinbase| {
                let leaf_index = TransactionKernelField::Coinbase as u32;
                let leaf = Tip5::hash(coinbase);
                tasm::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
            };
            assert_coinbase_integrity(left_txk_digest, &left_coinbase);
            assert_coinbase_integrity(right_txk_digest, &right_coinbase);
            assert_coinbase_integrity(new_txk_digest, &new_coinbase);

            // new timestamp is whichever is larger
            let left_timestamp: Timestamp = mw.left_kernel.timestamp;
            let right_timestamp: Timestamp = mw.right_kernel.timestamp;
            let new_timestamp: Timestamp = if left_timestamp < right_timestamp {
                right_timestamp
            } else {
                left_timestamp
            };

            let assert_timestamp_integrity = |merkle_root, timestamp| {
                let leaf_index = TransactionKernelField::Timestamp as u32;
                let leaf = Tip5::hash(timestamp);
                tasm::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
            };
            assert_timestamp_integrity(left_txk_digest, &left_timestamp);
            assert_timestamp_integrity(right_txk_digest, &right_timestamp);
            assert_timestamp_integrity(new_txk_digest, &new_timestamp);

            // mutator set hash is identical
            let assert_mutator_set_hash_integrity = |merkle_root| {
                let leaf_index = TransactionKernelField::MutatorSetHash as u32;
                let leaf = Tip5::hash(&mw.left_kernel.mutator_set_hash);
                tasm::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
            };
            assert_mutator_set_hash_integrity(left_txk_digest);
            assert_mutator_set_hash_integrity(right_txk_digest);
            assert_mutator_set_hash_integrity(new_txk_digest);

            // new merge bit is set
            tasm::tasmlib_hashing_merkle_verify(
                new_txk_digest,
                TransactionKernelField::MergeBit as u32,
                Tip5::hash(&1),
                TransactionKernel::MAST_HEIGHT as u32,
            );
        }
    }

    pub(crate) async fn deterministic_merge_witness(
        params_left: (usize, usize, usize),
        params_right: (usize, usize, usize),
        consensus_rule_set: ConsensusRuleSet,
        network: Network,
    ) -> MergeWitness {
        let mut test_runner = TestRunner::deterministic();
        let [primitive_witness_1, primitive_witness_2] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
                params_left,
                params_right,
            ])
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        println!("primitive_witness_1: {primitive_witness_1}");
        println!("primitive_witness_2: {primitive_witness_2}");

        let shuffle_seed = arb::<[u8; 32]>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let left_proof = produce_single_proof(
            &primitive_witness_1,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let right_proof = produce_single_proof(
            &primitive_witness_2,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();

        let left_tx = Transaction::new_single_proof(primitive_witness_1.kernel, left_proof);
        let right_tx = Transaction::new_single_proof(primitive_witness_2.kernel, right_proof);

        MergeWitness::from_transactions(left_tx, right_tx, shuffle_seed)
    }

    pub(crate) async fn deterministic_merge_witness_with_coinbase(
        num_total_inputs: usize,
        num_total_outputs: usize,
        num_pub_announcements: usize,
        network: Network,
        consensus_rule_set: ConsensusRuleSet,
    ) -> MergeWitness {
        let mut test_runner = TestRunner::deterministic();

        let (coinbase_transaction, tx_with_inputs) =
            PrimitiveWitness::arbitrary_pair_with_coinbase_and_inputs_respectively(
                num_total_inputs,
                num_total_outputs,
                num_pub_announcements,
            )
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        assert!(
            coinbase_transaction.kernel.coinbase.is_some(),
            "Expected coinbase field must be set."
        );
        assert!(
            coinbase_transaction.kernel.inputs.is_empty(),
            "coinbase transaction cannot have inputs."
        );

        let shuffle_seed = arb::<[u8; 32]>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let left_proof = produce_single_proof(
            &coinbase_transaction,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();
        let right_proof = produce_single_proof(
            &tx_with_inputs,
            TritonVmJobQueue::get_instance(),
            TritonVmProofJobOptions::default_with_network(network),
            consensus_rule_set,
        )
        .await
        .unwrap();

        let left = Transaction::new_single_proof(coinbase_transaction.kernel, left_proof);
        let right = Transaction::new_single_proof(tx_with_inputs.kernel, right_proof);

        MergeWitness::for_composition(left.into(), right, shuffle_seed)
    }
}
