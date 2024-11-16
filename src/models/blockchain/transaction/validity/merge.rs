use std::cmp::max;
use std::sync::OnceLock;

use itertools::Itertools;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use strum::EnumCount;
use tasm_lib::arithmetic::u128::safe_add::SafeAddU128;
use tasm_lib::arithmetic::u64::lt_u64::LtU64ConsumeArgs;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::list::higher_order::inner_function::InnerFunction;
use tasm_lib::list::higher_order::inner_function::RawCode;
use tasm_lib::list::higher_order::map::ChainMap;
use tasm_lib::list::higher_order::map::Map;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;

use super::single_proof::SingleProof;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::models::blockchain::transaction::validity::tasm::hash_removal_record_index_sets::HashRemovalRecordIndexSets;
use crate::models::blockchain::transaction::validity::tasm::merge::authenticate_coinbase_fields::AuthenticateCoinbaseFields;
use crate::models::blockchain::transaction::BFieldCodec;
use crate::models::blockchain::transaction::Proof;
use crate::models::blockchain::transaction::TransactionKernel;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;
use crate::prelude::triton_vm::prelude::triton_asm;
use crate::triton_vm::prelude::NonDeterminism;
use crate::triton_vm::prelude::Program;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub struct MergeWitness {
    left_kernel: TransactionKernel,
    right_kernel: TransactionKernel,
    pub new_kernel: TransactionKernel,
    left_proof: Proof,
    right_proof: Proof,
}

impl MergeWitness {
    /// Generate a `MergeWitness` from two transactions (kernels plus proofs).
    /// Assumes the transactions can be merged. Also takes randomness for shuffling
    /// the concatenations of inputs, outputs, and public announcements.
    pub(crate) fn from_transactions(
        left_kernel: TransactionKernel,
        left_proof: Proof,
        right_kernel: TransactionKernel,
        right_proof: Proof,
        shuffle_seed: [u8; 32],
    ) -> Self {
        let new_kernel = Self::new_kernel(&left_kernel, &right_kernel, shuffle_seed);

        Self {
            left_kernel,
            right_kernel,
            new_kernel,
            left_proof,
            right_proof,
        }
    }

    /// Generate a new transaction kernel from two transactions.
    ///
    /// # Panics
    ///
    /// Panics if given unmergable transactions as input.
    pub(super) fn new_kernel(
        left_kernel: &TransactionKernel,
        right_kernel: &TransactionKernel,
        shuffle_seed: [u8; 32],
    ) -> TransactionKernel {
        assert_eq!(
            left_kernel.mutator_set_hash, right_kernel.mutator_set_hash,
            "Attempted to merge transaction kernel with non-matching mutator set hashes"
        );
        let mut rng: StdRng = SeedableRng::from_seed(shuffle_seed);
        let mut inputs = [left_kernel.inputs.clone(), right_kernel.inputs.clone()].concat();
        inputs.shuffle(&mut rng);
        let mut outputs = [left_kernel.outputs.clone(), right_kernel.outputs.clone()].concat();
        outputs.shuffle(&mut rng);
        let mut public_announcements = [
            left_kernel.public_announcements.clone(),
            right_kernel.public_announcements.clone(),
        ]
        .concat();
        public_announcements.shuffle(&mut rng);

        let old_coinbase = left_kernel.coinbase.or(right_kernel.coinbase);

        TransactionKernel {
            inputs,
            outputs,
            public_announcements,
            fee: left_kernel.fee + right_kernel.fee,
            coinbase: old_coinbase,
            timestamp: max(left_kernel.timestamp, right_kernel.timestamp),
            mutator_set_hash: left_kernel.mutator_set_hash,
        }
    }
}

impl SecretWitness for MergeWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(
            [
                self.new_kernel.mast_hash().reversed().values(),
                SingleProof.program().hash().reversed().values(),
            ]
            .concat(),
        )
    }

    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program {
        Merge.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();

        // the merge witness lives in nondeterministically-initialized memory
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

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
        let left_claim = SingleProof::claim(self.left_kernel.mast_hash());
        let right_claim = SingleProof::claim(self.right_kernel.mast_hash());
        verify_snippet.update_nondeterminism(&mut nondeterminism, &self.left_proof, &left_claim);
        verify_snippet.update_nondeterminism(&mut nondeterminism, &self.right_proof, &right_claim);

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
                .mast_path(TransactionKernelField::PublicAnnouncements),
            self.right_kernel
                .mast_path(TransactionKernelField::PublicAnnouncements),
            self.new_kernel
                .mast_path(TransactionKernelField::PublicAnnouncements),
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
        ]
        .concat();
        nondeterminism.digests.extend(digests);

        nondeterminism
    }
}

#[derive(Debug, Clone)]
pub struct Merge;

impl ConsensusProgram for Merge {
    /// Get the program hash digest.
    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }

    fn source(&self) {
        // read the kernel of the transaction that this proof applies to
        let new_txk_digest = tasmlib::tasmlib_io_read_stdin___digest();

        // read the hash of the program relative to which the transactions were proven valid
        let single_proof_program_hash = tasmlib::tasmlib_io_read_stdin___digest();

        // divine the witness for this proof
        let start_address = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let mw = tasmlib::decode_from_memory::<MergeWitness>(start_address);

        // divine the left and right kernels of the operand transactions
        let left_txk_digest = tasmlib::tasmlib_io_read_secin___digest();
        let right_txk_digest = tasmlib::tasmlib_io_read_secin___digest();

        // verify the proofs of the operand transactions
        let left_claim = Claim::new(single_proof_program_hash)
            .with_input(left_txk_digest.reversed().values().to_vec());
        let right_claim = Claim::new(single_proof_program_hash)
            .with_input(right_txk_digest.reversed().values().to_vec());

        tasmlib::verify_stark(Stark::default(), &left_claim, &mw.left_proof);
        tasmlib::verify_stark(Stark::default(), &right_claim, &mw.right_proof);

        let tree_height = TransactionKernelField::COUNT.next_power_of_two().ilog2();

        // new inputs are a permutation of the operands' inputs' concatenation
        let left_inputs: &Vec<RemovalRecord> = &mw.left_kernel.inputs;
        let right_inputs: &Vec<RemovalRecord> = &mw.right_kernel.inputs;
        let new_inputs: &Vec<RemovalRecord> = &mw.new_kernel.inputs;

        let assert_input_integrity = |merkle_root, inputs| {
            let leaf_index = TransactionKernelField::Inputs as u32;
            let leaf = Tip5::hash(inputs);
            tasmlib::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
        };
        assert_input_integrity(left_txk_digest, left_inputs);
        assert_input_integrity(right_txk_digest, right_inputs);
        assert_input_integrity(new_txk_digest, new_inputs);

        let to_merge_inputs = left_inputs
            .iter()
            .chain(right_inputs)
            .map(Tip5::hash)
            .sorted()
            .collect_vec();
        let merged_inputs = new_inputs.iter().map(Tip5::hash).sorted().collect_vec();
        assert_eq!(to_merge_inputs, merged_inputs);

        // new outputs are a permutation of the operands' outputs' concatenation
        let left_outputs = &mw.left_kernel.outputs;
        let right_outputs = &mw.right_kernel.outputs;
        let new_outputs = &mw.new_kernel.outputs;

        let assert_output_integrity = |merkle_root, outputs| {
            let leaf_index = TransactionKernelField::Outputs as u32;
            let leaf = Tip5::hash(outputs);
            tasmlib::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height)
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

        // new public announcements is a permutation of operands' public
        // announcements' concatenation
        let left_public_announcements = &mw.left_kernel.public_announcements;
        let right_public_announcements = &mw.right_kernel.public_announcements;
        let new_public_announcements = &mw.new_kernel.public_announcements;

        let assert_public_announcement_integrity = |merkle_root, announcements| {
            let leaf_index = TransactionKernelField::PublicAnnouncements as u32;
            let leaf = Tip5::hash(announcements);
            tasmlib::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
        };
        assert_public_announcement_integrity(left_txk_digest, left_public_announcements);
        assert_public_announcement_integrity(right_txk_digest, right_public_announcements);
        assert_public_announcement_integrity(new_txk_digest, new_public_announcements);

        let to_merge_public_announcements = left_public_announcements
            .iter()
            .chain(right_public_announcements)
            .map(Tip5::hash)
            .sorted()
            .collect_vec();
        let merged_public_announcements = new_public_announcements
            .iter()
            .map(Tip5::hash)
            .sorted()
            .collect_vec();
        assert_eq!(to_merge_public_announcements, merged_public_announcements);

        // new fee is sum of operand fees
        let left_fee = mw.left_kernel.fee;
        let right_fee = mw.right_kernel.fee;
        let new_fee = left_fee + right_fee;

        let assert_fee_integrity = |merkle_root, fee| {
            let leaf_index = TransactionKernelField::Fee as u32;
            let leaf = Tip5::hash(fee);
            tasmlib::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
        };
        assert_fee_integrity(left_txk_digest, &left_fee);
        assert_fee_integrity(right_txk_digest, &right_fee);
        assert_fee_integrity(new_txk_digest, &new_fee);

        // at most one coinbase is set
        let left_coinbase = mw.left_kernel.coinbase;
        let right_coinbase = mw.right_kernel.coinbase;
        let new_coinbase = left_coinbase.or(right_coinbase);
        assert!(left_coinbase.is_none() || right_coinbase.is_none());

        let assert_coinbase_integrity = |merkle_root, coinbase| {
            let leaf_index = TransactionKernelField::Coinbase as u32;
            let leaf = Tip5::hash(coinbase);
            tasmlib::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
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
            tasmlib::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
        };
        assert_timestamp_integrity(left_txk_digest, &left_timestamp);
        assert_timestamp_integrity(right_txk_digest, &right_timestamp);
        assert_timestamp_integrity(new_txk_digest, &new_timestamp);

        // mutator set hash is identical
        let assert_mutator_set_hash_integrity = |merkle_root| {
            let leaf_index = TransactionKernelField::MutatorSetHash as u32;
            let leaf = Tip5::hash(&mw.left_kernel.mutator_set_hash);
            tasmlib::tasmlib_hashing_merkle_verify(merkle_root, leaf_index, leaf, tree_height);
        };
        assert_mutator_set_hash_integrity(left_txk_digest);
        assert_mutator_set_hash_integrity(right_txk_digest);
        assert_mutator_set_hash_integrity(new_txk_digest);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();
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
            AuthenticateTxkField(TransactionKernelField::PublicAnnouncements),
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
            DataType::Digest, // domain knowledge
            DataType::Digest,
        );
        let hash_1_list_of_outputs = library.import(Box::new(Map::new(InnerFunction::RawCode(
            hash_transaction_output.clone(),
        ))));
        let hash_2_lists_of_outputs = library.import(Box::new(ChainMap::<2>::new(
            InnerFunction::RawCode(hash_transaction_output),
        )));

        let hash_varlen = library.import(Box::new(HashVarlen));
        let hash_public_announcement = RawCode::new(
            triton_asm! {hash_public_announcement: call {hash_varlen} return },
            DataType::Tuple(vec![DataType::VoidPointer, DataType::Bfe]),
            DataType::Digest,
        );
        let hash_1_list_of_announcements = library.import(Box::new(Map::new(
            InnerFunction::RawCode(hash_public_announcement.clone()),
        )));
        let hash_2_lists_of_announcements = library.import(Box::new(ChainMap::<2>::new(
            InnerFunction::RawCode(hash_public_announcement),
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

        let neptune_coins_size = NeptuneCoins::static_length().unwrap();
        let kernel_field_fee = field!(TransactionKernel::fee);
        let safe_add_u128 = library.import(Box::new(SafeAddU128));
        let compare_u128 = DataType::U128.compare();

        let assert_new_fee_is_sum_of_left_and_right = triton_asm!(
            // _ *left_txk *right_txk *new_txk

            // 1. get left fee
            // 2. authenticate against left kernel mast hash
            // 3. same right right
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
            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            dup 5
            push {neptune_coins_size}
            call {authenticate_txk_fee_field}
            // _ *left_txk *right_txk *new_txk *left_fee *right_fee

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

            /*
              The recursive verification and check for double spend suffice as
              check for invalid u128s (with a word not being `u32`) and it
              suffices as a check against the creation of invalid Neptune coin
              amounts (exceeding the limit of total supply).
            */
            call {safe_add_u128}
            // _ *left_txk *right_txk *new_txk [calculated_new_fee;4]

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

        let lt_u64 = library.import(Box::new(LtU64ConsumeArgs));
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
            // _ *merge_witness *l_txk *r_txk *n_txk *left_timestamp left_timestamp [left_txkmh]

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
            // _ *merge_witness *l_txk *r_txk *n_txk *left_msh [left_msh; 5]

            // authenticate against left txkmh
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk *left_msh [left_msh; 5] [left_txkmh]

            pick {2*Digest::LEN}
            push {Digest::LEN}
            call {authenticate_kernel_field_mutator_set_hash}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5]

            // read right msh
            dup 6 {&kernel_field_mutator_set_hash}
            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            addi 1
            place {Digest::LEN}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *right_msh [right_msh; 5]

            // assert equal
            dup 10 dup 10 dup 10 dup 10 dup 10
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *right_msh [right_msh; 5] [left_msh; 5]

            {&compare_digests} assert
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *right_msh

            // authenticate against right txkmh
            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *right_msh [right_txkmh]

            pick {Digest::LEN}
            push {Digest::LEN}
            call {authenticate_kernel_field_mutator_set_hash}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5]

            // read new msh
            dup 5 {&kernel_field_mutator_set_hash}
            addi {Digest::LEN - 1}
            read_mem {Digest::LEN}
            addi 1
            place {Digest::LEN}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *new_msh [new_msh; 5]

            // assert equal
            dup 10 dup 10 dup 10 dup 10 dup 10
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *new_msh [new_msh; 5] [left_msh; 5]

            {&compare_digests} assert
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *new_msh

            // authenticate against new txkmh
            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5] *new_msh [new_txkmh]

            pick {Digest::LEN}
            push {Digest::LEN}
            call {authenticate_kernel_field_mutator_set_hash}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_msh; 5]

            pop 5
            // _ *merge_witness *l_txk *r_txk *n_txk
        };

        let main = triton_asm! {
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint  merge_witness: Pointer = stack[0]
            // _ *merge_witness

            read_io {Digest::LEN}
            hint  new_tx_kernel_digest: Digest = stack[0..5]
            // _ *merge_witness [new_txk_digest; 5]

            push {new_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1

            read_io {Digest::LEN}
            hint  single_proof_program_digest: Digest = stack[0..5]
            // _ *merge_witness [single_proof_program_digest; 5]

            divine {Digest::LEN}
            hint  left_tx_kernel_digest: Digest = stack[0..5]
            // _ *merge_witness [single_proof_program_digest; 5] [left_txk_digest; 5]

            dup 4 dup 4 dup 4 dup 4 dup 4
            push {left_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ *merge_witness [single_proof_program_digest; 5] [left_txk_digest; 5]

            dup 9 dup 9 dup 9 dup 9 dup 9
            call {generate_single_proof_claim}
            hint  left_claim: Pointer = stack[0]
            // _ *merge_witness [single_proof_program_digest; 5] *left_claim

            divine {Digest::LEN}
            hint  right_tx_kernel_digest: Digest = stack[0..5]
            // _ *merge_witness [single_proof_program_digest; 5] *left_claim [right_txk_digest; 5]

            dup 4 dup 4 dup 4 dup 4 dup 4
            push {right_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ *merge_witness [single_proof_program_digest; 5] *left_claim [right_txk_digest; 5]

            dup 10 dup 10 dup 10 dup 10 dup 10
            call {generate_single_proof_claim}
            hint  right_claim: Pointer = stack[0]
            // _ *merge_witness [single_proof_program_digest; 5] *left_claim *right_claim

            place 6
            place 5
            pop 5
            // _ *merge_witness *right_claim *left_claim

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
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5] *l_txk_in size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [left_txk_digest; 5] *l_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [right_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [right_txk_digest; 5] *r_txk_in size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [right_txk_digest; 5] *r_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [new_txk_digest; 5]

            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [new_txk_digest; 5] *n_txk_in size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in *n_txk_in [new_txk_digest; 5] *n_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in *n_txk_in

            call {hash_1_removal_record_index_set}
            place 2             // _ *merge_witness *l_txk *r_txk *n_txk *n_txk_in_digests *l_txk_in *r_txk_in
            call {hash_2_removal_record_index_sets}
            call {multiset_equality}
            assert
            // _ *merge_witness *l_txk *r_txk *n_txk


            /* new outputs are a permutation of the operands' outputs' concatenation */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5] *l_txk_out size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [left_txk_digest; 5] *l_txk_out size
            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [right_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [right_txk_digest; 5] *r_txk_out size

            dup 1
            place 7
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [right_txk_digest; 5] *r_txk_out size

            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [new_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [new_txk_digest; 5] *n_txk_out size

            dup 1
            place 7
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out *n_txk_out [new_txk_digest; 5] *n_txk_out size

            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out *n_txk_out

            /* left + right outputs must equal new outputs */
            call {hash_1_list_of_outputs}
            place 2
            call {hash_2_lists_of_outputs}
            call {multiset_equality}
            assert
            // _ *merge_witness *l_txk *r_txk *n_txk

            /* Check integrity of public announcement fields */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::public_announcements)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5] *l_txk_pa size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa [left_txk_digest; 5] *l_txk_pa size
            call {authenticate_txk_pub_announcement_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa [right_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::public_announcements)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa [right_txk_digest; 5] *r_txk_pa size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa [right_txk_digest; 5] *r_txk_pa size
            call {authenticate_txk_pub_announcement_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa [new_txk_digest; 5]

            dup 7
            {&field_with_size!(TransactionKernel::public_announcements)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa [new_txk_digest; 5] *n_txk_pa size

            dup 1
            place 7             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_pa *r_txk_pa *n_txk_pa [new_txk_digest; 5] *n_txk_pa size
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

            pop 4
            // _

            halt
        };

        triton_asm! {
            {&main}
            {&library.all_imports()}
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::PublicInput;

    use super::MergeWitness;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::transaction::validity::merge::Merge;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::PrimitiveWitness;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;
    use crate::triton_vm::prelude::Digest;

    impl MergeWitness {
        pub(crate) fn new_kernel_mast_hash(&self) -> Digest {
            self.new_kernel.mast_hash()
        }
    }

    #[tokio::test]
    async fn can_verify_transaction_merger() {
        let merge_witness = deterministic_merge_witness((2, 2, 2), (2, 2, 2)).await;

        let claim = merge_witness.claim();
        let public_input = PublicInput::new(claim.input);
        let rust_result = Merge.run_rust(&public_input, merge_witness.nondeterminism());
        let tasm_result = Merge.run_tasm(&public_input, merge_witness.nondeterminism());

        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    #[tokio::test]
    async fn can_verify_transaction_merger_with_coinbase() {
        let merge_witness = deterministic_merge_witness_with_coinbase(3, 3, 3).await;

        let claim = merge_witness.claim();
        let public_input = PublicInput::new(claim.input);
        let rust_result = Merge.run_rust(&public_input, merge_witness.nondeterminism());
        let tasm_result = Merge.run_tasm(&public_input, merge_witness.nondeterminism());

        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    pub(crate) async fn deterministic_merge_witness(
        params_left: (usize, usize, usize),
        params_right: (usize, usize, usize),
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

        let single_proof_1 = SingleProof::produce(
            &primitive_witness_1,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        let single_proof_2 = SingleProof::produce(
            &primitive_witness_2,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();

        MergeWitness::from_transactions(
            primitive_witness_1.kernel,
            single_proof_1,
            primitive_witness_2.kernel,
            single_proof_2,
            shuffle_seed,
        )
    }

    pub(crate) async fn deterministic_merge_witness_with_coinbase(
        num_total_inputs: usize,
        num_total_outputs: usize,
        num_pub_announcements: usize,
    ) -> MergeWitness {
        let mut test_runner = TestRunner::deterministic();

        let (left, right) = PrimitiveWitness::arbitrary_pair_with_inputs_and_coinbase_respectively(
            num_total_inputs,
            num_total_outputs,
            num_pub_announcements,
        )
        .new_tree(&mut test_runner)
        .unwrap()
        .current();

        let shuffle_seed = arb::<[u8; 32]>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let left_proof = SingleProof::produce(
            &left,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        let right_proof = SingleProof::produce(
            &right,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();

        MergeWitness::from_transactions(
            left.kernel,
            left_proof,
            right.kernel,
            right_proof,
            shuffle_seed,
        )
    }
}
