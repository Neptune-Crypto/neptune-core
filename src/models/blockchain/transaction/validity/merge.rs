use std::cmp::max;
use std::collections::HashMap;

use itertools::Itertools;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use strum::EnumCount;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::library::Library;
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
use crate::models::blockchain::transaction::BFieldCodec;
use crate::models::blockchain::transaction::Proof;
use crate::models::blockchain::transaction::TransactionKernel;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;
use crate::prelude::triton_vm::prelude::triton_asm;
use crate::triton_vm::prelude::NonDeterminism;
use crate::triton_vm::prelude::Program;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub struct MergeWitness {
    left_kernel: TransactionKernel,
    right_kernel: TransactionKernel,
    new_kernel: TransactionKernel,
    left_proof: Proof,
    right_proof: Proof,
}

impl MergeWitness {
    /// Generate a `MergeWitness` from two transactions (kernels plus proofs).
    /// Assumes the transactions can be merged. Also takes randomness for shuffling
    /// the concatenations of inputs, outputs, and public announcements.
    pub fn from_transactions(
        left_kernel: TransactionKernel,
        left_proof: Proof,
        right_kernel: TransactionKernel,
        right_proof: Proof,
        shuffle_seed: [u8; 32],
    ) -> Self {
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
        let coinbase = if left_kernel.coinbase.is_some() {
            left_kernel.coinbase
        } else {
            right_kernel.coinbase
        };
        let new_kernel = TransactionKernel {
            inputs,
            outputs,
            public_announcements,
            fee: left_kernel.fee + right_kernel.fee,
            coinbase,
            timestamp: max(left_kernel.timestamp, right_kernel.timestamp),
            mutator_set_hash: left_kernel.mutator_set_hash,
        };
        Self {
            left_kernel,
            right_kernel,
            new_kernel,
            left_proof,
            right_proof,
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
        SingleProof.program().hash().values().to_vec()
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
            //
            self.left_kernel
                .mast_path(TransactionKernelField::PublicAnnouncements),
            self.right_kernel
                .mast_path(TransactionKernelField::PublicAnnouncements),
            self.new_kernel
                .mast_path(TransactionKernelField::PublicAnnouncements),
            //
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
    fn source(&self) {
        // read the kernel of the transaction that this proof applies to
        let new_txk_digest = tasmlib::tasmlib_io_read_stdin___digest();

        // read the hash of the program relative to which the transactions were proven valid
        let single_proof_program_hash = tasmlib::tasmlib_io_read_stdin___digest();
        tasmlib::tasmlib_io_write_to_stdout___digest(single_proof_program_hash);

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

        // todo vvvvv from here
        let to_merge_outputs = left_outputs
            .iter()
            .chain(right_outputs)
            .map(Tip5::hash)
            .sorted()
            .collect_vec();
        let merged_outputs = new_outputs.iter().map(Tip5::hash).sorted().collect_vec();
        assert_eq!(to_merge_outputs, merged_outputs);
        // todo ^^^^

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
        let hash_1_removal_record_index_set =
            library.import(Box::new(HashRemovalRecordIndexSets::<1>));
        let hash_2_removal_record_index_sets =
            library.import(Box::new(HashRemovalRecordIndexSets::<2>));
        let multiset_equality = library.import(Box::new(MultisetEqualityDigests));

        let digest_len = u32::try_from(Digest::LEN).unwrap();
        let left_txk_mast_hash_alloc = library.kmalloc(digest_len);
        let right_txk_mast_hash_alloc = library.kmalloc(digest_len);
        let new_txk_mast_hash_alloc = library.kmalloc(digest_len);

        let main = triton_asm! {
            // _
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
                                hint merge_witness: Pointer = stack[0]
            // _ *merge_witness

            read_io {Digest::LEN}
                                hint new_tx_kernel_digest: Digest = stack[0..6]
            // _ *merge_witness [new_txk_digest; 5]

            push {new_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1               // _ *merge_witness

            read_io {Digest::LEN}
                                hint single_proof_program_digest: Digest = stack[0..6]
            // _ *merge_witness [single_proof_program_digest; 5]

            divine {Digest::LEN}
                                hint left_tx_kernel_digest: Digest = stack[0..6]
            // _ *merge_witness [single_proof_program_digest; 5] [left_txk_digest; 5]

            dup 4 dup 4 dup 4 dup 4 dup 4
            push {left_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1               // _ *merge_witness [single_proof_program_digest; 5] [left_txk_digest; 5]

            dup 9 dup 9 dup 9 dup 9 dup 9
            call {generate_single_proof_claim}
                                hint left_claim: Pointer = stack[0]
            // _ *merge_witness [single_proof_program_digest; 5] *left_claim

            divine {Digest::LEN}
                                hint right_tx_kernel_digest: Digest = stack[0..6]
            // _ *merge_witness [single_proof_program_digest; 5] *left_claim [right_txk_digest; 5]

            dup 4 dup 4 dup 4 dup 4 dup 4
            push {right_txk_mast_hash_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1               // _ *merge_witness [single_proof_program_digest; 5] *left_claim [right_txk_digest; 5]

            dup 10 dup 10 dup 10 dup 10 dup 10
            call {generate_single_proof_claim}
                                hint right_claim: Pointer = stack[0]
            // _ *merge_witness [single_proof_program_digest; 5] *left_claim *right_claim

            place 6
            place 6
            pop 5               // _ *merge_witness *left_claim *right_claim

            dup 2
            {&field!(MergeWitness::right_proof)}
            // _ *merge_witness *left_claim *right_claim *right_proof

            call {stark_verify} // _ *merge_witness *left_claim

            dup 1
            {&field!(MergeWitness::left_proof)}
            // _ *merge_witness *left_claim *left_proof

            call {stark_verify} // _ *merge_witness

            dup 0
            {&field!(MergeWitness::left_kernel)}
                                hint left_tx_kernel: Pointer = stack[0]
            dup 1
            {&field!(MergeWitness::right_kernel)}
                                hint right_tx_kernel: Pointer = stack[0]
            dup 2
            {&field!(MergeWitness::new_kernel)}
                                hint new_tx_kernel: Pointer = stack[0]
            // _ *merge_witness *left_tx_kernel *right_tx_kernel *new_tx_kernel

            /* new inputs are a permutation of the operands' inputs' concatenation */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5] *l_txk_in size

            dup 1
            place 6             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [left_txk_digest; 5] *l_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [right_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in [right_txk_digest; 5] *r_txk_in size

            dup 1
            place 6             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [right_txk_digest; 5] *r_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [new_txk_digest; 5]

            dup 7
            {&field_with_size!(TransactionKernel::inputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in [new_txk_digest; 5] *n_txk_in size

            dup 1
            place 6             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in *n_txk_in [new_txk_digest; 5] *n_txk_in size
            call {authenticate_txk_input_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_in *r_txk_in *n_txk_in

            call {hash_1_removal_record_index_set}
            place 2             // _ *merge_witness *l_txk *r_txk *n_txk *n_txk_in_digests *l_txk_in *r_txk_in
            call {hash_2_removal_record_index_sets}
            call {multiset_equality}
            assert              // _ *merge_witness *l_txk *r_txk *n_txk

            /* new outputs are a permutation of the operands' outputs' concatenation */
            push {left_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk [left_txk_digest; 5] *l_txk_out size

            dup 1
            place 6             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [left_txk_digest; 5] *l_txk_out size
            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out

            push {right_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [right_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out [right_txk_digest; 5] *r_txk_out size

            dup 1
            place 6             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [right_txk_digest; 5] *r_txk_out size
            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out

            push {new_txk_mast_hash_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1               // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [new_txk_digest; 5]
            dup 7
            {&field_with_size!(TransactionKernel::outputs)}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out [new_txk_digest; 5] *n_txk_out size
            dup 1
            place 6             // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out *n_txk_out [new_txk_digest; 5] *n_txk_out size

            call {authenticate_txk_output_field}
            // _ *merge_witness *l_txk *r_txk *n_txk *l_txk_out *r_txk_out *n_txk_out

        };

        triton_asm! {
            {&main}
            {&library.all_imports()}
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::PublicInput;

    use super::MergeWitness;
    use crate::models::blockchain::transaction::validity::merge::Merge;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
    use crate::models::blockchain::transaction::PrimitiveWitness;
    use crate::models::blockchain::transaction::ProofCollection;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;

    #[test]
    fn can_verify_transaction_merger() {
        let mut test_runner = TestRunner::deterministic();
        let [primitive_witness_1, primitive_witness_2] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([(2, 2, 2), (2, 2, 2)])
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

        let shuffle_seed = arb::<[u8; 32]>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let proof_collection_1 = ProofCollection::produce(&primitive_witness_1);
        let single_proof_witness_1 = SingleProofWitness::from_collection(proof_collection_1);
        let proof_1 = SingleProof.prove(
            &single_proof_witness_1.claim(),
            single_proof_witness_1.nondeterminism(),
        );

        let proof_collection_2 = ProofCollection::produce(&primitive_witness_2);
        let single_proof_witness_2 = SingleProofWitness::from_collection(proof_collection_2);
        let proof_2 = SingleProof.prove(
            &single_proof_witness_2.claim(),
            single_proof_witness_2.nondeterminism(),
        );

        let merge_witness = MergeWitness::from_transactions(
            primitive_witness_1.kernel,
            proof_1,
            primitive_witness_2.kernel,
            proof_2,
            shuffle_seed,
        );

        let claim = merge_witness.claim();
        let public_input = PublicInput::new(claim.input);
        let rust_result = Merge.run_rust(&public_input, merge_witness.nondeterminism());
        assert!(rust_result.is_ok());

        let tasm_result = Merge.run_tasm(&public_input, merge_witness.nondeterminism());
        assert!(tasm_result.is_ok());
    }
}
