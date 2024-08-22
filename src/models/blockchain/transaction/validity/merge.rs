use std::collections::HashMap;

use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use strum::EnumCount;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::Digest;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::BFieldCodec;
use crate::models::blockchain::transaction::Proof;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::transaction::TransactionKernel;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;
use crate::tasm_lib::memory::encode_to_memory;
use crate::triton_vm::program::NonDeterminism;
use crate::triton_vm::program::Program;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use std::cmp::max;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;

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
        PublicInput::new(self.new_kernel.mast_hash().reversed().values().to_vec())
    }

    fn program(&self) -> Program {
        Merge.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        // set digests
        let digests = [
            self.left_kernel.mast_path(TransactionKernelField::Inputs),
            self.right_kernel.mast_path(TransactionKernelField::Inputs),
            self.new_kernel.mast_path(TransactionKernelField::Inputs),
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
            self.left_kernel.mast_path(TransactionKernelField::Coinbase),
            self.right_kernel
                .mast_path(TransactionKernelField::Coinbase),
            self.new_kernel.mast_path(TransactionKernelField::Coinbase),
            self.left_kernel
                .mast_path(TransactionKernelField::Timestamp),
            self.right_kernel
                .mast_path(TransactionKernelField::Timestamp),
            self.new_kernel.mast_path(TransactionKernelField::Timestamp),
            self.left_kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            self.right_kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            self.new_kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
        ]
        .concat();

        // set individual tokens
        let individual_tokens = [
            self.left_kernel.mast_hash().reversed().values(),
            self.right_kernel.mast_hash().reversed().values(),
        ]
        .concat();

        NonDeterminism::new(individual_tokens)
            .with_ram(memory)
            .with_digests(digests)
    }
}

#[derive(Debug, Clone)]
pub struct Merge;

impl Merge {
    pub const SINGLE_PROOF_PROGRAM_HASH: Digest = Digest::new([
        BFieldElement::new(0),
        BFieldElement::new(0),
        BFieldElement::new(0),
        BFieldElement::new(0),
        BFieldElement::new(0),
    ]);
}

impl ConsensusProgram for Merge {
    fn source(&self) {
        // read the kernel of the transaction that this proof applies to
        let new_txk_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();

        // divine the witness for this proof
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let mw: MergeWitness = tasmlib::decode_from_memory(start_address);

        // divine the left and right kernels of the operand transactions
        let left_txk_digest: Digest = tasmlib::tasmlib_io_read_secin___digest();
        let left_txk_digest_as_input: Vec<BFieldElement> =
            left_txk_digest.reversed().values().to_vec();
        let right_txk_digest: Digest = tasmlib::tasmlib_io_read_secin___digest();
        let right_txk_digest_as_input: Vec<BFieldElement> =
            right_txk_digest.reversed().values().to_vec();

        // verify the proofs of the operand transactions
        let left_claim: Claim = Claim {
            program_digest: Self::SINGLE_PROOF_PROGRAM_HASH,
            input: left_txk_digest_as_input,
            output: vec![],
        };
        let left_proof: &Proof = &mw.left_proof;
        tasmlib::verify_stark(Stark::default(), &left_claim, left_proof);
        let right_claim: Claim = Claim {
            program_digest: Self::SINGLE_PROOF_PROGRAM_HASH,
            input: right_txk_digest_as_input,
            output: vec![],
        };
        let right_proof: &Proof = &mw.left_proof;
        tasmlib::verify_stark(Stark::default(), &right_claim, right_proof);

        // new inputs are a permutation of the operands' inputs' concatenation
        let left_inputs: &Vec<RemovalRecord> = &mw.left_kernel.inputs;
        tasmlib::tasmlib_hashing_merkle_verify(
            left_txk_digest,
            TransactionKernelField::Inputs as u32,
            Hash::hash(left_inputs),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let mut preshuffle_inputs: Vec<Digest> = Vec::new();
        let mut i: usize = 0;
        while i < left_inputs.len() {
            preshuffle_inputs.push(Hash::hash(&left_inputs[i]));
            i += 1;
        }
        let right_inputs: &Vec<RemovalRecord> = &mw.right_kernel.inputs;
        tasmlib::tasmlib_hashing_merkle_verify(
            right_txk_digest,
            TransactionKernelField::Inputs as u32,
            Hash::hash(right_inputs),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        i = 0;
        while i < right_inputs.len() {
            preshuffle_inputs.push(Hash::hash(&right_inputs[i]));
            i += 1;
        }
        let new_inputs: &Vec<RemovalRecord> = &mw.new_kernel.inputs;
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Inputs as u32,
            Hash::hash(new_inputs),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let mut postshuffle_inputs: Vec<Digest> = Vec::new();
        i = 0;
        while i < new_inputs.len() {
            postshuffle_inputs.push(Hash::hash(&new_inputs[i]));
        }
        preshuffle_inputs.sort();
        postshuffle_inputs.sort();
        assert_eq!(preshuffle_inputs, postshuffle_inputs);

        // new outputs are a permutation of the operands' outputs' concatenation
        let left_outputs: &Vec<AdditionRecord> = &mw.left_kernel.outputs;
        tasmlib::tasmlib_hashing_merkle_verify(
            left_txk_digest,
            TransactionKernelField::Outputs as u32,
            Hash::hash(left_outputs),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let mut preshuffle_outputs: Vec<Digest> = Vec::new();
        i = 0;
        while i < left_outputs.len() {
            preshuffle_outputs.push(Hash::hash(&left_outputs[i]));
            i += 1;
        }
        let right_outputs: &Vec<AdditionRecord> = &mw.right_kernel.outputs;
        tasmlib::tasmlib_hashing_merkle_verify(
            right_txk_digest,
            TransactionKernelField::Outputs as u32,
            Hash::hash(right_outputs),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        i = 0;
        while i < right_outputs.len() {
            preshuffle_inputs.push(Hash::hash(&right_outputs[i]));
            i += 1;
        }
        let new_outputs: &Vec<AdditionRecord> = &mw.new_kernel.outputs;
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Outputs as u32,
            Hash::hash(new_outputs),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let mut postshuffle_outputs: Vec<Digest> = Vec::new();
        i = 0;
        while i < new_outputs.len() {
            postshuffle_outputs.push(Hash::hash(&new_outputs[i]));
        }
        preshuffle_outputs.sort();
        postshuffle_outputs.sort();
        assert_eq!(preshuffle_outputs, postshuffle_outputs);

        // new public announcements is a permutation of operands' public
        // announcements' concatenation
        let left_public_announcements: &Vec<PublicAnnouncement> =
            &mw.left_kernel.public_announcements;
        tasmlib::tasmlib_hashing_merkle_verify(
            left_txk_digest,
            TransactionKernelField::PublicAnnouncements as u32,
            Hash::hash(left_public_announcements),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let mut preshuffle_public_announcements: Vec<Digest> = Vec::new();
        i = 0;
        while i < left_public_announcements.len() {
            preshuffle_public_announcements.push(Hash::hash(&left_public_announcements[i]));
            i += 1;
        }
        let right_public_announcements: &Vec<PublicAnnouncement> =
            &mw.right_kernel.public_announcements;
        tasmlib::tasmlib_hashing_merkle_verify(
            right_txk_digest,
            TransactionKernelField::PublicAnnouncements as u32,
            Hash::hash(right_public_announcements),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        i = 0;
        while i < right_public_announcements.len() {
            preshuffle_public_announcements.push(Hash::hash(&right_public_announcements[i]));
            i += 1;
        }
        let new_public_announcements: &Vec<PublicAnnouncement> =
            &mw.new_kernel.public_announcements;
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::PublicAnnouncements as u32,
            Hash::hash(new_public_announcements),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let mut postshuffle_public_announcements: Vec<Digest> = Vec::new();
        i = 0;
        while i < new_outputs.len() {
            postshuffle_public_announcements.push(Hash::hash(&new_public_announcements[i]));
        }
        preshuffle_public_announcements.sort();
        postshuffle_public_announcements.sort();
        assert_eq!(
            preshuffle_public_announcements,
            postshuffle_public_announcements
        );

        // new fee is sum of operand fees
        let left_fee: NeptuneCoins = mw.left_kernel.fee;
        tasmlib::tasmlib_hashing_merkle_verify(
            left_txk_digest,
            TransactionKernelField::Fee as u32,
            Hash::hash(&left_fee),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let right_fee: NeptuneCoins = mw.right_kernel.fee;
        tasmlib::tasmlib_hashing_merkle_verify(
            right_txk_digest,
            TransactionKernelField::Fee as u32,
            Hash::hash(&right_fee),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let new_fee: NeptuneCoins = left_fee + right_fee;
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Fee as u32,
            Hash::hash(&new_fee),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // at most one coinbase is set
        let left_coinbase: Option<NeptuneCoins> = mw.left_kernel.coinbase;
        tasmlib::tasmlib_hashing_merkle_verify(
            left_txk_digest,
            TransactionKernelField::Coinbase as u32,
            Hash::hash(&left_coinbase),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let right_coinbase: Option<NeptuneCoins> = mw.right_kernel.coinbase;
        tasmlib::tasmlib_hashing_merkle_verify(
            right_txk_digest,
            TransactionKernelField::Coinbase as u32,
            Hash::hash(&right_coinbase),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        assert!(left_coinbase.is_none() || right_coinbase.is_none());

        // new coinbase is whichever is set, or none
        let new_coinbase: Option<NeptuneCoins> = if left_coinbase.is_some() {
            left_coinbase
        } else {
            right_coinbase
        };
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Coinbase as u32,
            Hash::hash(&new_coinbase),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // new timestamp is whichever is larger
        let left_timestamp: Timestamp = mw.left_kernel.timestamp;
        tasmlib::tasmlib_hashing_merkle_verify(
            left_txk_digest,
            TransactionKernelField::Timestamp as u32,
            Hash::hash(&left_timestamp),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let right_timestamp: Timestamp = mw.right_kernel.timestamp;
        tasmlib::tasmlib_hashing_merkle_verify(
            right_txk_digest,
            TransactionKernelField::Timestamp as u32,
            Hash::hash(&right_timestamp),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        let new_timestamp: Timestamp = if left_timestamp < right_timestamp {
            right_timestamp
        } else {
            left_timestamp
        };
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Timestamp as u32,
            Hash::hash(&new_timestamp),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // mutator set hash is identical
        let mutator_set_hash: Digest = mw.left_kernel.mutator_set_hash;
        tasmlib::tasmlib_hashing_merkle_verify(
            left_txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&mutator_set_hash),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            right_txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&mutator_set_hash),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&mutator_set_hash),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::program::PublicInput;

    use crate::models::blockchain::transaction::validity::merge::Merge;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
    use crate::models::blockchain::transaction::PrimitiveWitness;
    use crate::models::blockchain::transaction::ProofCollection;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;
    use proptest::arbitrary::Arbitrary;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;

    use super::MergeWitness;

    #[test]
    fn const_single_proof_program_digest_matches_with_hashed_code() {
        assert_eq!(
            Merge::SINGLE_PROOF_PROGRAM_HASH,
            SingleProof.program().hash()
        );
    }

    #[test]
    fn can_verify_transaction_merger() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness_1 = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness_2 = PrimitiveWitness::arbitrary_with((2, 2, 2))
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
        let rust_result = Merge.run_rust(
            &PublicInput::new(claim.input),
            merge_witness.nondeterminism(),
        );
        assert!(rust_result.is_ok());
    }
}
