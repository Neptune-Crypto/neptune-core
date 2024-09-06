use itertools::Itertools;
use strum::EnumCount;
use tasm_lib::field;
use tasm_lib::mmr::verify_mmr_successor::VerifyMmrSuccessor;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::triton_asm;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::twenty_first::prelude::MerkleTreeInclusionProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::models::blockchain::transaction::BFieldCodec;
use crate::models::blockchain::transaction::Proof;
use crate::models::blockchain::transaction::TransactionKernel;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;
use crate::tasm_lib::memory::encode_to_memory;
use crate::triton_vm::program::NonDeterminism;
use crate::triton_vm::program::Program;
use crate::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::twenty_first::prelude::Mmr;

use super::single_proof::SingleProof;

#[derive(Debug, Clone, BFieldCodec, TasmObject)]
pub struct UpdateWitness {
    old_kernel: TransactionKernel,
    new_kernel: TransactionKernel,
    old_kernel_mast_hash: Digest,
    new_kernel_mast_hash: Digest,
    old_proof: Proof,
    new_swbfi_bagged: Digest,
    new_aocl: MmrAccumulator,
    new_swbfa_hash: Digest,
    old_swbfi_bagged: Digest,
    old_aocl: MmrAccumulator,
    old_swbfa_hash: Digest,
    aocl_successor_proof: MmrSuccessorProof,
    outputs_hash: Digest,
    public_announcements_hash: Digest,
}

impl UpdateWitness {
    pub fn from_old_transaction(
        old_kernel: TransactionKernel,
        old_proof: Proof,
        old_msa: MutatorSetAccumulator,
        new_kernel: TransactionKernel,
        new_msa: MutatorSetAccumulator,
        aocl_successor_proof: MmrSuccessorProof,
    ) -> Self {
        let msah_path = new_kernel.mast_path(TransactionKernelField::MutatorSetHash);
        assert!(
            MerkleTreeInclusionProof {
                tree_height: TransactionKernelField::COUNT.next_power_of_two().ilog2() as usize,
                indexed_leafs: vec![(
                    TransactionKernelField::MutatorSetHash as usize,
                    Hash::hash(&new_msa.hash())
                )],
                authentication_structure: msah_path.clone(),
            }
            .verify(new_kernel.mast_hash()),
            "path should be valid"
        );

        Self {
            old_kernel_mast_hash: old_kernel.mast_hash(),
            new_kernel_mast_hash: new_kernel.mast_hash(),
            old_kernel,
            new_kernel: new_kernel.clone(),
            old_proof,
            new_swbfi_bagged: new_msa.swbf_inactive.bag_peaks(),
            new_aocl: new_msa.aocl,
            new_swbfa_hash: Hash::hash(&new_msa.swbf_active),
            old_swbfi_bagged: old_msa.swbf_inactive.bag_peaks(),
            old_aocl: old_msa.aocl,
            old_swbfa_hash: Hash::hash(&old_msa.swbf_active),
            aocl_successor_proof,
            outputs_hash: Hash::hash(&new_kernel.outputs),
            public_announcements_hash: Hash::hash(&new_kernel.public_announcements),
        }
    }
}

impl SecretWitness for UpdateWitness {
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
        Update.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::new(vec![]);

        // set memory
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        // update nondeterminism to account for verifying one STARK proof
        let claim = Claim::new(SingleProof.program().hash())
            .with_input(self.old_kernel_mast_hash.reversed().values().to_vec());
        StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
            &mut nondeterminism,
            &self.old_proof,
            &claim,
        );

        // set remaining digests
        nondeterminism.digests.append(
            &mut [
                // mutator set hash
                self.new_kernel
                    .mast_path(TransactionKernelField::MutatorSetHash),
                self.old_kernel
                    .mast_path(TransactionKernelField::MutatorSetHash),
                // inputs
                self.old_kernel.mast_path(TransactionKernelField::Inputs),
                self.new_kernel.mast_path(TransactionKernelField::Inputs),
                // outputs
                self.old_kernel.mast_path(TransactionKernelField::Outputs),
                self.new_kernel.mast_path(TransactionKernelField::Outputs),
                // public announcements
                self.old_kernel
                    .mast_path(TransactionKernelField::PublicAnnouncements),
                self.new_kernel
                    .mast_path(TransactionKernelField::PublicAnnouncements),
                // fee
                self.old_kernel.mast_path(TransactionKernelField::Fee),
                self.new_kernel.mast_path(TransactionKernelField::Fee),
                // coinbase
                self.old_kernel.mast_path(TransactionKernelField::Coinbase),
                self.new_kernel.mast_path(TransactionKernelField::Coinbase),
                // timestamp
                self.old_kernel.mast_path(TransactionKernelField::Timestamp),
                self.new_kernel.mast_path(TransactionKernelField::Timestamp),
            ]
            .concat(),
        );

        VerifyMmrSuccessor::update_nondeterminism(&mut nondeterminism, &self.aocl_successor_proof);

        nondeterminism
    }
}

#[derive(Debug, Clone)]
pub struct Update;

impl ConsensusProgram for Update {
    fn source(&self) {
        // read the kernel of the transaction that this proof applies to
        let new_txk_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();

        // read the hash of the program that this transaction was proved valid under
        let single_proof_program_digest = tasmlib::tasmlib_io_read_stdin___digest();

        // divine the witness for this proof
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let uw: UpdateWitness = tasmlib::decode_from_memory(start_address);

        // get the kernel of the out-of-date transaction
        let old_txk_digest: Digest = uw.old_kernel_mast_hash;
        let old_txk_digest_as_input: Vec<BFieldElement> =
            old_txk_digest.reversed().values().to_vec();

        // verify the proof of the out-of-date transaction
        let claim: Claim = Claim {
            program_digest: single_proof_program_digest,
            input: old_txk_digest_as_input,
            output: vec![],
        };
        let proof: &Proof = &uw.old_proof;
        tasmlib::verify_stark(Stark::default(), &claim, proof);

        // authenticate the new mutator set accumulator against the txk mast hash
        let new_aocl_mmr: MmrAccumulator = uw.new_aocl;
        let new_aocl_mmr_bagged = new_aocl_mmr.bag_peaks();
        let new_inactive_swbf_bagged: Digest = uw.new_swbfi_bagged;
        let new_left: Digest = Hash::hash_pair(new_aocl_mmr_bagged, new_inactive_swbf_bagged);
        let new_active_swbf_digest: Digest = uw.new_swbfa_hash;
        let default: Digest = Digest::default();
        let new_right: Digest = Hash::hash_pair(new_active_swbf_digest, default);
        let new_msah: Digest = Hash::hash_pair(new_left, new_right);
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&new_msah),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // authenticate the old mutator set accumulator against the txk mast hash
        let old_aocl_mmr: MmrAccumulator = uw.old_aocl;
        let old_aocl_mmr_bagged = old_aocl_mmr.bag_peaks();
        let old_inactive_swbf_bagged: Digest = uw.old_swbfi_bagged;
        let old_left: Digest = Hash::hash_pair(old_aocl_mmr_bagged, old_inactive_swbf_bagged);
        let old_active_swbf_digest: Digest = uw.old_swbfa_hash;
        let old_right: Digest = Hash::hash_pair(old_active_swbf_digest, default);
        let old_msah: Digest = Hash::hash_pair(old_left, old_right);
        tasmlib::tasmlib_hashing_merkle_verify(
            old_txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&old_msah),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // verify update ...

        // authenticate inputs
        let old_inputs: Vec<RemovalRecord> = uw.old_kernel.inputs;
        let new_inputs: Vec<RemovalRecord> = uw.new_kernel.inputs;
        let old_inputs_hash: Digest = Hash::hash(&old_inputs);
        let new_inputs_hash: Digest = Hash::hash(&new_inputs);
        tasmlib::tasmlib_hashing_merkle_verify(
            old_txk_digest,
            TransactionKernelField::Inputs as u32,
            old_inputs_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Inputs as u32,
            new_inputs_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // inputs' index sets are identical
        let mut old_index_set_digests: Vec<Digest> = Vec::new();
        let mut new_index_set_digests: Vec<Digest> = Vec::new();
        assert_eq!(old_inputs.len(), new_inputs.len());
        let mut i: usize = 0;
        while i < old_inputs.len() {
            old_index_set_digests.push(Hash::hash(&old_inputs[i].absolute_indices));
            new_index_set_digests.push(Hash::hash(&new_inputs[i].absolute_indices));
            i += 1;
        }
        old_index_set_digests.sort();
        new_index_set_digests.sort();
        assert_eq!(old_index_set_digests, new_index_set_digests);

        // outputs are identical
        let outputs_hash: Digest = uw.outputs_hash;
        tasmlib::tasmlib_hashing_merkle_verify(
            old_txk_digest,
            TransactionKernelField::Outputs as u32,
            outputs_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Outputs as u32,
            outputs_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // public announcements are identical
        let public_announcements_hash: Digest = uw.public_announcements_hash;
        tasmlib::tasmlib_hashing_merkle_verify(
            old_txk_digest,
            TransactionKernelField::PublicAnnouncements as u32,
            public_announcements_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::PublicAnnouncements as u32,
            public_announcements_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // fees are identical
        let fee_hash: Digest = Hash::hash(&uw.new_kernel.fee);
        tasmlib::tasmlib_hashing_merkle_verify(
            old_txk_digest,
            TransactionKernelField::Fee as u32,
            fee_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Fee as u32,
            fee_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // coinbases are identical
        let coinbase_hash: Digest = Hash::hash(&uw.new_kernel.coinbase);
        tasmlib::tasmlib_hashing_merkle_verify(
            old_txk_digest,
            TransactionKernelField::Coinbase as u32,
            coinbase_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Coinbase as u32,
            coinbase_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // timestamp increases or no change
        let new_timestamp: Timestamp = uw.new_kernel.timestamp;
        let new_timestamp_hash: Digest = Hash::hash(&new_timestamp);
        let old_timestamp: Timestamp = uw.old_kernel.timestamp;
        let old_timestamp_hash: Digest = Hash::hash(&old_timestamp);
        tasmlib::tasmlib_hashing_merkle_verify(
            old_txk_digest,
            TransactionKernelField::Timestamp as u32,
            old_timestamp_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        tasmlib::tasmlib_hashing_merkle_verify(
            new_txk_digest,
            TransactionKernelField::Timestamp as u32,
            new_timestamp_hash,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );
        assert!(new_timestamp >= old_timestamp);

        // mutator set can change, but we only care about extensions of the AOCL MMR
        tasmlib::verify_mmr_successor_proof(&old_aocl_mmr, &new_aocl_mmr, &uw.aocl_successor_proof);

        // output hash of program against which the out-of-date transaction was proven valid
        tasmlib::tasmlib_io_write_to_stdout___digest(single_proof_program_digest);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let load_digest = triton_asm!(push {Digest::LEN - 1} add read_mem {Digest::LEN} pop 1);
        let load_digest_reversed = triton_asm! {
            // *digest
            read_mem 1 addi 2
            read_mem 1 addi 2
            read_mem 1 addi 2
            read_mem 1 addi 2
            read_mem 1 pop 1
        };

        let new_claim = library.import(Box::new(NewClaim));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let update_witness_field_old_kernel_mast_hash = field!(UpdateWitness::old_kernel_mast_hash);
        let generate_single_proof_claim = triton_asm!(
            // _ *update_witness [txk_mast_hash]

            push {Digest::LEN} push 0
            call {new_claim}
            // _ *update_witness [txk_mast_hash] *claim *output *input *program_digest

            read_io {Digest::LEN}
            // _ *update_witness [txk_mast_hash] *claim *output *input *program_digest [single_proof_program_digest]

            dup 5
            // _ **update_witness [txk_mast_hash] claim *output *input *program_digest [single_proof_program_digest] *program_digest

            write_mem {Digest::LEN} pop 2
            // _ *update_witness [txk_mast_hash] *claim *output *input

            dup 8 {&update_witness_field_old_kernel_mast_hash}
            {&load_digest_reversed}
            // _ *update_witness [txk_mast_hash] *claim *output *input [old_txk_mast_hash_as_input]

            dup 5 write_mem {Digest::LEN}
            // _ *update_witness [txk_mast_hash] *claim *output *input (*input+5)

            pop 3
            // _ *update_witness [txk_mast_hash] *claim
        );

        let update_witness_field_old_proof = field!(UpdateWitness::old_proof);

        let main = triton_asm! {
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *update_witness

            read_io {Digest::LEN}
            // _ *update_witness [txk_mast_hash]

            {&generate_single_proof_claim}
            // _ *update_witness [txk_mast_hash] *claim

            dup 0 dup 7 {&update_witness_field_old_proof}
            // _ *update_witness [txk_mast_hash] *claim *claim *proof

            break
            call {stark_verify}
            // _ *update_witness [txk_mast_hash] *claim

            halt

        };

        triton_asm! {
            {&main}
            {&library.all_imports()}
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use tasm_lib::triton_vm::program::PublicInput;
    use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
    use tasm_lib::Digest;

    use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
    use crate::models::blockchain::transaction::validity::single_proof::SingleProofWitness;
    use crate::models::blockchain::transaction::validity::update::Update;
    use crate::models::blockchain::transaction::PrimitiveWitness;
    use crate::models::blockchain::transaction::ProofCollection;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::proof_abstractions::SecretWitness;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use proptest::arbitrary::Arbitrary;
    use proptest::collection::vec;
    use proptest::strategy::Strategy;
    use proptest_arbitrary_interop::arb;

    use super::UpdateWitness;

    #[test]
    fn can_verify_transaction_update() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let newly_confirmed_records = vec(arb::<Digest>(), 0usize..100)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let proof_collection = ProofCollection::produce(&primitive_witness);
        let single_proof_witness = SingleProofWitness::from_collection(proof_collection);
        let proof = SingleProof.prove(
            &single_proof_witness.claim(),
            single_proof_witness.nondeterminism(),
        );

        let mut new_kernel = primitive_witness.kernel.clone();
        let mut new_msa = primitive_witness.mutator_set_accumulator.clone();
        for canonical_commitment in newly_confirmed_records.iter().copied() {
            new_msa.add(&AdditionRecord::new(canonical_commitment));
        }
        let aocl_successor_proof = MmrSuccessorProof::new_from_batch_append(
            &primitive_witness.mutator_set_accumulator.aocl,
            &newly_confirmed_records,
        );

        new_kernel.mutator_set_hash = new_msa.hash();
        new_kernel.timestamp = new_kernel.timestamp + Timestamp::days(1);
        // todo: also update mutator set
        let update_witness = UpdateWitness::from_old_transaction(
            primitive_witness.kernel,
            proof,
            primitive_witness.mutator_set_accumulator,
            new_kernel,
            new_msa,
            aocl_successor_proof,
        );

        let claim = update_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        let nondeterminism = update_witness.nondeterminism();

        let rust_result = Update.run_rust(&input, nondeterminism.clone());
        assert!(rust_result.is_ok());

        let tasm_result = Update.run_tasm(&input, nondeterminism);
        assert!(tasm_result.is_ok());
    }
}
