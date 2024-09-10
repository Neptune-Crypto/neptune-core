use strum::EnumCount;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::mmr::verify_mmr_successor::VerifyMmrSuccessor;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::triton_asm;
use tasm_lib::twenty_first::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::Digest;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::validity::tasm::assert_rr_index_set_equality::AssertRemovalRecordIndexSetEquality;
use crate::models::blockchain::transaction::validity::tasm::leaf_authentication::authenticate_inputs_against_txk::AuthenticateInputsAgainstTxk;
use crate::models::blockchain::transaction::validity::tasm::leaf_authentication::authenticate_msa_against_txk::AuthenticateMsaAgainstTxk;
use crate::models::blockchain::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
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
            ]
            .concat(),
        );

        VerifyMmrSuccessor::update_nondeterminism(&mut nondeterminism, &self.aocl_successor_proof);

        nondeterminism.digests.append(
            &mut [
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

        // mutator set can change, but we only care about extensions of the AOCL MMR
        tasmlib::verify_mmr_successor_proof(&old_aocl_mmr, &new_aocl_mmr, &uw.aocl_successor_proof);

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
        let authenticate_msa = library.import(Box::new(AuthenticateMsaAgainstTxk));
        let authenticate_inputs = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Inputs,
        )));
        let authenticate_outputs = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Outputs,
        )));
        let verify_mmr_successor_proof = library.import(Box::new(VerifyMmrSuccessor));
        let assert_rr_index_set_equality =
            library.import(Box::new(AssertRemovalRecordIndexSetEquality));

        let old_txk_digest_begin_ptr = library.kmalloc(Digest::LEN as u32);
        let old_txk_digest_end_ptr = old_txk_digest_begin_ptr + bfe!(Digest::LEN as u64 - 1);

        let old_kernel = field!(UpdateWitness::old_kernel);
        let load_old_kernel_digest = triton_asm!(
            push {old_txk_digest_end_ptr}
            read_mem {Digest::LEN}
            pop 1
        );

        let update_witness_field_old_kernel_mast_hash = field!(UpdateWitness::old_kernel_mast_hash);
        let generate_single_proof_claim = triton_asm!(
            // _ *update_witness [new_txk_mhash]

            push {Digest::LEN} push 0
            call {new_claim}
            // _ *update_witness [new_txk_mhash] *claim *output *input *program_digest

            read_io {Digest::LEN}
            // _ *update_witness [new_txk_mhash] *claim *output *input *program_digest [single_proof_program_digest]

            dup 5
            // _ **update_witness [new_txk_mhash] claim *output *input *program_digest [single_proof_program_digest] *program_digest

            write_mem {Digest::LEN} pop 2
            // _ *update_witness [new_txk_mhash] *claim *output *input

            dup 8 {&update_witness_field_old_kernel_mast_hash}
            {&load_digest}
            // _ *update_witness [new_txk_mhash] *claim *output *input [old_tx_mast_hash]

            push {old_txk_digest_begin_ptr}
            write_mem {Digest::LEN}
            pop 1
            // _ *update_witness [new_txk_mhash] *claim *output *input

            push {old_txk_digest_begin_ptr}
            {&load_digest_reversed}
            // _ *update_witness [new_txk_mhash] *claim *output *input [old_txk_mhash_as_input]

            dup 5 write_mem {Digest::LEN}
            // _ *update_witness [new_txk_mhash] *claim *output *input (*input+5)

            pop 3
            // _ *update_witness [new_txk_mhash] *claim
        );

        let mut authenticate_field_twice_with_no_change =
            |field_with_size_getter: &[LabelledInstruction], field: TransactionKernelField| {
                let authenticate_generic_field =
                    library.import(Box::new(AuthenticateTxkField(field)));
                triton_asm! {
                    // _ [new_txk_mhash] *old_kernel *new_kernel

                    dup 1
                    // _ [new_txk_mhash] *old_kernel *new_kernel *old_kernel

                    {&field_with_size_getter}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size

                    {&load_old_kernel_digest}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size [old_txk_mhash]

                    dup 6 dup 6 call {authenticate_generic_field}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size

                    dup 8
                    dup 8
                    dup 8
                    dup 8
                    dup 8
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size [new_txk_mhash]

                    dup 6 dup 6 call {authenticate_generic_field}
                    // _ [new_txk_mhash] *old_kernel *new_kernel *field field_size

                    pop 2
                    // _ [new_txk_mhash] *old_kernel *new_kernel
                }
            };

        let update_witness_field_old_proof = field!(UpdateWitness::old_proof);

        let new_aocl_mmr_field = field!(UpdateWitness::new_aocl);
        let new_swbfi_bagged = field!(UpdateWitness::new_swbfi_bagged);
        let new_swbfa_hash = field!(UpdateWitness::new_swbfa_hash);
        let old_aocl_mmr_field = field!(UpdateWitness::old_aocl);
        let old_swbfi_bagged = field!(UpdateWitness::old_swbfi_bagged);
        let old_swbfa_hash = field!(UpdateWitness::old_swbfa_hash);
        let peaks_field = field!(MmrAccumulator::peaks);

        let new_kernel = field!(UpdateWitness::new_kernel);
        let old_txk_mh = field!(UpdateWitness::old_kernel_mast_hash);
        let inputs_field_with_size = field_with_size!(TransactionKernel::inputs);
        let outputs_field_with_size = field_with_size!(TransactionKernel::outputs);
        let public_announcements_field_with_size =
            field_with_size!(TransactionKernel::public_announcements);
        let fee_field_with_size = field_with_size!(TransactionKernel::fee);
        let coinbase_field_with_size = field_with_size!(TransactionKernel::coinbase);

        let main = triton_asm! {
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *update_witness

            read_io {Digest::LEN}
            // _ *update_witness [new_txk_mhash]

            {&generate_single_proof_claim}
            // _ *update_witness [new_txk_mhash] *claim

            dup 6 {&update_witness_field_old_proof}
            // _ *update_witness [new_txk_mhash] *claim *proof

            call {stark_verify}
            // _ *update_witness [new_txk_mhash]

            /* Verify AOCL-related witness data */
            /* 1: Verify new AOCL-related witness data */
            dup 5
            {&new_aocl_mmr_field}
            // _ *update_witness [new_txk_mhash] *new_aocl

            dup 6
            {&new_swbfi_bagged}
            // _ *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged

            dup 7
            {&new_swbfa_hash}
            // _ *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest

            dup 2
            {&peaks_field}

            dup 2
            dup 2
            dup 10
            dup 10
            dup 10
            dup 10
            dup 10
            call {authenticate_msa}
            // _ *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest

            /* Verify old AOCL-related witness data */
            dup 8
            {&old_aocl_mmr_field}
            // _ *update_witness [...; 8] *old_aocl

            dup 9
            {&old_swbfi_bagged}
            // _ *update_witness [...; 8] *old_aocl *old_swbfi_bagged

            dup 10
            {&old_swbfa_hash}
            // _ *update_witness [...; 8] *old_aocl *old_swbfi_bagged *old_swbfa_digest

            dup 2
            {&peaks_field}

            dup 2
            dup 2
            push {old_txk_digest_end_ptr}
            read_mem {Digest::LEN}
            pop 1
            call {authenticate_msa}
            // _ *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest *old_aocl *old_swbfi_bagged *old_swbfa_digest

            pop 2
            swap 2
            pop 2
            swap 1
            // _ *update_witness [new_txk_mhash] *old_aocl *new_aocl

            /* Verify that new AOCL is a successor of old AOCL */
            call {verify_mmr_successor_proof}
            // _ *update_witness [new_txk_mhash]


            /* Authenticate inputs, preserve pointers */
            dup 5
            {&old_kernel}
            // _ *update_witness [new_txk_mhash] *old_kernel
            dup 0
            {&inputs_field_with_size}
            // _ *update_witness [new_txk_mhash] *old_kernel *old_inputs old_inputs_size

            push {old_txk_digest_end_ptr}
            read_mem {Digest::LEN}
            pop 1
            // _ *update_witness [new_txk_mhash] *old_kernel *old_inputs old_inputs_size [old_txk_mhash]

            dup 6
            dup 6
            call {authenticate_inputs}
            // _ *update_witness [new_txk_mhash] *old_kernel *old_inputs old_inputs_size

            pop 1
            dup 7
            {&new_kernel}
            // _ *update_witness [new_txk_mhash] *old_kernel *old_inputs old_inputs_size *new_kernel

            swap 2
            swap 1
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs old_inputs_size

            dup 2 {&inputs_field_with_size}
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size

            dup 9
            dup 9
            dup 9
            dup 9
            dup 9
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size [new_txk_mhash]

            dup 6
            dup 6
            call {authenticate_inputs}
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size

            pop 1
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs

            /* verify index set equality */
            call {assert_rr_index_set_equality}
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate outputs and verify no-change */
            {&authenticate_field_twice_with_no_change(&outputs_field_with_size, TransactionKernelField::Outputs)}
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate public announcements and verify no-change */
            {&authenticate_field_twice_with_no_change(&public_announcements_field_with_size, TransactionKernelField::PublicAnnouncements)}
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate outputs and verify no-change */
            {&authenticate_field_twice_with_no_change(&fee_field_with_size, TransactionKernelField::Fee)}
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate public announcements and verify no-change */
            {&authenticate_field_twice_with_no_change(&coinbase_field_with_size, TransactionKernelField::Coinbase)}
            // _ *update_witness [new_txk_mhash] *old_kernel *new_kernel

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
