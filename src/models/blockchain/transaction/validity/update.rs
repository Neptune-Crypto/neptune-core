use std::sync::OnceLock;

use strum::EnumCount;
use tasm_lib::arithmetic::u64::lt_u64::LtU64ConsumeArgs;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::verify_mmr_successor::VerifyMmrSuccessor;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use tasm_lib::verifier::stark_verify::StarkVerify;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::validity::tasm::hash_removal_record_index_sets::HashRemovalRecordIndexSets;
use crate::models::blockchain::transaction::validity::tasm::leaf_authentication::authenticate_msa_against_txk::AuthenticateMsaAgainstTxk;
use crate::models::blockchain::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::models::blockchain::transaction::BFieldCodec;
use crate::models::blockchain::transaction::Proof;
use crate::models::blockchain::transaction::TransactionKernel;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::audit_vm_end_state::AuditVmEndState;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;
use crate::tasm_lib::memory::encode_to_memory;
use crate::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::models::blockchain::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
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
        vec![]
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
    /// Get the program hash digest.
    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }

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
        let claim: Claim =
            Claim::new(single_proof_program_digest).with_input(old_txk_digest_as_input);
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
        let old_inputs = &uw.old_kernel.inputs;
        let new_inputs = &uw.new_kernel.inputs;
        let old_inputs_hash: Digest = Hash::hash(old_inputs);
        let new_inputs_hash: Digest = Hash::hash(new_inputs);
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
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let load_digest = triton_asm!(push {Digest::LEN - 1} add read_mem {Digest::LEN} pop 1);

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let authenticate_msa = library.import(Box::new(AuthenticateMsaAgainstTxk));
        let authenticate_inputs = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Inputs,
        )));
        let authenticate_timestamp = library.import(Box::new(AuthenticateTxkField(
            TransactionKernelField::Timestamp,
        )));
        let verify_mmr_successor_proof = library.import(Box::new(VerifyMmrSuccessor));
        let hash_removal_record_index_set =
            library.import(Box::new(HashRemovalRecordIndexSets::<1>));
        let multiset_eq_digests = library.import(Box::new(MultisetEqualityDigests));
        let u64_lt = library.import(Box::new(LtU64ConsumeArgs));

        let old_txk_digest_alloc = library.kmalloc(Digest::LEN as u32);

        let old_kernel = field!(UpdateWitness::old_kernel);
        let load_old_kernel_digest = triton_asm!(
            push {old_txk_digest_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
        );

        let old_txk_mh = field!(UpdateWitness::old_kernel_mast_hash);
        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim));

        let audit_preloaded_data =
            library.import(Box::new(VerifyNdSiIntegrity::<UpdateWitness>::default()));
        let audit_end_vm_state =
            library.import(Box::new(AuditVmEndState::<UpdateWitness>::default()));

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

        let field_timestamp = field!(TransactionKernel::timestamp);
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

            dup 0
            call {audit_preloaded_data}
            // _ *update_witness witness_size

            swap 1
            // _ witness_size *update_witness

            dup 0
            {&old_txk_mh}
            // _ witness_size *update_witness *old_txk_mhash

            {&load_digest}
            // _ witness_size *update_witness [old_tx_mast_hash; 5]

            push {old_txk_digest_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ witness_size *update_witness

            read_io {Digest::LEN}
            // _ witness_size *update_witness [new_txk_mhash]

            push {old_txk_digest_alloc.read_address()}
            read_mem 5
            pop 1
            // _ witness_size *update_witness [new_txk_mhash] [old_txk_mhash; 5]

            read_io 5
            // _ witness_size *update_witness [new_txk_mhash] [old_txk_mhash; 5] [single_proof_digest; 5]

            call {generate_single_proof_claim}
            // _ witness_size *update_witness [new_txk_mhash] *claim

            dup 6 {&update_witness_field_old_proof}
            // _ witness_size *update_witness [new_txk_mhash] *claim *proof

            call {stark_verify}
            // _ witness_size *update_witness [new_txk_mhash]

            /* Verify AOCL-related witness data */
            /* 1: Verify new AOCL-related witness data */
            dup 5
            {&new_aocl_mmr_field}
            // _ witness_size *update_witness [new_txk_mhash] *new_aocl

            dup 6
            {&new_swbfi_bagged}
            // _ witness_size *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged

            dup 7
            {&new_swbfa_hash}
            // _ witness_size *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest

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
            // _ witness_size *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest

            /* Verify old AOCL-related witness data */
            dup 8
            {&old_aocl_mmr_field}
            // _ witness_size *update_witness [...; 8] *old_aocl

            dup 9
            {&old_swbfi_bagged}
            // _ witness_size *update_witness [...; 8] *old_aocl *old_swbfi_bagged

            dup 10
            {&old_swbfa_hash}
            // _ witness_size *update_witness [...; 8] *old_aocl *old_swbfi_bagged *old_swbfa_digest

            dup 2
            {&peaks_field}

            dup 2
            dup 2
            push {old_txk_digest_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            call {authenticate_msa}
            // _ witness_size *update_witness [new_txk_mhash] *new_aocl *new_swbfi_bagged *new_swbfa_digest *old_aocl *old_swbfi_bagged *old_swbfa_digest

            pop 2
            swap 2
            pop 2
            swap 1
            // _ witness_size *update_witness [new_txk_mhash] *old_aocl *new_aocl

            /* Verify that new AOCL is a successor of old AOCL */
            call {verify_mmr_successor_proof}
            // _ witness_size *update_witness [new_txk_mhash]


            /* Authenticate inputs, preserve pointers */
            dup 5
            {&old_kernel}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel
            dup 0
            {&inputs_field_with_size}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *old_inputs old_inputs_size

            push {old_txk_digest_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *old_inputs old_inputs_size [old_txk_mhash]

            dup 6
            dup 6
            call {authenticate_inputs}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *old_inputs old_inputs_size

            pop 1
            dup 7
            {&new_kernel}
            hint new_kernel_ptr = stack[0]
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *old_inputs *new_kernel

            swap 1
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs

            dup 1 {&inputs_field_with_size}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size

            dup 9
            dup 9
            dup 9
            dup 9
            dup 9
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size [new_txk_mhash]

            dup 6
            dup 6
            call {authenticate_inputs}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs new_inputs_size

            pop 1
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs

            /* verify index set equality */
            call {hash_removal_record_index_set}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel *old_inputs *new_inputs_digests

            swap 1
            call {hash_removal_record_index_set}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel *new_inputs_digests *old_inputs_digests

            call {multiset_eq_digests}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel set_equality(*new_inputs_digests, *old_inputs_digests)

            assert
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate outputs and verify no-change */
            {&authenticate_field_twice_with_no_change(&outputs_field_with_size, TransactionKernelField::Outputs)}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate public announcements and verify no-change */
            {&authenticate_field_twice_with_no_change(&public_announcements_field_with_size, TransactionKernelField::PublicAnnouncements)}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate fee and verify no-change */
            {&authenticate_field_twice_with_no_change(&fee_field_with_size, TransactionKernelField::Fee)}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate coinbase and verify no-change */
            {&authenticate_field_twice_with_no_change(&coinbase_field_with_size, TransactionKernelField::Coinbase)}
            // _ witness_size *update_witness [new_txk_mhash] *old_kernel *new_kernel

            /* Authenticate timestamps and verify gte */
            {&field_timestamp}
            swap 1
            {&field_timestamp}
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp *old_timestamp

            {&load_old_kernel_digest}
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp *old_timestamp [old_kernel_txk_mh]

            dup 5 push 1
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp *old_timestamp [old_kernel_txk_mh] *old_timestamp 1

            call {authenticate_timestamp}
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp *old_timestamp

            dup 6
            dup 6
            dup 6
            dup 6
            dup 6
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp *old_timestamp [new_txk_mhash]

            dup 6 push 1
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp *old_timestamp [new_txk_mhash] *new_timestamp 1

            call {authenticate_timestamp}
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp *old_timestamp

            read_mem 1 pop 1
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp old_timestamp

            split
            // _ witness_size *update_witness [new_txk_mhash] *new_timestamp old_hi old_lo

            swap 1
            swap 2
            read_mem 1
            pop 1
            split
            // _ witness_size *update_witness [new_txk_mhash] old_hi old_lo new_hi new_lo

            call {u64_lt}
            // _ witness_size *update_witness [new_txk_mhash] (new_timestamp < old_timestamp)

            push 0 eq
            // _ witness_size *update_witness [new_txk_mhash] (new_timestamp >= old_timestamp)

            assert
            // _ witness_size *update_witness [new_txk_mhash]

            pop {Digest::LEN}
            // _ witness_size *update_witness

            call {audit_end_vm_state}
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
    use itertools::Itertools;
    use proptest::arbitrary::Arbitrary;
    use proptest::collection::vec;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::prelude::*;
    use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;

    use super::*;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
    use crate::models::blockchain::transaction::PrimitiveWitness;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::blockchain::transaction::TransactionKernelModifier;
    use crate::models::proof_abstractions::tasm::program::test::consensus_program_negative_test;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::test_shared::mutator_set::pseudorandom_removal_record;

    impl UpdateWitness {
        pub(crate) fn new_kernel_mast_hash(&self) -> Digest {
            self.new_kernel_mast_hash
        }
    }

    /// Return an update witness where the mutator set has had both elements
    /// added and removed.
    pub(crate) async fn deterministic_update_witness_additions_and_removals(
        num_inputs: usize,
        num_outputs: usize,
        num_pub_announcements: usize,
    ) -> UpdateWitness {
        let mut test_runner = TestRunner::deterministic();
        let num_new_records = (1usize..=10).new_tree(&mut test_runner).unwrap().current();
        let num_new_removals = (1usize..=10).new_tree(&mut test_runner).unwrap().current();
        let num_new_pub_announcements = 2;
        let [old_pw, mined] = PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets([
            (num_inputs, num_outputs, num_pub_announcements),
            (num_new_records, num_new_removals, num_new_pub_announcements),
        ])
        .new_tree(&mut test_runner)
        .unwrap()
        .current();

        let newly_confirmed_records = mined
            .kernel
            .outputs
            .iter()
            .map(|x| x.canonical_commitment)
            .collect_vec();
        let aocl_successor_proof = MmrSuccessorProof::new_from_batch_append(
            &old_pw.mutator_set_accumulator.aocl,
            &newly_confirmed_records,
        );

        let mut updated = Transaction::new_with_primitive_witness_ms_data(
            old_pw.clone(),
            mined.kernel.outputs.clone(),
            mined.kernel.inputs.clone(),
        );

        let mut new_mutator_set_accumulator = old_pw.mutator_set_accumulator.clone();
        MutatorSetUpdate::new(mined.kernel.inputs.clone(), mined.kernel.outputs.clone())
            .apply_to_accumulator(&mut new_mutator_set_accumulator)
            .unwrap();
        let old_proof = SingleProof::produce(
            &old_pw,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        let num_seconds = (0u64..=10).new_tree(&mut test_runner).unwrap().current();

        updated.kernel = TransactionKernelModifier::default()
            .timestamp(updated.kernel.timestamp + Timestamp::seconds(num_seconds))
            .modify(updated.kernel);

        UpdateWitness::from_old_transaction(
            old_pw.kernel,
            old_proof,
            old_pw.mutator_set_accumulator,
            updated.kernel,
            new_mutator_set_accumulator,
            aocl_successor_proof,
        )
    }

    /// Return an update witness where the mutator set is only changed by new
    /// additions.
    pub(crate) async fn deterministic_update_witness_only_additions(
        num_inputs: usize,
        num_outputs: usize,
        num_pub_announcements: usize,
    ) -> UpdateWitness {
        // TODO: Currently only tests a new mutator set with more AOCL leafs.
        // Should also test for removed records in the new mutator set
        // accumulator.
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness =
            PrimitiveWitness::arbitrary_with((num_inputs, num_outputs, num_pub_announcements))
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        let newly_confirmed_records = vec(arb::<Digest>(), 0usize..100)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let mut new_msa = primitive_witness.mutator_set_accumulator.clone();
        for canonical_commitment in newly_confirmed_records.iter().copied() {
            new_msa.add(&AdditionRecord::new(canonical_commitment));
        }

        let new_kernel = TransactionKernelModifier::default()
            .mutator_set_hash(new_msa.hash())
            .timestamp(primitive_witness.kernel.timestamp + Timestamp::days(1))
            .clone_modify(&primitive_witness.kernel);

        assert_ne!(
            new_msa, primitive_witness.mutator_set_accumulator,
            "must update mutator set too in order for test to be meaningful"
        );

        let aocl_successor_proof = MmrSuccessorProof::new_from_batch_append(
            &primitive_witness.mutator_set_accumulator.aocl,
            &newly_confirmed_records,
        );
        let old_proof = SingleProof::produce(
            &primitive_witness,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();

        UpdateWitness::from_old_transaction(
            primitive_witness.kernel,
            old_proof,
            primitive_witness.mutator_set_accumulator,
            new_kernel,
            new_msa,
            aocl_successor_proof,
        )
    }

    fn positive_prop(update_witness: UpdateWitness) {
        let claim = update_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        let nondeterminism = update_witness.nondeterminism();

        let rust_result = Update.run_rust(&input, nondeterminism.clone());

        let tasm_result = Update.run_tasm(&input, nondeterminism);

        assert_eq!(rust_result.unwrap(), tasm_result.unwrap());
    }

    #[tokio::test]
    async fn only_additions_small() {
        positive_prop(deterministic_update_witness_only_additions(2, 2, 2).await);
    }

    #[tokio::test]
    async fn only_additions_medium() {
        positive_prop(deterministic_update_witness_only_additions(4, 4, 4).await);
    }

    #[tokio::test]
    async fn addition_and_removals_tiny() {
        positive_prop(deterministic_update_witness_additions_and_removals(1, 1, 1).await);
    }

    #[tokio::test]
    async fn addition_and_removals_small() {
        positive_prop(deterministic_update_witness_additions_and_removals(2, 2, 2).await);
    }

    #[tokio::test]
    async fn addition_and_removals_midi() {
        positive_prop(deterministic_update_witness_additions_and_removals(3, 3, 3).await);
    }

    #[tokio::test]
    async fn addition_and_removals_medium() {
        positive_prop(deterministic_update_witness_additions_and_removals(4, 4, 4).await);
    }

    fn new_timestamp_older_than_old(good_witness: &UpdateWitness) {
        let mut bad_witness = good_witness.to_owned();

        bad_witness.new_kernel = TransactionKernelModifier::default()
            .timestamp(bad_witness.old_kernel.timestamp - Timestamp::hours(1))
            .modify(bad_witness.new_kernel);

        let claim = bad_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        let nondeterminism = bad_witness.nondeterminism();
        consensus_program_negative_test(Update, &input, nondeterminism, &[]);
    }

    fn bad_new_aocl(good_witness: &UpdateWitness) {
        let claim = good_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        let mut nondeterminism = good_witness.nondeterminism();

        let mut witness_again: UpdateWitness = *UpdateWitness::decode_from_memory(
            &nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
        )
        .unwrap();
        witness_again.new_aocl.append(random());
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &witness_again,
        );
        consensus_program_negative_test(Update, &input, nondeterminism, &[]);
    }

    fn bad_old_aocl(good_witness: &UpdateWitness) {
        let claim = good_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        let mut nondeterminism = good_witness.nondeterminism();

        let mut witness_again: UpdateWitness = *UpdateWitness::decode_from_memory(
            &nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
        )
        .unwrap();
        witness_again.old_aocl.append(random());
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &witness_again,
        );
        consensus_program_negative_test(Update, &input, nondeterminism, &[]);
    }

    fn bad_absolute_index_set_value(good_witness: &UpdateWitness) {
        let mut bad_witness = good_witness.clone();

        let mut new_inputs = bad_witness.new_kernel.inputs.clone();
        new_inputs[0]
            .absolute_indices
            .decrement_bloom_filter_index(10);

        bad_witness.new_kernel = TransactionKernelModifier::default()
            .inputs(new_inputs)
            .modify(bad_witness.new_kernel);

        let claim = bad_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();
        let nondeterminism = bad_witness.nondeterminism();
        consensus_program_negative_test(Update, &input, nondeterminism, &[]);
    }

    fn bad_absolute_index_set_length_too_short(good_witness: &UpdateWitness) {
        let mut bad_witness = good_witness.clone();

        let mut new_inputs = bad_witness.new_kernel.inputs.clone();
        new_inputs.remove(0);
        bad_witness.new_kernel = TransactionKernelModifier::default()
            .inputs(new_inputs)
            .modify(bad_witness.new_kernel);

        let claim = bad_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();
        let nondeterminism = bad_witness.nondeterminism();
        consensus_program_negative_test(Update, &input, nondeterminism, &[]);
    }

    fn bad_absolute_index_set_length_too_long(good_witness: &UpdateWitness) {
        let mut rng = StdRng::seed_from_u64(0);
        let mut bad_witness = good_witness.clone();

        let mut new_inputs = bad_witness.new_kernel.inputs.clone();
        new_inputs.push(pseudorandom_removal_record(rng.gen()));

        bad_witness.new_kernel = TransactionKernelModifier::default()
            .inputs(new_inputs)
            .modify(bad_witness.new_kernel);

        let claim = bad_witness.claim();
        let input = PublicInput::new(claim.input.clone());
        bad_witness.new_kernel_mast_hash = bad_witness.new_kernel.mast_hash();
        let nondeterminism = bad_witness.nondeterminism();
        consensus_program_negative_test(Update, &input, nondeterminism, &[]);
    }

    #[tokio::test]
    async fn update_witness_negative_tests() {
        // It takes a long time to generate the witness, so we reuse it across
        // multiple tests
        let good_witness = deterministic_update_witness_only_additions(2, 2, 2).await;
        new_timestamp_older_than_old(&good_witness);
        bad_new_aocl(&good_witness);
        bad_old_aocl(&good_witness);
        bad_absolute_index_set_value(&good_witness);
        bad_absolute_index_set_length_too_short(&good_witness);
        bad_absolute_index_set_length_too_long(&good_witness);
    }

    /// A test of the simple test generator, that it leaves the expected fields
    /// untouched, or at most permuted.
    #[tokio::test]
    async fn txid_is_constant_under_tx_updates_only_additions() {
        let update_witness = deterministic_update_witness_only_additions(4, 4, 4).await;
        assert_eq!(
            update_witness.old_kernel.txid(),
            update_witness.new_kernel.txid(),
            "Txid function must agree before and after transaction update"
        );
    }

    /// A test of the simple test generator, that it leaves the expected fields
    /// untouched, or at most permuted.
    #[tokio::test]
    async fn txid_is_constant_under_tx_updates_additions_and_removals() {
        let update_witness = deterministic_update_witness_additions_and_removals(4, 4, 4).await;
        assert_eq!(
            update_witness.old_kernel.txid(),
            update_witness.new_kernel.txid(),
            "Txid function must agree before and after transaction update"
        );
    }
}
