/*
- ~~either output the UTXO "(must be in the standard lock-script)\ (must be in the coins)"~~
- either
    - ✔️ output the address lock part
    - ✔️ output the ammount(s)
- ✔️ check the UTXO canonical commitment is in the AOCL
- ✔️ output the digest of the AOCL
- ✔️ output the digest of the `sender_randomness` (as reusing it won't allow to put the UTXO again, and its sole role is shifting the AR)
- no need to check the recipient digest as it doesn't add anything under the current assumptions */

use std::sync::OnceLock;

use tasm_lib::{
    field as rustfield,
    memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS},
    prelude::{Digest, Library, TasmObject, TasmStruct},
    triton_vm::{
        isa::triton_asm,
        prelude::BFieldCodec,
        proof::Claim,
        vm::{NonDeterminism, PublicInput},
    },
    twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator,
};

use crate::{
    api::export::{NativeCurrencyAmount, Utxo},
    protocol::proof_abstractions::{tasm::program::ConsensusProgram, SecretWitness},
    util_types::mutator_set::ms_membership_proof::MsMembershipProof,
};

#[derive(TasmObject, tasm_lib::triton_vm::prelude::BFieldCodec, Debug)]
struct WitnessMemory {
    /// AOCL for the block
    aocl: MmrAccumulator,
    ///
    membership_proof: MsMembershipProof,
    utxo: Utxo,
    // lock_script_and_witness: LockScriptAndWitness,
    utxo_digest: Digest,
}

#[derive(Debug)]
pub struct The(WitnessMemory, Claim);
impl The {
    pub fn claim_inputs(c: Claim, receiver_digest: Digest, release_date: Digest) -> Claim {
        c.with_input(
            [
                release_date.reversed().values(),
                receiver_digest.reversed().values(),
            ]
            .concat(),
        )
    }
    pub fn claim_outputs(
        c: Claim,
        sender_randomness_digest: Digest,
        aocl_digest: Digest,
        lock_postimage: Digest,
        amount: NativeCurrencyAmount,
        amount_timelocked: NativeCurrencyAmount,
    ) -> Claim {
        c.with_output(
            [
                sender_randomness_digest.values().to_vec(),
                aocl_digest.values().into(),
                lock_postimage.values().into(),
                amount.encode(),
                amount_timelocked.encode(),
            ]
            .concat(),
        )
    }

    pub fn new(
        c: Claim,
        witness_aocl: MmrAccumulator,
        witness_membershipproof: MsMembershipProof,
        witness_utxo: Utxo,
        witness_utxodigest: Digest,
    ) -> The {
        The(
            WitnessMemory {
                aocl: witness_aocl,
                membership_proof: witness_membershipproof,
                utxo: witness_utxo,
                utxo_digest: witness_utxodigest,
            },
            c,
        )
    }
}

impl SecretWitness for The {
    fn standard_input(&self) -> PublicInput {
        PublicInput {
            individual_tokens: self.claim().input,
        }
    }
    fn output(&self) -> Vec<tasm_lib::triton_vm::prelude::BFieldElement> {
        self.claim().output
    }
    fn claim(&self) -> Claim {
        self.1.clone()
    }

    fn program(&self) -> tasm_lib::triton_vm::prelude::Program {
        ConsensusProgram::program(self)
    }

    fn nondeterminism(&self) -> NonDeterminism {
        NonDeterminism {
            individual_tokens: vec![],
            digests: vec![],
            ram: {
                let mut m = std::collections::HashMap::default();
                encode_to_memory(
                    &mut m,
                    FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                    &self.0,
                );
                m
            },
        }
    }
}

impl ConsensusProgram for The {
    fn library_and_code(
        &self,
    ) -> (
        Library,
        Vec<tasm_lib::triton_vm::prelude::LabelledInstruction>,
    ) {
        let u64_stack_size: u32 = tasm_lib::prelude::DataType::U64
            .stack_size()
            .try_into()
            .unwrap();

        let mut library = Library::new();
        let lib_hash_varlen = library.import(Box::new(
            tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen,
        ));
        let lib_ms_commit =
            library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
        let lib_mmr_verify = library.import(Box::new(
            tasm_lib::mmr::verify_from_memory::MmrVerifyFromMemory,
        ));
        let lib_bagpeaks = library.import(Box::new(tasm_lib::mmr::bag_peaks::BagPeaks));
        let release_date = library.kmalloc(1);
        let lib_add_all_amounts_and_check_time_lock = library.import(
            Box::new(crate::protocol::consensus::type_scripts::amount::add_all_amounts_and_check_time_lock::AddAllAmountsAndCheckTimeLock {
                digest_source: crate::protocol::consensus::type_scripts::amount::total_amount_main_loop::DigestSource::
                Hardcode(crate::protocol::consensus::type_scripts::native_currency::NativeCurrency.hash()),
                release_date,
        }));

        let rustfield_membershipproof = rustfield!(WitnessMemory::membership_proof);
        let rustfield_senderrandomness = rustfield!(MsMembershipProof::sender_randomness);
        let rustfield_utxo = rustfield!(WitnessMemory::utxo);
        let rustfield_utxodigest = rustfield!(WitnessMemory::utxo_digest);
        let rustfield_aoclleafindex = rustfield!(MsMembershipProof::aocl_leaf_index);

        let payload = triton_asm! {
            /* pasted from <reserves.rs>
            ============== */
            // _

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // *w
            {&WitnessMemory::get_field("aocl")}
            // *aocl

            // prepare the value for '7.'
            dup 0
            {&MmrAccumulator::get_field("peaks")}
            // *aocl *aocl_peaks

            // read `receiver_digest`
            read_io 5
            // *aocl *aocl_peaks [receiver_digest]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *w
            {&rustfield_membershipproof}
            {&rustfield_senderrandomness}
            read_mem {Digest::LEN}
            pop 1
            // *aocl *aocl_peaks [receiver_digest] [sender_randomness]

            /* ## this segment diverges from the pasted code
            *it only affects the output sequence* */
            dup 4
            dup 4
            dup 4
            dup 4
            dup 4
            push 0
            push 0
            push 0
            push 0
            push 0
            write_io 5

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *w
            {&rustfield_utxo}
            // *aocl *aocl_peaks [receiver_digest] [sender_randomness] *utxo
        };

        let main = triton_asm! {
            read_mem 1
            addi 2
            // _ utxo_size *utxo+1
            swap 1
            // _ *utxo+1 utxo_size
            call {lib_hash_varlen}
            hint utxo_hash = stack[0..5]
            // *aocl *aocl_peaks [receiver_digest] [sender_randomness] [utxo_hash]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&rustfield_utxodigest}
            read_mem 5
            assert_vector
            // *aocl *aocl_peaks [receiver_digest] [sender_randomness] [utxo_hash]

            call {lib_ms_commit}
            // *aocl *aocl_peaks [canonical_commitment]

            /* 7. */
            dup 6 {&MmrAccumulator::get_field("leaf_count")}
            // *aocl *aocl_peaks [canonical_commitment] *num_leafs

            addi 1 read_mem {u64_stack_size} pop 1
            // *aocl *aocl_peaks [canonical_commitment] [num_leafs]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&rustfield_membershipproof}
            {&rustfield_aoclleafindex}
            read_mem {u64_stack_size}
            pop 1
            // *aocl *aocl_peaks [canonical_commitment] [num_leafs] [aocl_leaf_index]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&WitnessMemory::get_field("auth_path_aocl")}
            {&WitnessMemory::get_field("authentication_path")}
            // *aocl *aocl_peaks [canonical_commitment] [num_leafs] [aocl_leaf_index] *auth_path
            swap 2
            // *aocl *aocl_peaks [canonical_commitment] *auth_path [aocl_leaf_index] [num_leafs]
            swap 3
            // *aocl *aocl_peaks [num_leafs] *auth_path [aocl_leaf_index] [canonical_commitment]
            swap 1
            // *aocl *aocl_peaks [num_leafs] *auth_path [canonical_commitment] [aocl_leaf_index]
            swap 2
            // *aocl *aocl_peaks [num_leafs] [aocl_leaf_index] [canonical_commitment] *auth_path

            call {lib_mmr_verify}
            assert
            // *aocl

            /* finish of the code pasted from the beginning <reserves.rs>
            ____________________________ */

            /* the final part is pasted from <reserves.rs> too
            ============== */
            call {lib_bagpeaks}
            write_io 5

            read_io 1
            // release_date
            // https://github.com/Neptune-Crypto/neptune-core/blob/5c1c6ef2ca1e282a05c7dc5300e742c92758fbfb/neptune-core/src/protocol/consensus/type_scripts/native_currency.rs#L133C13-L135C18
            push {release_date.write_address()}
            write_mem 1
            pop 1

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&rustfield_utxo}
            {&Utxo::get_field("coins")}
            // *coins
            read_mem 1 addi 2
            // SI_coins *coins[0]
            push 0 swap
            // SI_coins 0 *coins[0]
            push 0
            push 0
            push 0
            push 0
            // SI_coins 0 *coins[0] amount timelocked_amount utxo_amount utxo_is_timelocked
            call {lib_add_all_amounts_and_check_time_lock}
            // num_coins num_coins *eof amount timelocked_amount utxo_amount' utxo_is_timelocked'
            pop 1 write_io 8
        };

        let imports = library.all_imports();
        let code = triton_asm!(
            {&payload}
            {&main}
            {&imports}
        );
        (library, code)
    }

    fn hash(&self) -> Digest {
        static DIGEST: OnceLock<Digest> = OnceLock::new();

        *DIGEST.get_or_init(|| ConsensusProgram::program(self).hash())
    }
}
