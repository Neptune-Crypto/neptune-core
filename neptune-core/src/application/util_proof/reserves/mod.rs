/// ~~this will need a rehaul when other typescript will be in the wild \
/// currently it uses presupposition that only Time-lock and Native currency are around~~
///
/// Outputting RR not only allows to check that the UTXO wasn't spent immediately after proving, but also allows to check that it isn't used in unrelated proofs (a problem which
/// occurs on its own and basically leads to the same solution).
///
/// Proving per an UTXO makes the job easier for the prover because 1) parrallelization and 2) the smaller proofs. This increase a verifier work which shouldn't be a problem due
/// to parallelization.
///
/// # running
/// Correct me if I'm wrong: for proving a new Neptune CLI command should be added.
/// # checks out of Triton
/// - AOCL must be from the block of interest
/// - each ~~salted~~ digest of RR should bump the amount only once
/// - the RR should not be already spent
/// - the address parts
/// - ...
/// # inside of Triton
/// - ✔️ hash the UTXO to find it's in the AOCL
/// - 🗙 check the preloaded AOCL is the same one in the membership proof (turned out this is covered by the membership proof check)
/// - ✔️ trace `MsMembershipProof` is in `TransactionDetails::mutator_set_accumulator` (*output*!)
/// - ✔️ trace unlocking the UTXO and *output* the digest/address of the holder
/// - ✔️ find the native coin in the coins
/// - ✔️ type script digest must match
/// - ✔️ *output* the amount
/// - 🗙 check that RR isn't in the Bloom filter
/// - 🗙 hash the RR with the Bloom filter state and *output*
use tasm_lib::{
    data_type::StructType,
    field as rustfield,
    io::{read_input::ReadInput, InputSource},
    memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
    prelude::{DataType, Digest, Library, TasmObject, TasmStruct},
    triton_vm::{isa::triton_asm, prelude::BFieldElement},
    twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator,
};

use crate::{
    api::export::{NativeCurrencyAmount, Timestamp, Utxo},
    protocol::consensus::transaction::utxo::Coin,
    state::wallet::unlocked_utxo::UnlockedUtxo,
    util_types::mutator_set::ms_membership_proof::MsMembershipProof,
};

#[derive(TasmObject, tasm_lib::triton_vm::prelude::BFieldCodec, Debug)]
pub(crate) struct WitnessMemory {
    // from `UnlockedUtxo`
    /* the preimage from the witness is probably unnecessary as we can just check that postimage is the same as in
    the public input and TODO ensure this is the same UTXO which produces the RR output */
    //
    /// AOCL for the block
    aocl: MmrAccumulator,
    ///
    membership_proof: MsMembershipProof,
    utxo: Utxo,
    // lock_script_and_witness: LockScriptAndWitness,
    utxo_digest: Digest,
    lock_preimage: Digest,
}
#[derive(Debug)]
pub struct PublicData {
    /// `receiver_digest`;
    /// `release_date` ([add `MINING_REWARD_TIME_LOCK_PERIOD`](https://github.com/Neptune-Crypto/neptune-core/blob/5c1c6ef2ca1e282a05c7dc5300e742c92758fbfb/neptune-core/src/protocol/consensus/type_scripts/native_currency.rs#L365))
    input: (Digest, Timestamp),
    /// the record to check if the reserve is still unspent;
    /// AOCL digest;
    /// `lock_postimage` of the address;
    /// the 'reserve'
    /// the timelocked 'reserve'
    output: (
        crate::util_types::mutator_set::removal_record::RemovalRecord,
        Digest,
        Digest,
        NativeCurrencyAmount,
        NativeCurrencyAmount,
    ),
}
impl crate::protocol::proof_abstractions::tasm::program::ConsensusProgram for PublicData {
    fn library_and_code(
        &self,
    ) -> (
        Library,
        Vec<tasm_lib::triton_vm::prelude::LabelledInstruction>,
    ) {
        let u64_stack_size: u32 = DataType::U64.stack_size().try_into().unwrap();

        let mut library = Library::new();
        let lib_hash_varlen = library.import(Box::new(
            tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen,
        ));
        let lib_ms_commit =
            library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
        let lib_mmr_verify = library.import(Box::new(
            tasm_lib::mmr::verify_from_memory::MmrVerifyFromMemory,
        ));
        let lib_compute_absolute_indices = library.import(Box::new(crate::protocol::consensus::transaction::validity::tasm::compute_absolute_indices::ComputeAbsoluteIndices));
        let lib_hash_absolute_indices = library.import(Box::new(tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize {
            size: <crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet as tasm_lib::triton_vm::prelude::BFieldCodec>::static_length().expect("absolute indices have a static size"),
        }));
        let lib_bagpeaks = library.import(Box::new(tasm_lib::mmr::bag_peaks::BagPeaks));
        let release_date = library.kmalloc(1);
        let lib_add_all_amounts_and_check_time_lock = library.import(
            Box::new(crate::protocol::consensus::type_scripts::amount::add_all_amounts_and_check_time_lock::AddAllAmountsAndCheckTimeLock {
                digest_source: crate::protocol::consensus::type_scripts::amount::total_amount_main_loop::DigestSource::
                Hardcode(crate::protocol::consensus::type_scripts::native_currency::NativeCurrency.hash()),
                release_date,
        }));

        // let aocl_datatype = DataType::StructRef(
        //     StructType{ name: "MmrAccumulator".into(), fields: vec!(
        //         ("leaf_count".into(), DataType::U64), ("peaks".into(), DataType::List(DataType::Digest.into()))
        //     ) }
        //     // self.input.try_into().expect("TODO move this into `self`")
        // );
        // // let aocl_read = ReadInput{ data_type: aocl_datatype, input_source: InputSource::StdIn };
        // let the_input_public = DataType::Tuple(vec![aocl_datatype, DataType::Digest, DataType::Digest]);
        // let mmrmembershipproof_datatype = DataType::StructRef(StructType {name: "MmrMembershipProof".into(), fields: vec!(
        //     ("authentication_path".into(), DataType::List(DataType::Digest.into()))
        // )});
        // let ram = DataType::StructRef(StructType { name: "ram".into(), fields: vec![
        //     ("utxo".into(), DataType::StructRef(StructType { name: "Utxo".into(), fields: vec![
        //         ("lock_script_hash".into(), DataType::Digest),
        //         ("coins".into(), DataType::List(DataType::StructRef(StructType {name: "Coin".into(), fields: vec!(
        //             ("type_script_hash".into(), DataType::Digest),
        //             ("state".into(), DataType::List(DataType::Bfe.into()))
        //         )}).into()))
        //     ] })),
        //     ("membership_proof".into(), DataType::StructRef(StructType { name: "MsMembershipProof".into(), fields: vec![
        //         ("sender_randomness".into(), DataType::Digest),
        //         ("receiver_preimage".into(), DataType::Digest),
        //         ("auth_path_aocl".into(), mmrmembershipproof_datatype),
        //         ("aocl_leaf_index".into(), DataType::U64),
        //         ("target_chunks".into(), DataType::StructRef(StructType {name: "ChunkDictionary".into(), fields: vec!(
        //             ("dictionary".into(), DataType::List(DataType::Tuple(vec![DataType::U64, DataType::Tuple(vec!(
        //                 mmrmembershipproof_datatype,
        //                 DataType::StructRef(StructType {name: "Chunk".into(), fields: vec!(
        //                     ("relative_indices".into(), DataType::U32)
        //                 )})
        //             ))]).into()))
        //         )})),
        //     ] }))
        // ]});

        // let npt_typesc_digest = .values();

        let rustfield_leafcount = rustfield!(MmrAccumulator::leaf_count);
        let rustfield_peaks = rustfield!(MmrAccumulator::peaks);
        let rustfield_membershipproof = rustfield!(WitnessMemory::membership_proof);
        let rustfield_senderrandomness = rustfield!(MsMembershipProof::sender_randomness);
        let rustfield_aoclleafindex = rustfield!(MsMembershipProof::aocl_leaf_index);
        let rustfield_receiverpreimage = rustfield!(MsMembershipProof::receiver_preimage);
        let rustfield_authpathaocl = rustfield!(WitnessMemory::auth_path_aocl);
        let rustfield_authenticationpath = rustfield!(WitnessMemory::authentication_path);
        let rustfield_utxo = rustfield!(WitnessMemory::utxo);
        let rustfield_utxodigest = rustfield!(WitnessMemory::utxo_digest);
        // let rustfield_lockscripthash = rustfield!(Utxo::lock_script_hash);
        let rustfield_coins = rustfield!(Utxo::coins);
        // let rustfield_typescripthash = rustfield!(Coin::type_script_hash);
        // let rustfield_state = rustfield!(Coin::state);
        let audit_preloaded_data = library.import(Box::new(
            tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity::<
                // MemoryPreload
                crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof,
            >::default(),
        )); // TODO
        let payload = triton_asm! {
            push {tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // *w
            {&WitnessMemory::get_field("aocl")}
            // *aocl

            // prepare the value for '7.'
            dup 0
            {&rustfield_peaks}
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

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *w
            {&rustfield_utxo}
            // *aocl *aocl_peaks [receiver_digest] [sender_randomness] *utxo
        };

        let main = triton_asm! {
            /* '2.' adapted from <removal_records_integrity.rs>
            ============== */
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

            /* pasted '6.' from <removal_records_integrity.rs>
            ============== */
            call {lib_ms_commit}
            // *aocl *aocl_peaks [canonical_commitment]

            /* pasted '7.' from <removal_records_integrity.rs>
            ============== */
            /* 7. */
            dup 6 {&rustfield_leafcount}
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
            {&rustfield_authpathaocl}
            {&rustfield_authenticationpath}
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

            /* pasted '8.' from <removal_records_integrity.rs>
            ============== */
            /* 8. */
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&rustfield_membershipproof}
            {&rustfield_aoclleafindex}
            read_mem {u64_stack_size}
            pop 1
            // *aocl [aocl_leaf_index]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&rustfield_membershipproof}
            {&rustfield_receiverpreimage}
            read_mem {Digest::LEN}
            pop 1
            // *aocl [aocl_leaf_index] [receiver_preimage]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&rustfield_membershipproof}
            {&rustfield_senderrandomness}
            read_mem {Digest::LEN}
            pop 1
            // *aocl [aocl_leaf_index] [receiver_preimage] [sender_randomness]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            {&rustfield_utxodigest}
            read_mem {Digest::LEN}
            pop 1
            // *aocl [aocl_leaf_index] [receiver_preimage] [sender_randomness] [utxo_hash]

            call {lib_compute_absolute_indices}
            // *aocl *absolute_indices

            call {lib_hash_absolute_indices}
            pop 1
            // *aocl [computed_bloom_indices]
            write_io 5
            // *aocl

            /* finish of the things from the RR integrity file
            ____________________________ */

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
            {&rustfield_coins}
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
            // num_coins num_coins *eof amount
            // _______________________________
            // left-over from an approach when I didn't get to the useful snippet
            // push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // {&rustfield_utxo}
            // {&rustfield_lockscripthash}
            // read_mem 5
            // pop 1
            // // [lock_script_digest]
            // dup 4
            // dup 4
            // dup 4
            // dup 4
            // dup 4
            // // [lock_script_digest] [lock_script_digest]
            // write_io 5
            // // [lock_script_digest]
            // push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // {&WitnessMemory::get_field("lock_preimage")}
            // // [lock_script_digest] *lock_preimage
            // push 0
            // push 0
            // push 0
            // push 0
            // push 0
            // // [lock_script_digest] *lock_preimage [ALL_ZERO]
            // // asked @j_f_s
            // addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
            // // [lock_script_digest] [ALL_ZERO] [lock_script_preimage]
            // hash assert_vector

            // {&Coin::get_field("type_script_hash")}
            // // SI *ts
            // addi {Digest::LEN - 1} read_mem {Digest::LEN} addi 1
            // // SI ts_digest *ts

            // // 5) push the digest of NativeCurrency (push {my_digest[0]} push my_digest[1] …)
            // push {npt_typesc_digest[4]}
            // push {npt_typesc_digest[3]}
            // push {npt_typesc_digest[2]}
            // push {npt_typesc_digest[1]}
            // push {npt_typesc_digest[0]}
            // {&DataType::Digest.compare()}
            // // _ is_NPT


            // next:

            // output_reserve:
            //     // _ *coin
            //     {&rustfield_state}
            //     read_mem 4 pop 1
            //     write_io 4
            //     halt
        };

        let imports = library.all_imports();
        let code = triton_asm!(
            {&payload}
            {&main}
            {&imports}
        );
        (library, code)
    }

    fn hash(&self) -> tasm_lib::prelude::Digest {
        todo!()
    }
}
