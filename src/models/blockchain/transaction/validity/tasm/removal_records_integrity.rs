use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::prelude::{triton_vm, twenty_first};
use crate::util_types::mutator_set::chunk_dictionary::ChunkDictionary;
use crate::util_types::mutator_set::get_swbf_indices;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;

use crate::models::blockchain::transaction::utxo::Utxo;
use strum::EnumCount;
use triton_vm::instruction::LabelledInstruction;
use triton_vm::prelude::BFieldElement;
use twenty_first::{
    math::tip5::Digest,
    util_types::{
        algebraic_hasher::AlgebraicHasher,
        mmr::{mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
    },
};

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::validity::removal_records_integrity::{
    RemovalRecordsIntegrity, RemovalRecordsIntegrityWitness,
};

// impl CompiledProgram for RemovalRecordsIntegrity {
//     fn rust_shadow(
//         public_input: &PublicInput,
//         nondeterminism: &NonDeterminism,
//     ) -> anyhow::Result<Vec<BFieldElement>> {
//         let hash_of_kernel = *Digest::decode(
//             &public_input
//                 .individual_tokens
//                 .iter()
//                 .copied()
//                 .take(DIGEST_LENGTH)
//                 .rev()
//                 .collect_vec(),
//         )
//         .expect("Could not decode public input in Removal Records Integrity :: verify_raw");

//         // 1. read and process witness data
//         let removal_record_integrity_witness = *RemovalRecordsIntegrityWitness::decode_from_memory(
//             &nondeterminism.ram,
//             FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
//         )
//         .unwrap();

//         println!(
//             "first element of witness: {}",
//             removal_record_integrity_witness.encode()[0]
//         );
//         println!(
//             "first element of kernel: {}",
//             removal_record_integrity_witness.kernel.encode()[0]
//         );

//         // 2. assert that the kernel from the witness matches the hash in the public input
//         // now we can trust all data in kernel
//         assert_eq!(
//             hash_of_kernel,
//             removal_record_integrity_witness.kernel.mast_hash(),
//             "hash of kernel ({})\nwitness kernel ({})",
//             hash_of_kernel,
//             removal_record_integrity_witness.kernel.mast_hash()
//         );

//         // 3. assert that the mutator set's MMRs in the witness match the kernel
//         // now we can trust all data in these MMRs as well
//         let mutator_set_hash = Hash::hash_pair(
//             Hash::hash_pair(
//                 removal_record_integrity_witness.aocl.bag_peaks(),
//                 removal_record_integrity_witness.swbfi.bag_peaks(),
//             ),
//             Hash::hash_pair(
//                 removal_record_integrity_witness.swbfa_hash,
//                 Digest::default(),
//             ),
//         );
//         assert_eq!(
//             removal_record_integrity_witness.kernel.mutator_set_hash,
//             mutator_set_hash
//         );

//         // 4. derive index sets from inputs and match them against those listed in the kernel
//         // How do we trust input UTXOs?
//         // Because they generate removal records, and we can match
//         // those against the removal records that are listed in the
//         // kernel.
//         let items = removal_record_integrity_witness
//             .input_utxos
//             .utxos
//             .iter()
//             .map(Hash::hash)
//             .collect_vec();

//         // test that removal records listed in kernel match those derived from input utxos
//         let digests_of_derived_index_lists = items
//             .iter()
//             .zip(removal_record_integrity_witness.membership_proofs.iter())
//             .map(|(&item, msmp)| {
//                 AbsoluteIndexSet::new(&get_swbf_indices(
//                     item,
//                     msmp.sender_randomness,
//                     msmp.receiver_preimage,
//                     msmp.auth_path_aocl.leaf_index,
//                 ))
//                 .encode()
//             })
//             .map(|x| Hash::hash_varlen(&x))
//             .collect::<HashSet<_>>();
//         let digests_of_claimed_index_lists = removal_record_integrity_witness
//             .kernel
//             .inputs
//             .iter()
//             .map(|input| input.absolute_indices.encode())
//             .map(|x| Hash::hash_varlen(&x))
//             .collect::<HashSet<_>>();
//         assert_eq!(
//             digests_of_derived_index_lists,
//             digests_of_claimed_index_lists
//         );

//         // 5. verify that all input utxos (mutator set items) live in the AOCL
//         assert!(items
//             .into_iter()
//             .zip(removal_record_integrity_witness.membership_proofs.iter())
//             .map(|(item, msmp)| {
//                 (
//                     commit(
//                         item,
//                         msmp.sender_randomness,
//                         msmp.receiver_preimage.hash::<Hash>(),
//                     ),
//                     &msmp.auth_path_aocl,
//                 )
//             })
//             .all(|(cc, mp)| {
//                 mp.verify(
//                     &removal_record_integrity_witness.aocl.get_peaks(),
//                     cc.canonical_commitment,
//                     removal_record_integrity_witness.aocl.count_leaves(),
//                 )
//             }));

//         Ok(vec![])
//     }

//     fn code() -> (Vec<LabelledInstruction>, Library) {
//         let mut library = Library::new();
//         let transaction_kernel_mast_hash = library.import(Box::new(TransactionKernelMastHash));
//         let bag_peaks = library.import(Box::new(BagPeaks));
//         let read_digest = library.import(Box::new(PushRamToStack {
//             data_type: DataType::Digest,
//         }));
//         let map_hash_utxo = library.import(Box::new(Map {
//             f: InnerFunction::BasicSnippet(Box::new(HashUtxo)),
//         }));
//         let get_pointer_list = library.import(Box::new(GetPointerList {}));
//         let zip_digest_with_void_pointer = library.import(Box::new(Zip {
//             left_type: DataType::Digest,
//             right_type: DataType::VoidPointer,
//         }));
//         let map_compute_indices = library.import(Box::new(Map {
//             f: InnerFunction::BasicSnippet(Box::new(ComputeIndices)),
//         }));
//         let map_hash_index_list = library.import(Box::new(Map {
//             f: InnerFunction::BasicSnippet(Box::new(HashIndexList)),
//         }));
//         let map_hash_removal_record_indices = library.import(Box::new(Map {
//             f: InnerFunction::BasicSnippet(Box::new(HashRemovalRecordIndices)),
//         }));
//         let multiset_equality = library.import(Box::new(MultisetEquality));

//         let map_compute_canonical_commitment = library.import(Box::new(Map {
//             f: InnerFunction::BasicSnippet(Box::new(ComputeCanonicalCommitment)),
//         }));
//         let all_verify_aocl_membership = library.import(Box::new(All {
//             f: InnerFunction::BasicSnippet(Box::new(VerifyAoclMembership)),
//         }));
//         let _compute_indices = library.import(Box::new(ComputeIndices));

//         // field getters
//         let witness_to_kernel = tasm_lib::field!(RemovalRecordsIntegrityWitness::kernel);
//         let witness_to_swbfa_hash = tasm_lib::field!(RemovalRecordsIntegrityWitness::swbfa_hash);
//         let witness_to_swbfi = tasm_lib::field!(RemovalRecordsIntegrityWitness::swbfi);
//         type MmraH = MmrAccumulator<Hash>;
//         let swbfi_to_peaks = tasm_lib::field!(MmraH::peaks);
//         let witness_to_aocl = tasm_lib::field!(RemovalRecordsIntegrityWitness::aocl);
//         let kernel_to_mutator_set_hash = tasm_lib::field!(TransactionKernel::mutator_set_hash);
//         let witness_to_utxos = tasm_lib::field!(RemovalRecordsIntegrityWitness::input_utxos);
//         let witness_to_mps = tasm_lib::field!(RemovalRecordsIntegrityWitness::membership_proofs);
//         let kernel_to_inputs = tasm_lib::field!(TransactionKernel::inputs);
//         let aocl_to_leaf_count = tasm_lib::field!(MmraH::leaf_count);
//         let aocl_to_peaks = tasm_lib::field!(MmraH::peaks);

//         let code = triton_asm! {

//         // 1. Witness was already loaded into memory, just point to it
//         push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS} // _ *witness

//         // 2. assert that witness kernel hash == public input
//         dup 0                               // _ *witness *witness

//         {&witness_to_kernel}                // _ *witness *kernel
//         dup 0                               // _ *witness *kernel *kernel
//         call {transaction_kernel_mast_hash} // _ *witness *kernel [witness_kernel_digest]
//         read_io 5                           // _ *witness *kernel [witness_kernel_digest] [input_kernel_digest]
//         assert_vector                       // _ *witness *kernel [witness_kernel_digest]
//         pop 5                               // _ *witness *kernel

//         // 3. assert that witness mutator set MMRs match those in kernel

//         push 0 push 0 push 0 push 0 push 0 // _ *witness *kernel 0 0 0 0 0
//         dup 6                              // _ *witness *kernel 0^5 *witness
//         {&witness_to_swbfa_hash}           // _ *witness *kernel 0^5 *witness_swbfa_hash
//         call {read_digest}

//         hash // _ *witness *kernel [H(H(swbfaw)||0^5)]

//         dup 6 // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness

//         {&witness_to_swbfi} // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi
//         {&swbfi_to_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi_peaks
//         call {bag_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash]

//         dup 11 // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness
//         {&witness_to_aocl} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl
//         {&aocl_to_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl_peaks
//         call {bag_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] [witness_aocl_hash]

//         hash // _ *witness *kernel [H(H(swbfaw)||0^5)] [H(aocl||swbfi)]

//         hash // _ *witness *kernel [Hw]

//         dup 5 // _ *witness *kernel [Hw] *kernel
//         {&kernel_to_mutator_set_hash} // _ *witness *kernel [Hw] *kernel_msh
//         call {read_digest}
//         // _ *witness *kernel [Hw] [Hk]

//         assert_vector
//         pop 5
//         // _ *witness *kernel

//         // 4. derive index sets and match them against kernel
//         dup 1 // _ *witness *kernel *witness
//         {&witness_to_utxos} // _ *witness *kernel *utxos
//         call {get_pointer_list} // _ *witness *kernel *[*utxo]
//         call {map_hash_utxo} // _ *witness *kernel *[item]

//         dup 2 // _ *witness *kernel *[item] *witness
//         {&witness_to_mps} //_ *witness *kernel *[items] *mps
//         call {get_pointer_list} //_ *witness *kernel *[item] *[*mp]
//         call {zip_digest_with_void_pointer} // _ *witness *kernel *[(item, *mp)]

//         // store for later use
//         dup 0  // _ *witness *kernel *[(item, *mp)] *[(item, *mp)]
//         swap 3 // _  *[(item, *mp)] *kernel *[(item, *mp)] *witness
//         swap 2 // _  *[(item, *mp)] *witness *[(item, *mp)] *kernel
//         swap 1 // _  *[(item, *mp)] *witness *kernel *[(item, *mp)]

//         call {map_compute_indices} // _  *[(item, *mp)] *witness *kernel *[*[index]]

//         call {map_hash_index_list} // _  *[(item, *mp)] *witness *kernel *[index_list_hash]

//         dup 1 // _  *[(item, *mp)] *witness *kernel *[index_list_hash] *kernel
//         {&kernel_to_inputs} // _  *[(item, *mp)] *witness *kernel *[index_list_hash] *kernel_inputs
//         call {get_pointer_list} // _  *[(item, *mp)] *witness *kernel *[index_list_hash] *[*tx_input]
//         call {map_hash_removal_record_indices} // _  *[(item, *mp)] *witness *kernel *[witness_index_list_hash] *[kernel_index_list_hash]

//         call {multiset_equality} // _  *[(item, *mp)] *witness *kernel witness_inputs==kernel_inputs

//         assert // _  *[(item, *mp)] *witness *kernel

//         // 5. verify that all items' commitments live in the aocl
//         // get aocl leaf count
//         dup 1 // _ *[(item, *mp)] *witness *kernel *witness
//         {&witness_to_aocl}              // _ *[(item, *mp)] *witness *kernel *aocl
//         dup 0                   // _ *[(item, *mp)] *witness *kernel *aocl *aocl
//         {&aocl_to_leaf_count} // _ *[(item, *mp)] *witness *kernel *aocl *leaf_count
//         push 1 add // _ *[(item, *mp)] *witness *kernel *aocl *leaf_count_last_word
//         read_mem 2
//         pop 1      // _ *[(item, *mp)] *witness *kernel *aocl leaf_count_hi leaf_count_lo

//         dup 2                   // _ *[(item, *mp)] *witness *kernel *aocl leaf_count_hi leaf_count_lo *aocl
//         {&aocl_to_peaks}              // _ *[(item, *mp)] *witness *kernel *aocl leaf_count_hi leaf_count_lo *peaks

//         swap 6 // _ *peaks *witness *kernel *aocl leaf_count_hi leaf_count_lo *[(item, *mp)]
//         swap 2 // _ *peaks *witness *kernel *aocl *[(item, *mp)] leaf_count_lo leaf_count_hi
//         swap 5 // _ *peaks leaf_count_hi *kernel *aocl *[(item, *mp)] leaf_count_lo *witness
//         pop  1 // _ *peaks leaf_count_hi *kernel *aocl *[(item, *mp)] leaf_count_lo
//         swap 3 // _ *peaks leaf_count_hi leaf_count_lo *aocl *[(item, *mp)] *kernel
//         pop  1 // _ *peaks leaf_count_hi leaf_count_lo *aocl *[(item, *mp)]
//         swap 1 // _ *peaks leaf_count_hi leaf_count_lo *[(item, *mp)] *aocl
//         pop  1 // _ *peaks leaf_count_hi leaf_count_lo *[(item, *mp)]

//         call {map_compute_canonical_commitment}
//                // _ *peaks leaf_count_hi leaf_count_lo *[(cc, *mp)]

//         call {all_verify_aocl_membership}
//                // _ *peaks leaf_count_hi leaf_count_lo all_live_in_aocl

//         assert

//         halt
//         };

//         (code, library)
//     }

//     fn crash_conditions() -> Vec<String> {
//         vec![
//             "the kernel from the witness does not match the hash in the public input".to_string(),
//             "the mutator set's MMRs in the witness do not match the kernel".to_string(),
//             "removal records listed in kernel do not match those derived from input utxos"
//                 .to_string(),
//             "not all input utxos (mutator set items) live in the AOCL".to_string(),
//         ]
//     }
// }

impl ConsensusProgram for RemovalRecordsIntegrity {
    fn source(&self) {
        let txk_digest: Digest = tasmlib::tasm_io_read_stdin___digest();

        let start_address: BFieldElement = BFieldElement::new(0);
        let rriw: RemovalRecordsIntegrityWitness = tasmlib::decode_from_memory(start_address);

        // divine in the salted input UTXOs with hash
        let salted_input_utxos: &SaltedUtxos = &rriw.input_utxos;
        let input_utxos: &[Utxo] = &salted_input_utxos.utxos;

        // divine in the mutator set accumulator
        let aocl: MmrAccumulator<Hash> = rriw.aocl;
        let swbfi: MmrAccumulator<Hash> = rriw.swbfi;

        // authenticate the mutator set accumulator against the txk mast hash
        let aocl_mmr_bagged: Digest = aocl.bag_peaks();
        let inactive_swbf_bagged: Digest = swbfi.bag_peaks();
        let active_swbf_bagged: Digest = rriw.swbfa_hash;
        let default = Digest::default();
        let msah: Digest = Hash::hash_pair(
            Hash::hash_pair(aocl_mmr_bagged, inactive_swbf_bagged),
            Hash::hash_pair(active_swbf_bagged, default),
        );
        tasmlib::tasm_hashing_merkle_verify(
            txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&msah),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // iterate over all input UTXOs
        let mut all_aocl_indices: Vec<u64> = Vec::new();
        let mut input_index: usize = 0;
        while input_index < input_utxos.len() {
            let removal_record: &RemovalRecord = &rriw.kernel.inputs[input_index];

            // calculate absolute index set
            let utxo: &Utxo = &input_utxos[input_index];
            let msmp: &MsMembershipProof = &rriw.membership_proofs[input_index];
            let aocl_leaf_index = msmp.auth_path_aocl.leaf_index;
            let index_set = get_swbf_indices(
                Hash::hash(utxo),
                msmp.sender_randomness,
                msmp.receiver_preimage,
                aocl_leaf_index,
            );

            assert_eq!(index_set, removal_record.absolute_indices.to_array());

            // ensure the aocl leaf index is unique
            let mut j: usize = 0;
            while j < all_aocl_indices.len() {
                assert_ne!(all_aocl_indices[j], aocl_leaf_index);
                j += 1;
            }
            all_aocl_indices.push(aocl_leaf_index);

            // derive inactive chunk indices from absolute index set
            let mut inactive_chunk_indices: Vec<u64> = Vec::new();
            let mut j = 0;
            while j < index_set.len() {
                let absolute_index = index_set[j];
                let chunk_index: u64 = (absolute_index / (CHUNK_SIZE as u128)) as u64;
                if chunk_index < swbfi.count_leaves()
                    && !inactive_chunk_indices.contains(&chunk_index)
                {
                    inactive_chunk_indices.push(chunk_index);
                }
                j += 1;
            }

            // authenticate chunks in dictionary
            let target_chunks: &ChunkDictionary = &removal_record.target_chunks;
            let mut visited_chunk_indices: Vec<u64> = vec![];
            for (chunk_index, (mmrmp, chunk)) in &target_chunks.dictionary {
                assert!(mmrmp.verify(&swbfi.get_peaks(), Hash::hash(chunk), swbfi.count_leaves()));
                visited_chunk_indices.push(*chunk_index);
            }

            // equate chunk index lists as sets
            inactive_chunk_indices.sort();
            visited_chunk_indices.sort();
            assert_eq!(inactive_chunk_indices, visited_chunk_indices);

            input_index += 1;
        }

        // authenticate computed removal records against txk mast hash
        let removal_records_digest = Hash::hash(&rriw.kernel.inputs);
        tasmlib::tasm_hashing_merkle_verify(
            txk_digest,
            TransactionKernelField::InputUtxos as u32,
            removal_records_digest,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // compute and output hash of salted input UTXOs
        let hash_of_inputs = Hash::hash(salted_input_utxos);
        tasmlib::tasm_io_write_to_stdout___digest(hash_of_inputs);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}

#[cfg(test)]
mod tests {

    use crate::models::{
        blockchain::transaction::primitive_witness::PrimitiveWitness,
        proof_abstractions::SecretWitness,
    };

    use super::*;
    use proptest::{
        arbitrary::Arbitrary, prop_assert, strategy::Strategy, test_runner::TestRunner,
    };
    use test_strategy::proptest;

    #[proptest(cases = 5)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
    ) {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::new(&primitive_witness);
        let result = RemovalRecordsIntegrity {}.run(
            &removal_records_integrity_witness.standard_input(),
            removal_records_integrity_witness.nondeterminism(),
        );
        prop_assert!(result.is_ok());
    }

    #[test]
    fn derived_witness_generates_accepting_program_deterministic() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::new(&primitive_witness);
        let result = RemovalRecordsIntegrity {}.run(
            &removal_records_integrity_witness.standard_input(),
            removal_records_integrity_witness.nondeterminism(),
        );
        assert!(result.is_ok());
    }

    // #[test]
    // fn test_validation_logic() {
    //     let mut rng = thread_rng();
    //     let tx_kernel = &pseudorandom_transaction_kernel(rng.gen(), 2, 2, 2);
    //     let prrriw =
    //         pseudorandom_removal_record_integrity_witness(rng.gen());
    //     let input_utxos = prrriw.input_utxos;
    //     let input_lock_scripts = prrriw.input_utxos.iter().map(|x| x.)

    //     // pub struct PrimitiveWitness {
    //     // pub input_utxos: Vec<Utxo>,
    //     // pub input_lock_scripts: Vec<LockScript>,
    //     // pub lock_script_witnesses: Vec<Vec<BFieldElement>>,
    //     // pub input_membership_proofs: Vec<MsMembershipProof<Hash>>,
    //     // pub output_utxos: Vec<Utxo>,
    //     // pub pubscripts: Vec<PubScript>,
    //     // pub mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    //     // }

    //     // let primitive_witness = pseudorandom_pri
    //     let rriw = RemovalRecordsIntegrity::new_from_witness(primitive_witness, tx_kernel);
    // }

    // #[test]
    // fn test_graceful_halt() {
    //     let mut seed = [0u8; 32];
    //     seed[0] = 0xa0;
    //     seed[1] = 0xf1;
    //     let mut rng: StdRng = SeedableRng::from_seed(seed);
    //     let removal_record_integrity_witness =
    //         pseudorandom_removal_record_integrity_witness(rng.gen());

    //     let stdin: Vec<BFieldElement> = removal_record_integrity_witness
    //         .kernel
    //         .mast_hash()
    //         .reversed()
    //         .values()
    //         .to_vec();

    //     let mut memory = HashMap::default();
    //     encode_to_memory(
    //         &mut memory,
    //         FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
    //         removal_record_integrity_witness,
    //     );
    //     let nondeterminism = NonDeterminism::new(vec![]).with_ram(memory);
    //     // let program = RemovalRecordsIntegrity::program();
    //     let program = todo!();
    //     let run_res = program.run(PublicInput::new(stdin.clone()), nondeterminism.clone());
    //     match run_res {
    //         Ok(_) => println!("Run successful."),
    //         Err(err) => panic!("Failed:\n last state was:\n{err}"),
    //     };

    //     if std::env::var("DYING_TO_PROVE").is_ok() {
    //         let claim: Claim = Claim {
    //             program_digest: program.hash::<Hash>(),
    //             input: stdin,
    //             output: vec![],
    //         };
    //         let maybe_proof = triton_vm::prove(Stark::default(), &claim, &program, nondeterminism);
    //         assert!(maybe_proof.is_ok());

    //         assert!(triton_vm::verify(
    //             Stark::default(),
    //             &claim,
    //             &maybe_proof.unwrap()
    //         ));
    //     }
    // }

    // #[test]
    // fn tasm_matches_rust() {
    //     let mut seed = [0u8; 32];
    //     seed[0] = 0xa0;
    //     seed[1] = 0xf1;
    //     let mut rng: StdRng = SeedableRng::from_seed(seed);
    //     let removal_record_integrity_witness =
    //         pseudorandom_removal_record_integrity_witness(rng.gen());
    //     let mut memory = HashMap::default();
    //     encode_to_memory(
    //         &mut memory,
    //         FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
    //         removal_record_integrity_witness.clone(),
    //     );
    //     let nondeterminism = NonDeterminism::new(vec![]).with_ram(memory);
    //     let kernel_hash = removal_record_integrity_witness
    //         .kernel
    //         .mast_hash()
    //         .reversed()
    //         .values();
    //     let public_input = PublicInput::new(kernel_hash.to_vec());

    //     test_rust_shadow::<RemovalRecordsIntegrity>(&public_input, &nondeterminism);
    // }
}

#[cfg(test)]
mod bench {
    // use std::collections::HashMap;

    // use crate::{models::proof_abstractions::mast_hash::MastHash, prelude::triton_vm};

    // use crate::tests::shared::pseudorandom_removal_record_integrity_witness;
    // use rand::{rngs::StdRng, Rng, SeedableRng};
    // use tasm_lib::{
    //     memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS},
    //     snippet_bencher::BenchmarkCase,
    // };
    // use triton_vm::prelude::{BFieldElement, NonDeterminism, PublicInput};

    // use super::RemovalRecordsIntegrity;
    // use tasm_lib::traits::compiled_program::bench_and_profile_program;

    // #[test]
    // fn benchmark() {
    //     let mut seed = [0u8; 32];
    //     seed[0] = 0xa7;
    //     seed[1] = 0xf7;
    //     let mut rng: StdRng = SeedableRng::from_seed(seed);
    //     let removal_record_integrity_witness =
    //         pseudorandom_removal_record_integrity_witness(rng.gen());

    //     let stdin: Vec<BFieldElement> = removal_record_integrity_witness
    //         .kernel
    //         .mast_hash()
    //         .reversed()
    //         .values()
    //         .to_vec();
    //     let public_input = PublicInput::new(stdin);
    //     let mut memory = HashMap::default();
    //     encode_to_memory(
    //         &mut memory,
    //         FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
    //         removal_record_integrity_witness,
    //     );
    //     let nondeterminism = NonDeterminism::default().with_ram(memory);

    //     bench_and_profile_program::<RemovalRecordsIntegrity>(
    //         "tasm_neptune_transaction_removal_records_integrity",
    //         BenchmarkCase::CommonCase,
    //         &public_input,
    //         &nondeterminism,
    //     );
    // }
}
