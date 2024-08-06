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
//                 .take(Digest::LEN)
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
//                     msmp.aocl_leaf_index,
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
//                         msmp.receiver_preimage.hash(),
//                     ),
//                     &msmp.auth_path_aocl,
//                 )
//             })
//             .all(|(cc, mp)| {
//                 mp.verify(
//                     &removal_record_integrity_witness.aocl.peaks(),
//                     cc.canonical_commitment,
//                     removal_record_integrity_witness.aocl.num_leafs(),
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
//         type MmraH = MmrAccumulator;
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
