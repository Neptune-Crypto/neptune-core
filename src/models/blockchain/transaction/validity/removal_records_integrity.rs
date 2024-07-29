use arbitrary::Arbitrary;
use field_count::FieldCount;
use get_size::GetSize;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::collections::HashMap;
use strum::EnumCount;
use tasm_lib::arithmetic::u128::shift_right_static_u128::ShiftRightStaticU128;
use tasm_lib::arithmetic::u64::lt_u64::LtU64ConsumeArgs;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::list::contains::Contains;
use tasm_lib::list::multiset_equality_u64s::MultisetEqualityU64s;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::bag_peaks::BagPeaks;
use tasm_lib::mmr::verify_from_memory::MmrVerifyFromMemory;
use tasm_lib::mmr::verify_from_secret_in_leaf_index_on_stack::MmrVerifyFromSecretInLeafIndexOnStack;
use tasm_lib::neptune::mutator_set;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::Digest;
use triton_vm::instruction::LabelledInstruction;
use triton_vm::prelude::BFieldElement;
use triton_vm::prelude::NonDeterminism;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::validity::tasm::compute_indices::ComputeIndices;
use crate::models::blockchain::transaction::PrimitiveWitness;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::SecretWitness;
use crate::prelude::triton_vm;
use crate::prelude::twenty_first;
use crate::triton_vm::triton_asm;
use crate::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::chunk_dictionary::ChunkDictionary;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::get_swbf_indices;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;
use crate::util_types::mutator_set::shared::NUM_TRIALS;

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    GetSize,
    BFieldCodec,
    FieldCount,
    TasmObject,
)]
pub struct RemovalRecordsIntegrityWitness {
    input_utxos: SaltedUtxos,
    membership_proofs: Vec<MsMembershipProof>,
    aocl: MmrAccumulator<Hash>,
    swbfi: MmrAccumulator<Hash>,
    swbfa_hash: Digest,
    removal_records: Vec<RemovalRecord>,
    mast_path_mutator_set: Vec<Digest>,
    mast_path_inputs: Vec<Digest>,
    mast_root: Digest,
}

impl From<&PrimitiveWitness> for RemovalRecordsIntegrityWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            input_utxos: primitive_witness.input_utxos.clone(),
            membership_proofs: primitive_witness.input_membership_proofs.clone(),
            removal_records: primitive_witness.kernel.inputs.clone(),
            aocl: primitive_witness.mutator_set_accumulator.aocl.clone(),
            swbfi: primitive_witness
                .mutator_set_accumulator
                .swbf_inactive
                .clone(),
            swbfa_hash: Hash::hash(&primitive_witness.mutator_set_accumulator.swbf_active),
            mast_path_mutator_set: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            mast_path_inputs: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::Inputs),
            mast_root: primitive_witness.kernel.mast_hash(),
        }
    }
}

impl SecretWitness for RemovalRecordsIntegrityWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );

        // set digests
        let digests = [
            self.mast_path_mutator_set.clone(),
            self.mast_path_inputs.clone(),
            self.membership_proofs
                .iter()
                .flat_map(|msmp| msmp.auth_path_aocl.authentication_path.clone())
                .collect_vec(),
        ]
        .concat();

        NonDeterminism::default()
            .with_ram(memory)
            .with_digests(digests)
    }

    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.mast_root.reversed().values().to_vec())
    }

    fn output(&self) -> Vec<BFieldElement> {
        Hash::hash(&self.input_utxos).values().to_vec()
    }

    fn program(&self) -> triton_vm::prelude::Program {
        RemovalRecordsIntegrity.program()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount, BFieldCodec)]
pub struct RemovalRecordsIntegrity;

impl RemovalRecordsIntegrityWitness {
    pub fn pseudorandom_merkle_root_with_authentication_paths(
        seed: [u8; 32],
        tree_height: usize,
        leafs_and_indices: &[(Digest, u64)],
    ) -> (Digest, Vec<Vec<Digest>>) {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut nodes: HashMap<u64, Digest> = HashMap::new();

        // populate nodes dictionary with leafs
        for (leaf, index) in leafs_and_indices.iter() {
            nodes.insert(*index, *leaf);
        }

        // walk up tree layer by layer
        // when we need nodes not already present, sample at random
        let mut depth = tree_height + 1;
        while depth > 0 {
            let mut working_indices = nodes
                .keys()
                .copied()
                .filter(|i| {
                    (*i as u128) < (1u128 << (depth)) && (*i as u128) >= (1u128 << (depth - 1))
                })
                .collect_vec();
            working_indices.sort();
            working_indices.dedup();
            for wi in working_indices {
                let wi_odd = wi | 1;
                nodes.entry(wi_odd).or_insert_with(|| rng.gen::<Digest>());
                let wi_even = wi_odd ^ 1;
                nodes.entry(wi_even).or_insert_with(|| rng.gen::<Digest>());
                let hash = Hash::hash_pair(nodes[&wi_even], nodes[&wi_odd]);
                nodes.insert(wi >> 1, hash);
            }
            depth -= 1;
        }

        // read out root
        let root = *nodes.get(&1).unwrap_or(&rng.gen());

        // read out paths
        let paths = leafs_and_indices
            .iter()
            .map(|(_d, i)| {
                (0..tree_height)
                    .map(|j| *nodes.get(&((*i >> j) ^ 1)).unwrap())
                    .collect_vec()
            })
            .collect_vec();

        (root, paths)
    }

    pub fn pseudorandom_mmra_with_mps(
        seed: [u8; 32],
        leafs: &[Digest],
    ) -> (MmrAccumulator<Hash>, Vec<(u64, MmrMembershipProof<Hash>)>) {
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        // sample size of MMR
        let mut leaf_count = rng.next_u64();
        while leaf_count < leafs.len() as u64 {
            leaf_count = rng.next_u64();
        }
        let num_peaks = leaf_count.count_ones();

        // sample mmr leaf indices and calculate matching derived indices
        let leaf_indices = leafs
            .iter()
            .enumerate()
            .map(|(original_index, _leaf)| (original_index, rng.next_u64() % leaf_count))
            .map(|(original_index, mmr_index)| {
                let (mt_index, peak_index) =
                    leaf_index_to_mt_index_and_peak_index(mmr_index, leaf_count);
                (original_index, mmr_index, mt_index, peak_index)
            })
            .collect_vec();
        let leafs_and_indices = leafs.iter().copied().zip(leaf_indices).collect_vec();

        // iterate over all trees
        let mut peaks = vec![];
        let dummy_mp = MmrMembershipProof::new(vec![]);
        let mut mps = (0..leafs.len())
            .map(|i| (i as u64, dummy_mp.clone()))
            .collect_vec();
        for tree in 0..num_peaks {
            // select all leafs and merkle tree indices for this tree
            let leafs_and_mt_indices = leafs_and_indices
                .iter()
                .copied()
                .filter(
                    |(_leaf, (_original_index, _mmr_index, _mt_index, peak_index))| {
                        *peak_index == tree
                    },
                )
                .map(
                    |(leaf, (original_index, _mmr_index, mt_index, _peak_index))| {
                        (leaf, mt_index, original_index)
                    },
                )
                .collect_vec();
            if leafs_and_mt_indices.is_empty() {
                peaks.push(rng.gen());
                continue;
            }

            // generate root and authentication paths
            let tree_height = (*leafs_and_mt_indices.first().map(|(_l, i, _o)| i).unwrap() as u128)
                .ilog2() as usize;
            let (root, authentication_paths) =
                Self::pseudorandom_merkle_root_with_authentication_paths(
                    rng.gen(),
                    tree_height,
                    &leafs_and_mt_indices
                        .iter()
                        .map(|(l, i, _o)| (*l, *i))
                        .collect_vec(),
                );

            // sanity check
            // for ((leaf, mt_index, _original_index), auth_path) in
            //     leafs_and_mt_indices.iter().zip(authentication_paths.iter())
            // {
            //     assert!(merkle_verify_tester_helper::<H>(
            //         root, *mt_index, auth_path, *leaf
            //     ));
            // }

            // update peaks list
            peaks.push(root);

            // generate membership proof objects
            let membership_proofs = leafs_and_indices
                .iter()
                .copied()
                .filter(
                    |(_leaf, (_original_index, _mmr_index, _mt_index, peak_index))| {
                        *peak_index == tree
                    },
                )
                .zip(authentication_paths.into_iter())
                .map(
                    |(
                        (_leaf, (_original_index, mmr_index, _mt_index, _peak_index)),
                        authentication_path,
                    )| {
                        (
                            mmr_index,
                            MmrMembershipProof::<Hash>::new(authentication_path),
                        )
                    },
                )
                .collect_vec();

            // sanity check: test if membership proofs agree with peaks list (up until now)
            let dummy_remainder: Vec<Digest> = (peaks.len()..num_peaks as usize)
                .map(|_| rng.gen())
                .collect_vec();
            let dummy_peaks = [peaks.clone(), dummy_remainder].concat();
            for (&(leaf, _mt_index, _original_index), (mmr_leaf_index, mp)) in
                leafs_and_mt_indices.iter().zip(membership_proofs.iter())
            {
                assert!(mp.verify(*mmr_leaf_index, leaf, &dummy_peaks, leaf_count));
            }

            // collect membership proofs in vector, with indices matching those of the supplied leafs
            for ((_leaf, _mt_index, original_index), (mmr_leaf_index, mp)) in
                leafs_and_mt_indices.iter().zip(membership_proofs.iter())
            {
                mps[*original_index] = (*mmr_leaf_index, mp.clone());
            }
        }

        let mmra = MmrAccumulator::<Hash>::init(peaks, leaf_count);

        // sanity check
        for (&leaf, (mmr_leaf_index, mp)) in leafs.iter().zip(mps.iter()) {
            assert!(mp.verify(*mmr_leaf_index, leaf, &mmra.peaks(), mmra.num_leafs()));
        }

        (mmra, mps)
    }
}

impl ConsensusProgram for RemovalRecordsIntegrity {
    fn source(&self) {
        let txk_digest: Digest = tasmlib::tasm_io_read_stdin___digest();

        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
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
        let left = Hash::hash_pair(aocl_mmr_bagged, inactive_swbf_bagged);
        let active_swbf_digest: Digest = rriw.swbfa_hash;
        let default = Digest::default();
        let right = Hash::hash_pair(active_swbf_digest, default);
        let msah: Digest = Hash::hash_pair(left, right);
        tasmlib::tasm_hashing_merkle_verify(
            txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&msah),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // authenticate divined removal records against txk mast hash
        let removal_records_digest = Hash::hash(&rriw.removal_records);
        tasmlib::tasm_hashing_merkle_verify(
            txk_digest,
            TransactionKernelField::Inputs as u32,
            removal_records_digest,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // iterate over all input UTXOs
        let mut all_aocl_indices: Vec<u64> = Vec::new();
        let mut input_index: usize = 0;
        while input_index < input_utxos.len() {
            let utxo: &Utxo = &input_utxos[input_index];
            let utxo_hash = Hash::hash(utxo);
            let msmp: &MsMembershipProof = &rriw.membership_proofs[input_index];
            let removal_record: &RemovalRecord = &rriw.removal_records[input_index];

            // verify AOCL membership
            let addition_record: AdditionRecord = commit(
                utxo_hash,
                msmp.sender_randomness,
                msmp.receiver_preimage.hash(),
            );
            tasmlib::mmr_verify_from_secret_in_leaf_index_on_stack(
                &aocl.peaks(),
                aocl.num_leafs(),
                msmp.aocl_leaf_index,
                addition_record.canonical_commitment,
            );

            // calculate absolute index set
            let aocl_leaf_index = msmp.aocl_leaf_index;
            let index_set = get_swbf_indices(
                utxo_hash,
                msmp.sender_randomness,
                msmp.receiver_preimage,
                aocl_leaf_index,
            );

            assert_eq!(index_set, removal_record.absolute_indices.to_array());

            // ensure the aocl leaf index is unique
            {
                let mut j: usize = 0;
                while j < all_aocl_indices.len() {
                    assert_ne!(all_aocl_indices[j], aocl_leaf_index);
                    j += 1;
                }
            }
            all_aocl_indices.push(aocl_leaf_index);

            // derive inactive chunk indices from absolute index set
            let mut inactive_chunk_indices: Vec<u64> = Vec::new();
            {
                let mut j = 0;
                while j < index_set.len() {
                    let absolute_index = index_set[j];
                    let chunk_index: u64 = (absolute_index / (CHUNK_SIZE as u128)) as u64;
                    if chunk_index < swbfi.num_leafs()
                        && !inactive_chunk_indices.contains(&chunk_index)
                    {
                        inactive_chunk_indices.push(chunk_index);
                    }
                    j += 1;
                }
            }

            // authenticate chunks in dictionary
            let target_chunks: &ChunkDictionary = &removal_record.target_chunks;
            let mut visited_chunk_indices: Vec<u64> = vec![];
            for (chunk_index, (mmrmp, chunk)) in target_chunks.iter() {
                assert!(mmrmp.verify(
                    *chunk_index,
                    Hash::hash(chunk),
                    &swbfi.peaks(),
                    swbfi.num_leafs()
                ));
                visited_chunk_indices.push(*chunk_index);
            }

            // equate chunk index lists as sets
            inactive_chunk_indices.sort();
            visited_chunk_indices.sort();
            assert_eq!(inactive_chunk_indices, visited_chunk_indices);

            input_index += 1;
        }

        // compute and output hash of salted input UTXOs
        let hash_of_inputs = Hash::hash(salted_input_utxos);
        tasmlib::tasm_io_write_to_stdout___digest(hash_of_inputs);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let bag_peaks = library.import(Box::new(BagPeaks));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let new_list_u64 = library.import(Box::new(New {
            element_type: DataType::U64,
        }));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let ms_commit = library.import(Box::new(mutator_set::commit::Commit));
        let mmr_verify = library.import(Box::new(MmrVerifyFromSecretInLeafIndexOnStack));
        let compute_indices = library.import(Box::new(ComputeIndices));
        let hash_index_list = library.import(Box::new(HashStaticSize {
            size: NUM_TRIALS as usize * 4,
        }));
        let contains_u64 = library.import(Box::new(Contains {
            element_type: DataType::U64,
        }));
        let push_u64 = library.import(Box::new(Push {
            element_type: DataType::U64,
        }));
        let multiset_equality_u64s = library.import(Box::new(MultisetEqualityU64s));
        let shift_right_log2_chunk_size =
            library.import(Box::new(ShiftRightStaticU128::<LOG2_CHUNK_SIZE>));
        let lt_u64 = library.import(Box::new(LtU64ConsumeArgs));
        let mmr_verify_from_memory = library.import(Box::new(MmrVerifyFromMemory));

        let field_aocl = field!(RemovalRecordsIntegrityWitness::aocl);
        let field_swbfi = field!(RemovalRecordsIntegrityWitness::swbfi);
        type MmrAccumulatorTip5 = MmrAccumulator<Hash>;
        let field_peaks = field!(MmrAccumulatorTip5::peaks);
        let field_swbfa_hash = field!(RemovalRecordsIntegrityWitness::swbfa_hash);
        let field_input_utxos = field!(RemovalRecordsIntegrityWitness::input_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_with_size_removal_records =
            field_with_size!(RemovalRecordsIntegrityWitness::removal_records);
        let field_with_size_input_utxos =
            field_with_size!(RemovalRecordsIntegrityWitness::input_utxos);
        let field_ms_membership_proofs = field!(RemovalRecordsIntegrityWitness::membership_proofs);
        let field_removal_records = field!(RemovalRecordsIntegrityWitness::removal_records);

        let outer_loop = "for_all_utxos".to_string();

        let authenticate_mutator_set_acc_against_txkmh = triton_asm!(
            // _ [txk_mast_hash] *witness
            dup 5
            dup 5
            dup 5
            dup 5
            dup 5
            // _ [txk_mast_hash] *witness [txk_mast_hash]

            push {TransactionKernel::MAST_HEIGHT}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h

            dup 6
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness

            push 0
            push 0
            push 0
            push 0
            push 1
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [default]

            push 0
            push 0
            push 0
            push 0
            push 0
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [default]

            dup 10 {&field_swbfa_hash}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [default] *swbfa_hash

            push {Digest::LEN-1} add read_mem {Digest::LEN} pop 1
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [default] [swbfa_hash]

            hash
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right]

            dup 10 {&field_swbfi}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] *swbfi

            {&field_peaks} call {bag_peaks}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [swbfi_hash]

            dup 15 {&field_aocl}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [swbfi_hash] *aocl

            {&field_peaks} call {bag_peaks}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [swbfi_hash] [aocl_hash]

            hash
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [left]

            hash
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [msa_hash]

            sponge_init sponge_absorb
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness

            sponge_squeeze
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [garbage] [msa_hash_as_leaf]

            swap 5 pop 1
            swap 5 pop 1
            swap 5 pop 1
            swap 5 pop 1
            swap 5 pop 1
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [msa_hash_as_leaf]

            push {TransactionKernelField::MutatorSetHash as u32}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [msa_hash] i

            swap 6 pop 1
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i [msa_hash]

            call {merkle_verify}
            // _ [txk_mast_hash] *witness
        );

        let authenticate_removal_records_against_txkmh = triton_asm!(
            // _ [txk_mast_hash] *witness
            dup 5
            dup 5
            dup 5
            dup 5
            dup 5
            // _ [txk_mast_hash] *witness [txk_mast_hash]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Inputs as u32}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i

            dup 7 {&field_with_size_removal_records}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i *removal_records size

            call {hash_varlen}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i [removal_records_hash]

            call {merkle_verify}
            // _ [txk_mast_hash] *witness
        );

        let payload = triton_asm! {
            /* read txkmh */
            read_io {Digest::LEN}
            hint txk_mast_hash = stack[0..5]
            // _ [txk_mast_hash]

            /* point to witness */
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            // _ [txk_mast_hash] *witness

            {&authenticate_mutator_set_acc_against_txkmh}
            // _ [txk_mast_hash] *witness


            /* authenticate divined removal records against txk mast hash */
            {&authenticate_removal_records_against_txkmh}

            /* iterate over all input UTXOs */
            call {new_list_u64}
            // _ [txk_mast_hash] *witness *all_aocl_indices
            hint all_aocl_indices = stack[0]

            dup 1 {&field_aocl}
            // _ [txk_mast_hash] *witness *all_aocl_indices *aocl
            hint aocl = stack[0]

            dup 2 {&field_input_utxos} {&field_utxos}
            // _ [txk_mast_hash] *witness *all_aocl_indices *aocl *utxos

            read_mem 1 push 2 add push 0 swap 1
            // _ [txk_mast_hash] *witness *all_aocl_indices *aocl num_utxos 0 *utxos[0]_si

            dup 5 {&field_ms_membership_proofs} push 1 add
            // _ [txk_mast_hash] *witness *all_aocl_indices *aocl num_utxos 0 *utxos[0]_si *msmp[0]_si

            dup 6 {&field_removal_records} push 1 add
            // _ [txk_mast_hash] *witness *all_aocl_indices *aocl num_utxos 0 *utxos[0]_si *msmp[0]_si *removal_records[0]_si

            swap 5
            // _ [txk_mast_hash] *witness *all_aocl_indices *removal_records[0]_si num_utxos 0 *utxos[0]_si *msmp[0]_si *aocl
            hint aocl = stack[0]
            hint msmp_i_si = stack[1]
            hint utxos_i_si = stack[2]
            hint i = stack[3]
            hint num_utxos = stack[4]
            hint removal_records_i_si = stack[5]
            hint all_aocl_indices = stack[6]

            // INVARIANT: _ *witness *all_aocl_indices *removal_records[0]_si num_utxos 0 *utxos[0]_si *msmp[0]_si *aocl
            call {outer_loop}
            // _ [txk_mast_hash] *witness *all_aocl_indices *removal_records[0]_si num_utxos num_utxos *utxos[num_utxos]_si *msmp[num_utxos]_si *aocl

            pop 5 pop 2
            // _ [txk_mast_hash] *witness


            /* compute and output hash of salted input UTXOs */
            {&field_with_size_input_utxos}
            // _ [txk_mast_hash] *salted_input_utxos size

            call {hash_varlen}
            // _ [txk_mast_hash] [salted_input_utxos_hash]

            write_io 5
            // _ [txk_mast_hash]

            halt
        };

        let field_receiver_preimage = field!(MsMembershipProof::receiver_preimage);
        let field_sender_randomness = field!(MsMembershipProof::sender_randomness);
        let field_mmr_num_leafs = field!(MmrAccumulatorTip5::leaf_count);
        let field_aocl_leaf_index = field!(MsMembershipProof::aocl_leaf_index);
        let field_indices = field!(RemovalRecord::absolute_indices);
        let field_target_chunks = field!(RemovalRecord::target_chunks);

        let collect_aocl_index = "collect_aocl_index".to_string();
        let for_all_absolute_indices = "for_all_absolute_indices".to_string();
        let visit_all_chunks = "visit_all_chunks".to_string();

        let compare_digests = DataType::Digest.compare();

        let subroutine_outer_loop = triton_asm! {
            // INVARIANT: _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl
            {outer_loop}:

                dup 4 dup 4 eq
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl(num_utxos == i)

                skiz return
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl


                /* calculate UTXO hash */
                dup 2 read_mem 1 push 2 add swap 1 call {hash_varlen}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash]
                hint utxo_hash = stack[0..5]

                dup 5
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *aocl


                /* put peaks on stack */
                {&field_peaks}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks

                /* get `receiver_digest` */
                push 0
                push 0
                push 0
                push 0
                push 0
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [default]

                dup 12
                push 1 add
                {&field_receiver_preimage}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [default] *receiver_preimage

                push {Digest::LEN - 1}
                add
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [default] [receiver_preimage]
                hint receiver_preimage = stack[0..5]

                hash
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [receiver_digest]
                hint receiver_digest = stack[0..5]

                /* get `sender_randomness` */
                dup 12
                push 1
                add
                {&field_sender_randomness}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [receiver_preimage] *sender_randomness

                push {Digest::LEN - 1}
                add
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [receiver_preimage] [sender_randomness]
                hint sender_randomness = stack[0..5]

                /* duplicate utxo hash to top */
                dup 15
                dup 15
                dup 15
                dup 15
                dup 15
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [receiver_preimage] [sender_randomness] [utxo_hash]

                /* calculate canonical commitment */
                call {ms_commit}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [canonical_commitment]
                hint canonical_commitment = stack[0..5]

                /* authenticate commitment against aocl */
                dup 11
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [canonical_commitment] *aocl

                {&field_mmr_num_leafs} push 1 add read_mem 2 pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [canonical_commitment] [num_leafs]

                dup 14 push 1 add {&field_aocl_leaf_index}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [canonical_commitment] [num_leafs] *index

                push 1 add read_mem 2 pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *peaks [canonical_commitment] [num_leafs] [leaf_index]

                call {mmr_verify}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash]


                /* calculate the absolute index set */

                dup 6 push 1 add
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl [utxo_hash] *msmp[i]
                hint msmp_i = stack[0]

                call {compute_indices}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices
                hint computed_bloom_indices = stack[0]


                /* assert equality with the absolute index set from the removal record */

                dup 6 push 1 add
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *removal_records[i]
                hint removal_record_i = stack[0]

                {&field_indices}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *present_bloom_indices
                hint present_bloom_indices = stack[0]

                call {hash_index_list} pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [present_bloom_indices]
                hint present_bloom_indices = stack[0..5]

                dup 5 push 1 add call {hash_index_list} pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [present_bloom_indices] [computed_bloom_indices]
                hint computed_bloom_indices = stack[0..5]

                {&compare_digests}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices (present == computed)

                assert
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices

                /* ensure that the AOCL leaf index is unique */

                dup 7 dup 3 push 1 add {&field_aocl_leaf_index}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *all_aocl_indices *aocl_index
                hint aocl_leaf_index_ptr = stack[0]

                push 1 add read_mem 2 pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *all_aocl_indices [aocl_index]
                hint aocl_leaf_index = stack[0..2]

                call {contains_u64}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices (aocl_index in all_aocl_indices)

                push 0 eq
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices (aocl_index not in all_aocl_indices)

                dup 0 assert
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices (aocl_index not in all_aocl_indices)

                skiz call {collect_aocl_index}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices


                /* derive inactive chunk indices from absolute index set */

                dup 8
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *witness

                {&field_swbfi}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *swbfi

                {&field_mmr_num_leafs}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *swbfi_num_leafs

                push 1 add read_mem 2 pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs]

                call {new_list_u64}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices

                push {NUM_TRIALS} push 0
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices NUM_TRIALS 0

                dup 5 push 1 add
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices NUM_TRIALS 0 *bloom_index[0]
                hint bloom_index_i = stack[0]
                hint i = stack[1]
                hint num_trials = stack[2]
                hint inactive_chunk_indices = stack[3]
                hint swbfi_num_leafs = stack[4..6]

                call {for_all_absolute_indices}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices NUM_TRIALS NUM_TRIALS *bloom_index[NUM_TRIALS]

                pop 3
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices


                /* authenticate chunks in dictionary */

                call {new_list_u64}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices
                hint visited_chunk_indices = stack[0]

                dup 12 {&field_swbfi}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices *swbfi
                hint swbfi = stack[0]

                dup 11 push 1 add
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices *utxos[i]
                hint removal_records_i = stack[0]

                {&field_target_chunks}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices *swbfi *target_chunks

                dup 0 push 1 add read_mem 1 pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices *swbfi *target_chunks N

                push 0 dup 2 push 2 add
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices *swbfi *target_chunks N 0 *target_chunks[0]_si
                hint target_chunks_j_si = stack[0]
                hint j = stack[1]
                hint num_chunks = stack[2]
                hint target_chunks = stack[3]

                call {visit_all_chunks}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices *swbfi *target_chunks N N *target_chunks[N]_si

                pop 5
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] *inactive_chunk_indices *visited_chunk_indices


                /* equate chunk index lists as sets */

                call {multiset_equality_u64s}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs] ({inactive_chunk_indices} == {visited_chunk_indices})

                assert
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices [swbfi_num_leafs]


                /* clear stack and prepare to reiterate */

                pop 3
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl

                swap 1 read_mem 1 push 2 add add swap 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i+1] *aocl
                swap 2 read_mem 1 push 2 add add swap 2
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i+1]_si *msmp[i+1] *aocl
                swap 5 read_mem 1 push 2 add add swap 5
                // _ *witness *all_aocl_indices *removal_records[i+1]_si num_utxos i *utxos[i+1]_si *msmp[i+1] *aocl

                swap 3 push 1 add swap 3
                // _ *witness *all_aocl_indices *removal_records[i+1]_si num_utxos (i+1) *utxos[i+1]_si *msmp[i+1] *aocl

                recurse
        };

        let subroutine_collect_aocl_index = triton_asm! {
            // BEFORE: _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices
            // AFTER: _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices
            {collect_aocl_index}:
                dup 7
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *all_aocl_indices

                dup 4 push 1 add {&field_aocl_leaf_index}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *all_aocl_indices *aocl_leaf_index

                push 1 add read_mem 2 pop 1
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices *all_aocl_indices [aocl_leaf_index]

                call {push_u64}
                // _ *witness *all_aocl_indices *removal_records[i]_si num_utxos i *utxos[i]_si *msmp[i]_si *aocl *computed_bloom_indices

                return
        };

        let collect_inactive_chunk_index = "collect_inactive_chunk_index".to_string();
        const LOG2_CHUNK_SIZE: u8 = 12;
        assert_eq!(CHUNK_SIZE, 1 << LOG2_CHUNK_SIZE);

        let subroutine_for_all_absolute_indices = triton_asm! {
            // INVARIANT: _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS 0 *bloom_index[0]
            {for_all_absolute_indices}:
                dup 2 dup 2 eq
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] (NUM_TRIALS==i)

                skiz return
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i]


                /* compute chunk index */
                dup 0 push 3 add read_mem 4 pop 1
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [bloom_index[i]]
                hint bloom_index = stack[0..4]

                call {shift_right_log2_chunk_size}
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [bloom_index[i] / chunk_size]
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] 0 0 [chunk_index]

                swap 2 pop 1
                swap 2 pop 1
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index]
                hint chunk_index = stack[0..2]


                /* test activity */
                dup 7 dup 7
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] [swbf_num_leafs]

                dup 3 dup 3
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] [swbf_num_leafs] [chunk_index]

                call {lt_u64}
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] (chunk_index < swbf_num_leafs)


                /* filter out duplicates */

                dup 6 dup 3 dup 3
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] (chunk_index < swbf_num_leafs) *inactive_indices [chunk_index]

                call {contains_u64}
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] (chunk_index < swbf_num_leafs) (chunk_index in inactive_indices)

                push 0 eq
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] (chunk_index < swbf_num_leafs) (chunk_index not in inactive_indices)

                mul
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] (chunk_index < swbf_num_leafs && chunk_index not in inactive_indices)

                skiz call {collect_inactive_chunk_index}
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index]

                pop 2
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i]


                /* prepare next iteration */

                swap 1 push 1 add swap 1
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS (i+1) *bloom_index[i]

                push 4 add
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS (i+1) *bloom_index[i+1]

                recurse
        };

        let subroutine_collect_inactive_chunk_index = triton_asm! {
            // BEFORE: _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index]
            // AFTER: _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index]
            {collect_inactive_chunk_index}:

                dup 5 dup 2 dup 2
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index] *inactive_chunk_indices [chunk_index]

                call {push_u64}
                // _ [swbf_num_leafs] *inactive_chunk_indices NUM_TRIALS i *bloom_index[i] [chunk_index]

                return
        };

        // field getters for chunk dictionary entry
        // *chunk_dictionary_entry : (chunk_index, (mmr_mp, chunk))
        // serialized as: size(chunk+mmr_mp), size(chunk), len(chunk), [indices], size(mmr_mp), [mmr_mp], [chunk index]
        let field_chunk_index = triton_asm!(
            read_mem 1
            hint size_of_chunk_and_mmrmp = stack[1]
            hint chunk_entry_minus_one = stack[0]
            push 2 add
            hint chunk_si = stack[0]
            add
            hint chunk_index_ptr = stack[0]
        );
        let field_with_size_chunk = triton_asm!(
            push 1 add
            hint chunk_si = stack[0]
            read_mem 1
            hint size = stack[1]
            hint garbage = stack[0]
            push 2 add
            hint chunk = stack[0]
            swap 1
        );
        type MmrMembershipProofTip5 = MmrMembershipProof<Hash>;
        let field_authentication_path_on_mmrmp =
            field!(MmrMembershipProofTip5::authentication_path);
        let field_auth_path = triton_asm!(
            push 1 add
            read_mem 1
            push 3 add add
            hint mmr_mp = stack[0]
            {&field_authentication_path_on_mmrmp}
        );

        let subroutine_visit_all_chunks = triton_asm! {
            // INVARIANT: _ *visited_chunk_indices *swbfi *target_chunks N j *target_chunks[i]_si
            {visit_all_chunks}:
                dup 2 dup 2 eq
                // _  *visited_chunk_indices *swbfi *target_chunks N j *target_chunks[i]_si (N == i)

                skiz return
                // _ *visited_chunk_indices *swbfi *target_chunks N j *target_chunks[i]_si

                read_mem 1 push 2 add
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i]
                hint target_chunks_j = stack[0]
                hint chunk_size = stack[1]

                /* prepare to call mmr verify from memory
                   For this call to work, the stack needs to look like this:
                   _ *peaks leaf_count_hi leaf_count_lo leaf_index_hi leaf_index_lo [digest (leaf_digest)] *auth_path
                */

                dup 5 {&field_peaks}
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *peaks
                hint peaks = stack[0]

                dup 6 {&field_mmr_num_leafs}
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *peaks *mmr_num_leafs
                hint mmr_num_leafs = stack[0]

                push 1 add read_mem 2 pop 1
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *peaks [num_leafs]
                hint num_leafs = stack[0..2]

                dup 3 {&field_chunk_index} push 1 add read_mem 2 pop 1
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *peaks [num_leafs] [leaf_index]
                hint leaf_index = stack[0..2]

                dup 5 {&field_with_size_chunk}
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *peaks [num_leafs] [leaf_index] *chunk size
                hint chunk_size = stack[0]
                hint chunk = stack[1]

                call {hash_varlen}
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *peaks [num_leafs] [leaf_index] [chunk_digest]
                hint chunk_digest = stack[0..5]

                dup 10 {&field_auth_path}
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *peaks [num_leafs] [leaf_index] [chunk_digest] *auth_path
                hint auth_path = stack[0]

                call {mmr_verify_from_memory} assert
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i]


                /* record chunk index as visited */

                dup 6 dup 1 {&field_chunk_index}
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *visited_chunk_indices *chunk_index

                push 1 add read_mem 2 pop 1
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i] *visited_chunk_indices [chunk_index]

                call {push_u64}
                // _ *visited_chunk_indices *swbfi *target_chunks N j chunk_size *target_chunks[i]


                /* prepare next iteration */

                add
                // _ *visited_chunk_indices *swbfi *target_chunks N j *target_chunks[i+1]_si

                swap 1 push 1 add swap 1
                // _ *visited_chunk_indices *swbfi *target_chunks N (j+1) *target_chunks[i+1]_si

                recurse
        };

        let imports = library.all_imports();

        triton_asm!(
            {&payload}
            {&subroutine_outer_loop}
            {&subroutine_collect_aocl_index}
            {&subroutine_for_all_absolute_indices}
            {&subroutine_collect_inactive_chunk_index}
            {&subroutine_visit_all_chunks}
            {&imports}
        )
    }
}

impl<'a> Arbitrary<'a> for RemovalRecordsIntegrityWitness {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_inputs = u.int_in_range(1..=3usize)?;
        let _num_outputs = u.int_in_range(1..=3usize)?;
        let _num_public_announcements = u.int_in_range(0..=2usize)?;

        let input_utxos: Vec<Utxo> = (0..num_inputs)
            .map(|_| u.arbitrary().unwrap())
            .collect_vec();
        let mut membership_proofs: Vec<MsMembershipProof> = (0..num_inputs)
            .map(|_| u.arbitrary().unwrap())
            .collect_vec();
        let addition_records: Vec<AdditionRecord> = input_utxos
            .iter()
            .zip(membership_proofs.iter())
            .map(|(utxo, msmp)| {
                commit(
                    Hash::hash(utxo),
                    msmp.sender_randomness,
                    msmp.receiver_preimage.hash(),
                )
            })
            .collect_vec();
        let canonical_commitments = addition_records
            .iter()
            .map(|ar| ar.canonical_commitment)
            .collect_vec();
        let (aocl, mmr_mps) =
            Self::pseudorandom_mmra_with_mps(u.arbitrary()?, &canonical_commitments);
        assert_eq!(num_inputs, mmr_mps.len());
        assert_eq!(num_inputs, canonical_commitments.len());

        for ((idx, mp), &cc) in mmr_mps.iter().zip_eq(canonical_commitments.iter()) {
            assert!(
                mp.verify(*idx, cc, &aocl.peaks(), aocl.num_leafs()),
                "Returned MPs must be valid for returned AOCL"
            );
        }

        for (ms_mp, (_idx, mmr_mp)) in membership_proofs.iter_mut().zip(mmr_mps.iter()) {
            ms_mp.auth_path_aocl = mmr_mp.clone();
        }
        let swbfi: MmrAccumulator<Hash> = u.arbitrary()?;
        let swbfa_hash: Digest = u.arbitrary()?;
        let mut kernel: TransactionKernel = u.arbitrary()?;
        kernel.mutator_set_hash = Hash::hash_pair(
            Hash::hash_pair(aocl.bag_peaks(), swbfi.bag_peaks()),
            Hash::hash_pair(swbfa_hash, Digest::default()),
        );
        kernel.inputs = input_utxos
            .iter()
            .zip(membership_proofs.iter())
            .map(|(utxo, msmp)| {
                (
                    Hash::hash(utxo),
                    msmp.sender_randomness,
                    msmp.receiver_preimage,
                    msmp.aocl_leaf_index,
                )
            })
            .map(|(item, sr, rp, li)| get_swbf_indices(item, sr, rp, li))
            .map(|ais| RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new(&ais),
                target_chunks: u.arbitrary().unwrap(),
            })
            .rev()
            .collect_vec();

        let salted_utxos = SaltedUtxos::new(input_utxos);

        Ok(RemovalRecordsIntegrityWitness {
            input_utxos: salted_utxos,
            membership_proofs,
            aocl,
            swbfi,
            swbfa_hash,
            removal_records: kernel.inputs.clone(),
            mast_path_mutator_set: kernel.mast_path(TransactionKernelField::MutatorSetHash),
            mast_path_inputs: kernel.mast_path(TransactionKernelField::Inputs),
            mast_root: kernel.mast_hash(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RemovalRecordsIntegrity;
    use super::RemovalRecordsIntegrityWitness;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::proof_abstractions::tasm::program::ConsensusError;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::models::proof_abstractions::SecretWitness;
    use crate::triton_vm::prelude::*;

    use itertools::Itertools;
    use proptest::arbitrary::Arbitrary;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestCaseError;
    use proptest::test_runner::TestRunner;
    use test_strategy::proptest;

    fn prop_positive(
        removal_records_integrity_witness: RemovalRecordsIntegrityWitness,
    ) -> Result<(), TestCaseError> {
        let salted_inputs_utxos_hash = removal_records_integrity_witness.output();
        let rust_result = RemovalRecordsIntegrity
            .run_rust(
                &removal_records_integrity_witness.standard_input(),
                removal_records_integrity_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(salted_inputs_utxos_hash, rust_result.clone());

        let tasm_result = RemovalRecordsIntegrity
            .run_tasm(
                &removal_records_integrity_witness.standard_input(),
                removal_records_integrity_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(
            rust_result.clone(),
            tasm_result.clone(),
            "\ntasm output: [{}]\nbut expected: [{}]",
            tasm_result.iter().join(", "),
            rust_result.iter().join(", "),
        );

        Ok(())
    }

    fn prop_negative(
        removal_records_integrity_witness: RemovalRecordsIntegrityWitness,
        allowed_failure_codes: &[InstructionError],
    ) -> Result<(), TestCaseError> {
        let tasm_result = RemovalRecordsIntegrity.run_tasm(
            &removal_records_integrity_witness.standard_input(),
            removal_records_integrity_witness.nondeterminism(),
        );
        prop_assert!(tasm_result.is_err());
        let triton_vm_error_code = match tasm_result.unwrap_err() {
            ConsensusError::TritonVMPanic(_string, instruction_error) => instruction_error,
            _ => unreachable!(),
        };

        prop_assert!(allowed_failure_codes.contains(&triton_vm_error_code));

        let rust_result = RemovalRecordsIntegrity.run_rust(
            &removal_records_integrity_witness.standard_input(),
            removal_records_integrity_witness.nondeterminism(),
        );
        prop_assert!(rust_result.is_err());

        Ok(())
    }

    #[proptest(cases = 5)]
    fn removal_records_integrity_proptest(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
    ) {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        prop_positive(removal_records_integrity_witness)?;
    }

    #[test]
    fn removal_records_integrity_unit_test() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        println!("primitive_witness: {primitive_witness}");
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        let property = prop_positive(removal_records_integrity_witness);
        assert!(property.is_ok(), "err: {}", property.unwrap_err());
    }

    #[test]
    fn removal_records_fail_on_bad_ms_acc() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mut bad_removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        bad_removal_records_integrity_witness.mast_path_mutator_set[1] = Digest::default();
        let property = prop_negative(
            bad_removal_records_integrity_witness,
            &[InstructionError::VectorAssertionFailed(0)],
        );
        assert!(property.is_ok(), "Got error: {}", property.unwrap_err());
    }

    #[test]
    fn removal_records_fail_on_bad_mast_path_inputs() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mut bad_removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        bad_removal_records_integrity_witness.mast_path_inputs[1] = Digest::default();
        let property = prop_negative(
            bad_removal_records_integrity_witness,
            &[InstructionError::VectorAssertionFailed(0)],
        );
        assert!(property.is_ok(), "Got error: {}", property.unwrap_err());
    }
}
