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
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::bag_peaks::BagPeaks;
use tasm_lib::mmr::verify_from_secret_in_leaf_index_on_stack::MmrVerifyFromSecretInLeafIndexOnStack;
use tasm_lib::neptune::mutator_set;
use tasm_lib::neptune::mutator_set::get_swbf_indices::GetSwbfIndices;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::bfe;
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
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::get_swbf_indices;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::shared::NUM_TRIALS;
use crate::util_types::mutator_set::shared::WINDOW_SIZE;

/// An Ms membership proof without any authentication paths
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject, Arbitrary,
)]
struct PartialMsMembershipProof {
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub aocl_leaf_index: u64,
}

impl From<&MsMembershipProof> for PartialMsMembershipProof {
    fn from(value: &MsMembershipProof) -> Self {
        PartialMsMembershipProof {
            sender_randomness: value.sender_randomness,
            receiver_preimage: value.receiver_preimage,
            aocl_leaf_index: value.aocl_leaf_index,
        }
    }
}

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
    partial_membership_proofs: Vec<PartialMsMembershipProof>,
    aocl_auth_paths: Vec<MmrMembershipProof<Hash>>,
    removal_records: Vec<RemovalRecord>,
    aocl: MmrAccumulator<Hash>,
    swbfi: MmrAccumulator<Hash>,
    swbfa_hash: Digest,
    mast_path_mutator_set: Vec<Digest>,
    mast_path_inputs: Vec<Digest>,
    mast_root: Digest,
}

impl From<&PrimitiveWitness> for RemovalRecordsIntegrityWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            input_utxos: primitive_witness.input_utxos.clone(),
            partial_membership_proofs: primitive_witness
                .input_membership_proofs
                .iter()
                .map(|x| x.into())
                .collect(),
            aocl_auth_paths: primitive_witness
                .input_membership_proofs
                .iter()
                .map(|x| x.auth_path_aocl.to_owned())
                .collect(),
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
            self.aocl_auth_paths
                .iter()
                .flat_map(|x| x.authentication_path.clone())
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
        let txk_digest: Digest = tasmlib::tasmlib_io_read_stdin___digest();

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
        tasmlib::tasmlib_hashing_merkle_verify(
            txk_digest,
            TransactionKernelField::MutatorSetHash as u32,
            Hash::hash(&msah),
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // authenticate divined removal records against txk mast hash
        let removal_records_digest = Hash::hash(&rriw.removal_records);
        tasmlib::tasmlib_hashing_merkle_verify(
            txk_digest,
            TransactionKernelField::Inputs as u32,
            removal_records_digest,
            TransactionKernelField::COUNT.next_power_of_two().ilog2(),
        );

        // iterate over all input UTXOs
        let mut input_index: usize = 0;
        while input_index < input_utxos.len() {
            let utxo: &Utxo = &input_utxos[input_index];
            let utxo_hash = Hash::hash(utxo);
            let msmp = &rriw.partial_membership_proofs[input_index];
            let claimed_absolute_indices = &rriw.removal_records[input_index].absolute_indices;

            // verify AOCL membership
            let addition_record: AdditionRecord = commit(
                utxo_hash,
                msmp.sender_randomness,
                msmp.receiver_preimage.hash(),
            );
            assert!(tasmlib::mmr_verify_from_secret_in_leaf_index_on_stack(
                &aocl.peaks(),
                aocl.num_leafs(),
                msmp.aocl_leaf_index,
                addition_record.canonical_commitment,
            ));

            // calculate absolute index set
            let aocl_leaf_index = msmp.aocl_leaf_index;
            let index_set = get_swbf_indices(
                utxo_hash,
                msmp.sender_randomness,
                msmp.receiver_preimage,
                aocl_leaf_index,
            );

            assert_eq!(index_set, claimed_absolute_indices.to_array());

            input_index += 1;
        }

        // compute and output hash of salted input UTXOs
        let hash_of_inputs = Hash::hash(salted_input_utxos);
        tasmlib::tasmlib_io_write_to_stdout___digest(hash_of_inputs);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();

        let bag_peaks = library.import(Box::new(BagPeaks));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let ms_commit = library.import(Box::new(mutator_set::commit::Commit));
        let mmr_verify = library.import(Box::new(MmrVerifyFromSecretInLeafIndexOnStack));
        let swbf_indices = library.import(Box::new(GetSwbfIndices {
            num_trials: NUM_TRIALS as usize,
            window_size: WINDOW_SIZE,
        }));

        let size_of_u128 = DataType::U128.stack_size();
        let hash_index_array = library.import(Box::new(HashStaticSize {
            // size is 4 * NUM_TRIALS as arrays don't contain size indicators
            size: NUM_TRIALS as usize * size_of_u128,
        }));

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
        let field_ms_membership_proofs =
            field!(RemovalRecordsIntegrityWitness::partial_membership_proofs);
        let field_removal_records = field!(RemovalRecordsIntegrityWitness::removal_records);

        let for_all_utxos = "for_all_utxos".to_string();

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

            /* Prepare for main loop */
            dup 0 {&field_aocl}
            hint aocl = stack[0]
            // _ [txk_mast_hash] *witness *aocl

            dup 1 {&field_input_utxos} {&field_utxos}
            // _ [txk_mast_hash] *witness *aocl *utxos

            read_mem 1 push 2 add push 0 swap 1
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si

            dup 4 {&field_ms_membership_proofs} push 1 add
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si *msmp[0]_si

            dup 5 {&field_removal_records} push 1 add
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si *msmp[0]_si *removal_records[0]_si

            swap 5
            hint aocl = stack[0]
            hint msmp_i = stack[1]
            hint utxos_i_si = stack[2]
            hint i = stack[3]
            hint num_utxos = stack[4]
            hint removal_records_i_si = stack[5]
            // _ [txk_mast_hash] *witness *removal_records[0]_si num_utxos 0 *utxos[0]_si *msmp[0] *aocl

            // INVARIANT: _ *witness *removal_records[0]_si num_utxos 0 *utxos[0]_si *msmp[0] *aocl
            call {for_all_utxos}
            // _ [txk_mast_hash] *witness *removal_records[num_utxos]_si num_utxos num_utxos *utxos[num_utxos]_si *msmp[num_utxos] *aocl

            pop 5 pop 1
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

        let field_receiver_preimage = field!(PartialMsMembershipProof::receiver_preimage);
        let field_sender_randomness = field!(PartialMsMembershipProof::sender_randomness);
        let field_mmr_num_leafs = field!(MmrAccumulatorTip5::leaf_count);
        let field_aocl_leaf_index = field!(PartialMsMembershipProof::aocl_leaf_index);
        let field_indices = field!(RemovalRecord::absolute_indices);

        let compare_digests = DataType::Digest.compare();

        let partial_msmp_size = PartialMsMembershipProof::static_length().unwrap();

        let u64_stack_size: u32 = DataType::U64.stack_size().try_into().unwrap();
        let aocl_leaf_index_write_pointer = library.kmalloc(u64_stack_size);
        let aocl_leaf_index_read_pointer = aocl_leaf_index_write_pointer + bfe!(u64_stack_size - 1);

        let digest_stack_size: u32 = DataType::Digest.stack_size().try_into().unwrap();
        let receiver_preimage_write_pointer = library.kmalloc(digest_stack_size);
        let receiver_preimage_read_pointer =
            receiver_preimage_write_pointer + bfe!(digest_stack_size - 1);
        let sender_randomness_write_pointer = library.kmalloc(digest_stack_size);
        let sender_randomness_read_pointer =
            sender_randomness_write_pointer + bfe!(digest_stack_size - 1);
        let utxo_hash_write_pointer = library.kmalloc(digest_stack_size);
        let utxo_hash_read_pointer = utxo_hash_write_pointer + bfe!(digest_stack_size - 1);

        let for_all_utxos_loop = triton_asm! {
            // INVARIANT: _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl
            {for_all_utxos}:
                /*
                    1. Check loop stop-condition
                    2. Calculate UTXO hash, store to static memory
                    3. Get AOCL leaf index, store to static memory
                    4. Get receiver preimage, store to static memory
                    5. Get sender randomness, store to static memory
                    6. Calculate canonical commitment
                    7. Verify AOCL-membership of canonical commitment
                    8. Calculate SWBF-indices
                    9. Verify equality with claimed SWBF-indices
                    10. Prepare for next loop iteration
                 */


                /* 1. */
                dup 4 dup 4 eq
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl(num_utxos == i)

                skiz return
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl


                /* 2. */
                dup 2
                read_mem 1
                push 2
                add
                swap 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *utxos[i] utxos[i]_size

                call {hash_varlen}
                hint utxo_hash = stack[0..5]
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [utxo_hash]

                push {utxo_hash_write_pointer}
                write_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl


                /* 3. */
                dup 1 {&field_aocl_leaf_index}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_leaf_index

                push 1 add read_mem {u64_stack_size} pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [aocl_leaf_index]

                push {aocl_leaf_index_write_pointer}
                write_mem {u64_stack_size}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl


                /* 4. */
                dup 1 {&field_receiver_preimage}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *receiver_preimage

                push {Digest::LEN - 1}
                add
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [receiver_preimage]

                push {receiver_preimage_write_pointer}
                write_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl


                /* 5. */
                dup 1 {&field_sender_randomness}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *sender_randomness

                push {Digest::LEN - 1}
                add
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [sender_randomness]

                push {sender_randomness_write_pointer}
                write_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl


                /* 6. */
                dup 0
                {&field_peaks}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks

                push 0
                push 0
                push 0
                push 0
                push 0
                push {receiver_preimage_read_pointer}
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [default] [receiver_preimage]

                hash
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [receiver_digest]

                push {sender_randomness_read_pointer}
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [receiver_digest] [sender_randomness]

                push {utxo_hash_read_pointer}
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [receiver_digest] [sender_randomness] [utxo_hash]

                call {ms_commit}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [canonical_commitment]


                /* 7. */
                dup 6 {&field_mmr_num_leafs}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [canonical_commitment] *num_leafs

                push 1 add read_mem {u64_stack_size} pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [canonical_commitment] [num_leafs]

                push {aocl_leaf_index_read_pointer}
                read_mem {u64_stack_size}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *aocl_peaks [canonical_commitment] [num_leafs_aocl] [aocl_leaf_index]

                call {mmr_verify}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl

                /* 8. */
                push {aocl_leaf_index_read_pointer}
                read_mem {u64_stack_size}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [aocl_leaf_index]

                push {receiver_preimage_read_pointer}
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [aocl_leaf_index] [receiver_preimage]

                push {sender_randomness_read_pointer}
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [aocl_leaf_index] [receiver_preimage] [sender_randomness]

                push {utxo_hash_read_pointer}
                read_mem {Digest::LEN}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [aocl_leaf_index] [receiver_preimage] [sender_randomness] [utxo_hash]

                call {swbf_indices}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl *computed_bloom_indices

                push 1 add
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl (*computed_bloom_indices as array)

                call {hash_index_array}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [computed_bloom_indices]

                /* 9. */
                dup 10
                push 1
                add
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [computed_bloom_indices] *rrs[i]

                {&field_indices}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [computed_bloom_indices] *claimed_indices[i]

                call {hash_index_array}
                pop 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl [computed_bloom_indices_h] [claimed_indices_h]

                {&compare_digests}
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl (computed_bloom_indices_h == claimed_indices_h)

                assert
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i] *aocl

                /* 10. */
                swap 1
                push {partial_msmp_size} add
                swap 1
                // _ *witness *rrs[i]_si num_utxos i *utxos[i]_si *msmp[i + 1] *aocl

                swap 2
                read_mem 1
                push 2 add
                add
                swap 2
                // _ *witness *rrs[i]_si num_utxos i *utxos[i + 1]_si *msmp[i + 1] *aocl

                swap 3
                push 1 add
                swap 3
                // _ *witness *rrs[i]_si num_utxos (i + 1) *utxos[i + 1]_si *msmp[i + 1] *aocl

                swap 5
                read_mem 1
                push 2 add
                add
                swap 5
                // _ *witness *rrs[i + 1]_si num_utxos (i + 1) *utxos[i + 1]_si *msmp[i + 1] *aocl

                recurse
        };

        let imports = library.all_imports();
        triton_asm!(
            {&payload}
            {&for_all_utxos_loop}
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

        let partial_membership_proofs = membership_proofs.iter().map(|x| x.into()).collect();
        let aocl_auth_paths = membership_proofs
            .iter()
            .map(|x| x.auth_path_aocl.to_owned())
            .collect();

        Ok(RemovalRecordsIntegrityWitness {
            input_utxos: salted_utxos,
            partial_membership_proofs,
            aocl_auth_paths,
            aocl,
            swbfi,
            swbfa_hash,
            mast_path_mutator_set: kernel.mast_path(TransactionKernelField::MutatorSetHash),
            mast_path_inputs: kernel.mast_path(TransactionKernelField::Inputs),
            mast_root: kernel.mast_hash(),
            removal_records: kernel.inputs,
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
    use crate::util_types::mutator_set::shared::NUM_TRIALS;

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
    fn removal_records_integrity_only_rust_shadowing() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        println!("primitive_witness: {primitive_witness}");
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        let salted_inputs_utxos_hash = removal_records_integrity_witness.output();
        let rust_result = RemovalRecordsIntegrity
            .run_rust(
                &removal_records_integrity_witness.standard_input(),
                removal_records_integrity_witness.nondeterminism(),
            )
            .unwrap();
        assert_eq!(salted_inputs_utxos_hash, rust_result.clone());
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

    #[proptest(cases = 2)]
    fn removal_records_fail_on_bad_absolute_indices(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
        #[strategy(0..2usize)] mutated_input: usize,
        #[strategy(0..NUM_TRIALS as usize)] mutated_bloom_filter_index: usize,
    ) {
        let mut bad_removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        bad_removal_records_integrity_witness.removal_records[mutated_input]
            .absolute_indices
            .increment_bloom_filter_index(mutated_bloom_filter_index);
        prop_negative(
            bad_removal_records_integrity_witness,
            &[InstructionError::VectorAssertionFailed(0)],
        )?;
    }
}
