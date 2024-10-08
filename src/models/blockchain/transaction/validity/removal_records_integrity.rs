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
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::traits::compiled_program::CompiledProgram;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use triton_vm::prelude::NonDeterminism;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PrimitiveWitness;
use crate::models::consensus::mast_hash::MastHash;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::models::consensus::SecretWitness;
use crate::models::consensus::ValidationLogic;
use crate::models::consensus::ValidityAstType;
use crate::models::consensus::ValidityTree;
use crate::models::consensus::WhichProgram;
use crate::models::consensus::WitnessType;
use crate::prelude::triton_vm;
use crate::prelude::twenty_first;
use crate::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::get_swbf_indices;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

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
    pub input_utxos: Vec<Utxo>,
    pub membership_proofs: Vec<MsMembershipProof>,
    pub aocl: MmrAccumulator<Hash>,
    pub swbfi: MmrAccumulator<Hash>,
    pub swbfa_hash: Digest,
    pub kernel: TransactionKernel,
}

impl RemovalRecordsIntegrityWitness {
    pub fn new(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            input_utxos: primitive_witness.input_utxos.utxos.clone(),
            membership_proofs: primitive_witness.input_membership_proofs.clone(),
            kernel: primitive_witness.kernel.clone(),
            aocl: primitive_witness.mutator_set_accumulator.aocl.clone(),
            swbfi: primitive_witness
                .mutator_set_accumulator
                .swbf_inactive
                .clone(),
            swbfa_hash: Hash::hash(&primitive_witness.mutator_set_accumulator.swbf_active),
        }
    }
}

impl SecretWitness for RemovalRecordsIntegrityWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );
        NonDeterminism::default().with_ram(memory)
    }

    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.kernel.mast_hash().reversed().values().to_vec())
    }

    fn program(&self) -> triton_vm::prelude::Program {
        RemovalRecordsIntegrity {
            witness: self.clone(),
        }
        .program()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount, BFieldCodec)]
pub struct RemovalRecordsIntegrity {
    pub witness: RemovalRecordsIntegrityWitness,
}

impl ConsensusProgram for RemovalRecordsIntegrity {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let program = <Self as CompiledProgram>::program();
        program.labelled_instructions()
    }
}

impl From<transaction::PrimitiveWitness> for RemovalRecordsIntegrity {
    fn from(primitive_witness: transaction::PrimitiveWitness) -> Self {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::new(&primitive_witness);

        Self {
            witness: removal_records_integrity_witness,
        }
    }
}

impl ValidationLogic for RemovalRecordsIntegrity {
    fn vast(&self) -> ValidityTree {
        ValidityTree {
            vast_type: ValidityAstType::Atomic(
                Some(Box::new(self.witness.program())),
                self.witness.claim(),
                WhichProgram::RemovalRecordsIntegrity,
            ),
            witness_type: WitnessType::RawWitness(self.witness.nondeterminism().into()),
        }
    }
}

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
    ) -> (MmrAccumulator<Hash>, Vec<MmrMembershipProof<Hash>>) {
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
        let dummy_mp = MmrMembershipProof::new(0u64, vec![]);
        let mut mps: Vec<MmrMembershipProof<Hash>> =
            (0..leafs.len()).map(|_| dummy_mp.clone()).collect_vec();
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
                        MmrMembershipProof::<Hash>::new(mmr_index, authentication_path)
                    },
                )
                .collect_vec();

            // sanity check: test if membership proofs agree with peaks list (up until now)
            let dummy_remainder: Vec<Digest> = (peaks.len()..num_peaks as usize)
                .map(|_| rng.gen())
                .collect_vec();
            let dummy_peaks = [peaks.clone(), dummy_remainder].concat();
            for (&(leaf, _mt_index, _original_index), mp) in
                leafs_and_mt_indices.iter().zip(membership_proofs.iter())
            {
                assert!(mp.verify(&dummy_peaks, leaf, leaf_count));
            }

            // collect membership proofs in vector, with indices matching those of the supplied leafs
            for ((_leaf, _mt_index, original_index), mp) in
                leafs_and_mt_indices.iter().zip(membership_proofs.iter())
            {
                mps[*original_index] = mp.clone();
            }
        }

        let mmra = MmrAccumulator::<Hash>::init(peaks, leaf_count);

        // sanity check
        for (&leaf, mp) in leafs.iter().zip(mps.iter()) {
            assert!(mp.verify(&mmra.get_peaks(), leaf, mmra.count_leaves()));
        }

        (mmra, mps)
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
                    msmp.receiver_preimage.hash::<Hash>(),
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

        for (mp, &cc) in mmr_mps.iter().zip_eq(canonical_commitments.iter()) {
            assert!(
                mp.verify(&aocl.get_peaks(), cc, aocl.count_leaves()),
                "Returned MPs must be valid for returned AOCL"
            );
        }

        for (ms_mp, mmr_mp) in membership_proofs.iter_mut().zip(mmr_mps.iter()) {
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
                    msmp.auth_path_aocl.leaf_index,
                )
            })
            .map(|(item, sr, rp, li)| get_swbf_indices(item, sr, rp, li))
            .map(|ais| RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new(&ais),
                target_chunks: u.arbitrary().unwrap(),
            })
            .rev()
            .collect_vec();

        let mut kernel_index_set_hashes = kernel
            .inputs
            .iter()
            .map(|rr| Hash::hash(&rr.absolute_indices))
            .collect_vec();
        kernel_index_set_hashes.sort();

        Ok(RemovalRecordsIntegrityWitness {
            input_utxos,
            membership_proofs,
            aocl,
            swbfi,
            swbfa_hash,
            kernel,
        })
    }
}
