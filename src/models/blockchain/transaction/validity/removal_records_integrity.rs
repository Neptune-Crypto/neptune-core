use arbitrary::Arbitrary;
use field_count::FieldCount;
use get_size::GetSize;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use strum::EnumCount;
use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use triton_vm::instruction::LabelledInstruction;
use triton_vm::prelude::BFieldElement;
use triton_vm::prelude::NonDeterminism;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::{
    math::tip5::Digest,
    util_types::{
        algebraic_hasher::AlgebraicHasher,
        mmr::{mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
    },
};

use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::builtins as tasmlib;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::prelude::{triton_vm, twenty_first};
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::chunk_dictionary::ChunkDictionary;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::get_swbf_indices;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;

use crate::models::blockchain::transaction::utxo::Utxo;

use crate::models::blockchain::shared::Hash;
use crate::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;

use crate::models::blockchain::transaction::{
    transaction_kernel::TransactionKernel, PrimitiveWitness,
};
use crate::models::proof_abstractions::SecretWitness;

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
    pub input_utxos: SaltedUtxos,
    pub membership_proofs: Vec<MsMembershipProof>,
    pub aocl: MmrAccumulator<Hash>,
    pub swbfi: MmrAccumulator<Hash>,
    pub swbfa_hash: Digest,
    pub kernel: TransactionKernel,
}

impl RemovalRecordsIntegrityWitness {
    pub fn new(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            input_utxos: primitive_witness.input_utxos.clone(),
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
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );

        // set digests
        let digests = vec![
            self.kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            self.kernel.mast_path(TransactionKernelField::InputUtxos),
        ]
        .concat();

        NonDeterminism::default()
            .with_ram(memory)
            .with_digests(digests)
    }

    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.kernel.mast_hash().reversed().values().to_vec())
    }

    fn program(&self) -> triton_vm::prelude::Program {
        RemovalRecordsIntegrity {}.program()
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
            for (chunk_index, (mmrmp, chunk)) in target_chunks.iter() {
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

        let salted_utxos = SaltedUtxos::new(input_utxos);

        Ok(RemovalRecordsIntegrityWitness {
            input_utxos: salted_utxos,
            membership_proofs,
            aocl,
            swbfi,
            swbfa_hash,
            kernel,
        })
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
