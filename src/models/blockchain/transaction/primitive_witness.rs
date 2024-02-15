use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use arbitrary::Arbitrary;
use get_size::GetSize;
use itertools::Itertools;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use tasm_lib::{
    twenty_first::{
        shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
        util_types::{
            algebraic_hasher::AlgebraicHasher,
            mmr::{
                mmr_accumulator::MmrAccumulator, mmr_membership_proof::MmrMembershipProof,
                mmr_trait::Mmr,
            },
        },
    },
    Digest,
};

use crate::{
    models::blockchain::type_scripts::native_currency::{
        native_currency_program, NATIVE_CURRENCY_TYPE_SCRIPT_DIGEST,
    },
    util_types::mutator_set::{
        chunk::Chunk,
        chunk_dictionary::ChunkDictionary,
        mutator_set_kernel::{get_swbf_indices, MutatorSetKernel},
        mutator_set_trait::{commit, MutatorSet},
        removal_record::{AbsoluteIndexSet, RemovalRecord},
        shared::{BATCH_SIZE, CHUNK_SIZE},
    },
    Hash,
};
use crate::{
    models::blockchain::type_scripts::neptune_coins::NeptuneCoins,
    twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index,
};
use crate::{
    models::{blockchain::type_scripts::TypeScript, state::wallet::address::generation_address},
    util_types::mutator_set::{
        ms_membership_proof::MsMembershipProof, mutator_set_accumulator::MutatorSetAccumulator,
    },
};

use super::{
    transaction_kernel::TransactionKernel,
    utxo::{Coin, LockScript, Utxo},
};

/// The raw witness is the most primitive type of transaction witness.
/// It exposes secret data and is therefore not for broadcasting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct PrimitiveWitness {
    pub input_utxos: Vec<Utxo>,
    pub input_lock_scripts: Vec<LockScript>,
    pub type_scripts: Vec<TypeScript>,
    pub lock_script_witnesses: Vec<Vec<BFieldElement>>,
    pub input_membership_proofs: Vec<MsMembershipProof>,
    pub output_utxos: Vec<Utxo>,
    pub mutator_set_accumulator: MutatorSetAccumulator,
    pub kernel: TransactionKernel,
}

impl PrimitiveWitness {
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
                assert!(mp.verify(&dummy_peaks, leaf, leaf_count).0);
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
            assert!(mp.verify(&mmra.get_peaks(), leaf, mmra.count_leaves()).0);
        }

        (mmra, mps)
    }

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
                if nodes.get(&wi_odd).is_none() {
                    nodes.insert(wi_odd, rng.gen::<Digest>());
                }
                let wi_even = wi_odd ^ 1;
                if nodes.get(&wi_even).is_none() {
                    nodes.insert(wi_even, rng.gen::<Digest>());
                }
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

    fn pseudorandom_mmra_of_given_size_with_mps_at_indices(
        seed: [u8; 32],
        size: u64,
        leafs: &[Digest],
        indices: &[u64],
    ) -> (MmrAccumulator<Hash>, Vec<MmrMembershipProof<Hash>>) {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut tree_heights = vec![];
        for h in (0..64).rev() {
            if size & (1 << h) != 0 {
                tree_heights.push(h);
            }
        }

        let mut peaks = vec![];
        let mut membership_proofs = vec![];
        let leaf_and_various_indices = leafs
            .iter()
            .zip(indices.iter())
            .map(|(&l, &idx)| (l, idx, leaf_index_to_mt_index_and_peak_index(idx, size)));
        for (i, tree_height) in tree_heights.into_iter().enumerate() {
            let leafs_and_indices = leaf_and_various_indices
                .clone()
                .filter(|(_l, _idx, (_mti, pki))| *pki == i as u32)
                .map(|(l, _idx, (mti, _pki))| (l, mti))
                .collect_vec();
            let (root, paths) = Self::pseudorandom_merkle_root_with_authentication_paths(
                rng.gen(),
                tree_height,
                &leafs_and_indices,
            );
            peaks.push(root);
            membership_proofs.append(
                &mut leafs_and_indices
                    .into_iter()
                    .zip(paths.into_iter())
                    .map(|((_l, idx), path)| MmrMembershipProof::new(idx, path))
                    .collect_vec(),
            );
        }
        (MmrAccumulator::init(peaks, size), membership_proofs)
    }
}

impl<'a> Arbitrary<'a> for PrimitiveWitness {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_inputs = u.int_in_range(0..=4)?;
        let num_outputs = u.int_in_range(0..=4)?;
        let num_public_announcements = u.int_in_range(0..=2)?;
        let sender_spending_keys = (0..num_inputs)
            .map(|_| {
                generation_address::SpendingKey::derive_from_seed(u.arbitrary::<Digest>().unwrap())
            })
            .collect_vec();
        let sender_receiving_addresses = sender_spending_keys
            .iter()
            .map(|ssk| ssk.to_address())
            .collect_vec();
        let input_lock_scripts = sender_receiving_addresses
            .iter()
            .map(|sra| sra.lock_script())
            .collect_vec();
        let lock_script_witnesses = sender_spending_keys
            .iter()
            .map(|ssk| ssk.unlock_key.values().to_vec())
            .collect_vec();
        let input_amounts = (0..num_inputs)
            .map(|_| u.arbitrary::<NeptuneCoins>().unwrap())
            .collect_vec();
        let total_inputs = input_amounts.iter().cloned().sum::<NeptuneCoins>();
        let mut output_fractions = (0..=num_outputs)
            .map(|_| u.int_in_range(0..=99).unwrap() as f64)
            .collect_vec();
        let output_sum = output_fractions.iter().cloned().sum::<f64>();
        output_fractions.iter_mut().for_each(|f| *f /= output_sum);
        let input_utxos = input_lock_scripts
            .iter()
            .map(|ils| {
                Utxo::new(
                    ils.clone(),
                    vec![Coin {
                        type_script_hash: NATIVE_CURRENCY_TYPE_SCRIPT_DIGEST,
                        state: u.arbitrary::<NeptuneCoins>().unwrap().encode(),
                    }],
                )
            })
            .collect_vec();
        let input_triples = input_utxos
            .iter()
            .map(|utxo| {
                (
                    Hash::hash(utxo),
                    u.arbitrary::<Digest>().unwrap(),
                    u.arbitrary::<Digest>().unwrap(),
                )
            })
            .collect_vec();
        let input_commitments = input_triples
            .iter()
            .map(|(item, sender_randomness, receiver_preimage)| {
                commit(*item, *sender_randomness, Hash::hash(receiver_preimage))
            })
            .map(|ar| ar.canonical_commitment)
            .collect_vec();
        let (aocl_mmr, aocl_authentication_paths) =
            Self::pseudorandom_mmra_with_mps(u.arbitrary().unwrap(), &input_commitments);
        let all_index_sets = input_triples
            .iter()
            .zip(aocl_authentication_paths.iter())
            .map(
                |((item, sender_randomness, receiver_preimage), authentication_path)| {
                    get_swbf_indices(
                        *item,
                        *sender_randomness,
                        *receiver_preimage,
                        authentication_path.leaf_index,
                    )
                },
            )
            .collect_vec();
        let mut all_indices = all_index_sets.iter().flatten().cloned().collect_vec();
        all_indices.sort();
        let mut all_chunk_indices = all_indices
            .iter()
            .map(|index| index / (CHUNK_SIZE as u128))
            .map(|index| index as u64)
            .collect_vec();
        all_chunk_indices.dedup();
        let mmr_chunk_indices = all_chunk_indices
            .iter()
            .cloned()
            .filter(|ci| *ci < aocl_mmr.count_leaves() / (BATCH_SIZE as u64))
            .collect_vec();
        let mmr_chunks = (0..mmr_chunk_indices.len())
            .map(|_| u.arbitrary::<Chunk>().unwrap())
            .collect_vec();
        let (swbf_mmr, swbf_authentication_paths) =
            Self::pseudorandom_mmra_of_given_size_with_mps_at_indices(
                u.arbitrary().unwrap(),
                aocl_mmr.count_leaves() / (BATCH_SIZE as u64),
                &mmr_chunks.iter().map(Hash::hash).collect_vec(),
                &mmr_chunk_indices,
            );
        let chunk_dictionary: HashMap<u64, (MmrMembershipProof<Hash>, Chunk)> = mmr_chunk_indices
            .iter()
            .cloned()
            .zip(swbf_authentication_paths.into_iter().zip(mmr_chunks))
            .collect();
        let personalized_chunk_dictionaries = all_index_sets
            .iter()
            .map(|index_set| {
                let mut is = index_set
                    .iter()
                    .map(|index| index / (BATCH_SIZE as u128))
                    .map(|index| index as u64)
                    .collect_vec();
                is.sort();
                is.dedup();
                is
            })
            .map(|chunk_indices| {
                ChunkDictionary::new(
                    chunk_indices
                        .iter()
                        .map(|chunk_index| {
                            (
                                *chunk_index,
                                chunk_dictionary.get(chunk_index).cloned().unwrap(),
                            )
                        })
                        .collect::<HashMap<u64, (MmrMembershipProof<Hash>, Chunk)>>(),
                )
            })
            .collect_vec();
        let input_membership_proofs = input_triples
            .iter()
            .zip(aocl_authentication_paths.iter())
            .zip(personalized_chunk_dictionaries.iter())
            .map(
                |(((_item, sender_randomness, receiver_preimage), auth_path), target_chunks)| {
                    MsMembershipProof {
                        sender_randomness: *sender_randomness,
                        receiver_preimage: *receiver_preimage,
                        auth_path_aocl: auth_path.clone(),
                        target_chunks: target_chunks.clone(),
                    }
                },
            )
            .collect_vec();
        let input_removal_records = all_index_sets
            .iter()
            .zip(personalized_chunk_dictionaries.iter())
            .map(|(index_set, target_chunks)| RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new(index_set),
                target_chunks: target_chunks.clone(),
            })
            .collect_vec();
        let type_scripts = vec![TypeScript::new(native_currency_program())];
        let output_utxos = output_fractions
            .iter()
            .take(num_outputs)
            .map(|f| Utxo {
                lock_script_hash: u.arbitrary().unwrap(),
                coins: vec![Coin {
                    type_script_hash: NATIVE_CURRENCY_TYPE_SCRIPT_DIGEST,
                    state: NeptuneCoins::new((f * total_inputs.to_nau_f64()) as u32).encode(),
                }],
            })
            .collect_vec();
        let output_commitments = output_utxos
            .iter()
            .map(|utxo| {
                commit(
                    Hash::hash(utxo),
                    u.arbitrary().unwrap(),
                    u.arbitrary().unwrap(),
                )
            })
            .collect_vec();
        let mutator_set_accumulator = MutatorSetAccumulator {
            kernel: MutatorSetKernel {
                aocl: aocl_mmr,
                swbf_inactive: swbf_mmr,
                swbf_active: u.arbitrary()?,
            },
        };
        let has_coinbase: bool = u.arbitrary()?;
        let coinbase = if !has_coinbase {
            None
        } else {
            let fraction_to_coinbase: f64 = u.int_in_range(0..=99)? as f64 / 100.0;
            let coinbase_amount =
                total_inputs.to_nau_f64() * output_fractions.last().unwrap() * fraction_to_coinbase;
            Some(NeptuneCoins::new(coinbase_amount as u32))
        };
        let fee = match coinbase {
            Some(cb) => {
                NeptuneCoins::new(
                    (total_inputs.to_nau_f64() * output_fractions.last().unwrap()) as u32,
                ) - cb
            }
            None => NeptuneCoins::new(
                (total_inputs.to_nau_f64() * output_fractions.last().unwrap()) as u32,
            ),
        };
        let public_announcements = (0..num_public_announcements)
            .map(|_| u.arbitrary().unwrap())
            .collect_vec();
        let kernel = TransactionKernel {
            inputs: input_removal_records,
            outputs: output_commitments,
            public_announcements,
            fee,
            coinbase,
            timestamp: BFieldElement::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            ),
            mutator_set_hash: mutator_set_accumulator.hash(),
        };
        let primitive_witness = PrimitiveWitness {
            input_lock_scripts,
            input_utxos,
            input_membership_proofs,
            type_scripts,
            lock_script_witnesses,
            output_utxos,
            mutator_set_accumulator,
            kernel,
        };
        Ok(primitive_witness)
    }
}
