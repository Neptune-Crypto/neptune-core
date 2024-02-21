use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use get_size::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use proptest::{
    arbitrary::Arbitrary,
    collection::vec,
    strategy::{BoxedStrategy, Strategy},
};
use proptest_arbitrary_interop::arb;
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
        msa_and_records::MsaAndRecords,
        mutator_set_trait::{commit, MutatorSet},
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
    utxo::{LockScript, Utxo},
    PublicAnnouncement,
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
}

impl Arbitrary for PrimitiveWitness {
    type Parameters = (usize, usize, usize);
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
        let (num_inputs, num_outputs, num_public_announcements) = parameters;

        // unwrap:
        //  - lock script preimages (inputs)
        //  - amounts (inputs)
        //  - lock script preimages (outputs)
        //  - amounts (outputs)
        //  - public announcements
        //  - fee
        //  - coinbase (option)
        (
            vec(arb::<Digest>(), num_inputs),
            vec(arb::<NeptuneCoins>(), num_inputs),
            vec(arb::<Digest>(), num_outputs),
            vec(arb::<NeptuneCoins>(), num_outputs),
            vec(arb::<PublicAnnouncement>(), num_public_announcements),
            arb::<NeptuneCoins>(),
            arb::<Option<NeptuneCoins>>(),
        )
            .prop_flat_map(
                |(
                    input_lock_script_preimages,
                    input_amounts,
                    output_lock_script_preimages,
                    mut output_amounts,
                    public_announcements,
                    mut fee,
                    maybe_coinbase,
                )| {
                    let input_utxos = input_lock_script_preimages
                        .into_iter()
                        .zip(input_amounts)
                        .map(|(lock_script_preimage, amount)| {
                            Utxo::new(
                                generation_address::SpendingKey::derive_from_seed(
                                    lock_script_preimage,
                                )
                                .to_address()
                                .lock_script(),
                                amount.to_native_coins(),
                            )
                        })
                        .collect_vec();
                    let total_inputs = input_utxos
                        .iter()
                        .flat_map(|utxo| utxo.coins.clone())
                        .filter(|coin| coin.type_script_hash == NATIVE_CURRENCY_TYPE_SCRIPT_DIGEST)
                        .map(|coin| coin.state)
                        .map(|state| NeptuneCoins::decode(&state))
                        .filter(|r| r.is_ok())
                        .map(|r| *r.unwrap())
                        .sum::<NeptuneCoins>();
                    let mut total_outputs = output_amounts.iter().cloned().sum::<NeptuneCoins>();
                    let mut some_coinbase = match maybe_coinbase {
                        Some(coinbase) => coinbase,
                        None => NeptuneCoins::zero(),
                    };
                    while total_inputs < total_outputs + fee + some_coinbase {
                        for amount in output_amounts.iter_mut() {
                            amount.div_two();
                        }
                        if let Some(mut coinbase) = maybe_coinbase {
                            coinbase.div_two();
                            some_coinbase.div_two();
                        }
                        fee.div_two();
                        total_outputs = output_amounts.iter().cloned().sum::<NeptuneCoins>();
                    }
                    let output_utxos = output_lock_script_preimages
                        .into_iter()
                        .zip(output_amounts)
                        .map(|(lock_script_preimage, amount)| {
                            Utxo::new(
                                generation_address::SpendingKey::derive_from_seed(
                                    lock_script_preimage,
                                )
                                .to_address()
                                .lock_script(),
                                amount.to_native_coins(),
                            )
                        })
                        .collect_vec();
                    arbitrary_primitive_witness_with(
                        &input_utxos,
                        &output_utxos,
                        &public_announcements,
                        fee,
                        maybe_coinbase,
                    )
                },
            )
            .boxed()
    }
}

pub(crate) fn arbitrary_primitive_witness_with(
    input_utxos: &[Utxo],
    output_utxos: &[Utxo],
    public_announcements: &[PublicAnnouncement],
    fee: NeptuneCoins,
    coinbase: Option<NeptuneCoins>,
) -> BoxedStrategy<PrimitiveWitness> {
    let num_inputs = input_utxos.len();
    let num_outputs = output_utxos.len();
    let input_utxos = input_utxos.to_vec();
    let output_utxos = output_utxos.to_vec();
    let public_announcements = public_announcements.to_vec();

    // unwrap:
    //  - spending key seeds
    //  - sender randomness (input)
    //  - receiver preimage (input)
    //  - sender randomness (output)
    //  - receiver preimage (output)
    //  - aocl size
    (
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<Digest>(), num_outputs),
        vec(arb::<Digest>(), num_outputs),
        0u64..=u64::MAX,
    )
        .prop_flat_map(
            move |(
                mut spending_key_seeds,
                mut sender_randomnesses_input,
                mut receiver_preimages_input,
                sender_randomnesses_output,
                receiver_preimages_output,
                aocl_size,
            )| {
                let sender_spending_keys = (0..num_inputs)
                    .map(|_| {
                        generation_address::SpendingKey::derive_from_seed(
                            spending_key_seeds.pop().unwrap(),
                        )
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

                // prepare to unwrap
                let lock_script_witnesses = lock_script_witnesses.clone();
                let input_lock_scripts = input_lock_scripts.clone();
                let input_utxos = input_utxos.clone();
                let output_utxos = output_utxos.clone();
                let public_announcements = public_announcements.clone();

                let input_triples = input_utxos
                    .iter()
                    .map(|utxo| {
                        (
                            Hash::hash(utxo),
                            sender_randomnesses_input.pop().unwrap(),
                            receiver_preimages_input.pop().unwrap(),
                        )
                    })
                    .collect_vec();

                // prepare to unwrap
                let input_lock_scripts = input_lock_scripts.clone();
                let lock_script_witnesses = lock_script_witnesses.clone();
                let input_triples = input_triples.clone();
                let input_utxos = input_utxos.clone();
                let output_utxos = output_utxos.clone();
                let public_announcements = public_announcements.clone();

                // unwrap random mutator set accumulator with membership proofs and removal records
                MsaAndRecords::arbitrary_with((input_triples, aocl_size))
                    .prop_map(move |msa_and_records| {
                        let mutator_set_accumulator = msa_and_records.mutator_set_accumulator;
                        let input_membership_proofs = msa_and_records.membership_proofs;
                        let input_removal_records = msa_and_records.removal_records;

                        let type_scripts = vec![TypeScript::new(native_currency_program())];

                        // prepare to unwrap
                        let input_lock_scripts = input_lock_scripts.clone();
                        let input_utxos = input_utxos.clone();
                        let input_removal_records = input_removal_records.clone();
                        let input_membership_proofs = input_membership_proofs.clone();
                        let type_scripts = type_scripts.clone();
                        let lock_script_witnesses = lock_script_witnesses.clone();
                        let output_utxos = output_utxos.clone();
                        let public_announcements = public_announcements.clone();
                        let mut sender_randomnesses_output = sender_randomnesses_output.clone();
                        let mut receiver_preimages_output = receiver_preimages_output.clone();

                        let output_commitments = output_utxos
                            .iter()
                            .map(|utxo| {
                                commit(
                                    Hash::hash(utxo),
                                    sender_randomnesses_output.pop().unwrap(),
                                    receiver_preimages_output.pop().unwrap().hash::<Hash>(),
                                )
                            })
                            .collect_vec();

                        // prepare to unwrap
                        let input_lock_scripts = input_lock_scripts.clone();
                        let input_utxos = input_utxos.clone();
                        let input_removal_records = input_removal_records.clone();
                        let input_membership_proofs = input_membership_proofs.clone();
                        let type_scripts = type_scripts.clone();
                        let lock_script_witnesses = lock_script_witnesses.clone();
                        let output_utxos = output_utxos.clone();
                        let public_announcements = public_announcements.clone();

                        let kernel = TransactionKernel {
                            inputs: input_removal_records.clone(),
                            outputs: output_commitments.clone(),
                            public_announcements: public_announcements.to_vec(),
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

                        PrimitiveWitness {
                            input_lock_scripts: input_lock_scripts.clone(),
                            input_utxos: input_utxos.clone(),
                            input_membership_proofs: input_membership_proofs.clone(),
                            type_scripts: type_scripts.clone(),
                            lock_script_witnesses: lock_script_witnesses.clone(),
                            output_utxos: output_utxos.clone(),
                            mutator_set_accumulator: mutator_set_accumulator.clone(),
                            kernel,
                        }
                    })
                    .boxed()
            },
        )
        .boxed()
}

#[cfg(test)]
mod test {
    use crate::models::blockchain::transaction::validity::TransactionValidationLogic;

    use super::PrimitiveWitness;
    use proptest::prop_assert;
    use test_strategy::proptest;

    #[proptest(cases = 1)]
    fn arbitrary_transaction_is_valid(
        #[strategy(1usize..3)] _num_inputs: usize,
        #[strategy(1usize..3)] _num_outputs: usize,
        #[strategy(0usize..3)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with((#_num_inputs, #_num_outputs, #_num_public_announcements)))]
        transaction_primitive_witness: PrimitiveWitness,
    ) {
        prop_assert!(TransactionValidationLogic::new_from_primitive_witness(
            &transaction_primitive_witness
        )
        .verify());
    }
}
