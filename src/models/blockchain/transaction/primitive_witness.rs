use std::time::{SystemTime, UNIX_EPOCH};

use get_size::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use proptest::{
    arbitrary::Arbitrary,
    collection::vec,
    strategy::{BoxedStrategy, Strategy},
};
use proptest_arbitrary_interop::arb;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    twenty_first::{
        shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
        util_types::algebraic_hasher::AlgebraicHasher,
    },
    Digest,
};

use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::{
    models::blockchain::type_scripts::native_currency::native_currency_program,
    util_types::mutator_set::{
        msa_and_records::MsaAndRecords,
        mutator_set_trait::{commit, MutatorSet},
    },
    Hash,
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
    pub fn transaction_inputs_from_address_seeds_and_amounts(
        address_seeds: &[Digest],
        input_amounts: &[NeptuneCoins],
    ) -> (Vec<Utxo>, Vec<LockScript>, Vec<Vec<BFieldElement>>) {
        let input_spending_keys = address_seeds
            .iter()
            .map(|address_seed| generation_address::SpendingKey::derive_from_seed(*address_seed))
            .collect_vec();
        let input_lock_scripts = input_spending_keys
            .iter()
            .map(|spending_key| spending_key.to_address().lock_script())
            .collect_vec();
        let input_lock_script_witnesses = input_spending_keys
            .iter()
            .map(|spending_key| spending_key.unlock_key.values().to_vec())
            .collect_vec();

        let input_utxos = input_lock_scripts
            .iter()
            .zip(input_amounts)
            .map(|(lock_script, amount)| Utxo::new(lock_script.clone(), amount.to_native_coins()))
            .collect_vec();
        (input_utxos, input_lock_scripts, input_lock_script_witnesses)
    }

    pub fn valid_transaction_outputs_from_amounts_and_address_seeds(
        total_inputs: NeptuneCoins,
        maybe_coinbase: Option<NeptuneCoins>,
        fee: &mut NeptuneCoins,
        output_amounts: &mut [NeptuneCoins],
        address_seeds: &[Digest],
    ) -> Vec<Utxo> {
        let mut total_outputs = output_amounts.iter().cloned().sum::<NeptuneCoins>();
        let mut some_coinbase = match maybe_coinbase {
            Some(coinbase) => coinbase,
            None => NeptuneCoins::zero(),
        };
        while total_inputs < total_outputs + *fee + some_coinbase {
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
        address_seeds
            .iter()
            .zip(output_amounts)
            .map(|(seed, amount)| {
                Utxo::new(
                    generation_address::SpendingKey::derive_from_seed(*seed)
                        .to_address()
                        .lock_script(),
                    amount.to_native_coins(),
                )
            })
            .collect_vec()
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
                    input_address_seeds,
                    input_amounts,
                    output_address_seeds,
                    mut output_amounts,
                    public_announcements,
                    mut fee,
                    maybe_coinbase,
                )| {
                    let (input_utxos, input_lock_scripts, input_lock_script_witnesses) =
                        Self::transaction_inputs_from_address_seeds_and_amounts(
                            &input_address_seeds,
                            &input_amounts,
                        );
                    let total_inputs = input_amounts.iter().copied().sum::<NeptuneCoins>();
                    let output_utxos =
                        Self::valid_transaction_outputs_from_amounts_and_address_seeds(
                            total_inputs,
                            maybe_coinbase,
                            &mut fee,
                            &mut output_amounts,
                            &output_address_seeds,
                        );
                    arbitrary_primitive_witness_with(
                        &input_utxos,
                        &input_lock_scripts,
                        &input_lock_script_witnesses,
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
    input_lock_scripts: &[LockScript],
    input_lock_script_witnesses: &[Vec<BFieldElement>],
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
    let input_lock_scripts = input_lock_scripts.to_vec();
    let input_lock_script_witnesses = input_lock_script_witnesses.to_vec();

    // unwrap:
    //  - sender randomness (input)
    //  - receiver preimage (input)
    //  - sender randomness (output)
    //  - receiver preimage (output)
    //  - aocl size
    (
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<Digest>(), num_outputs),
        vec(arb::<Digest>(), num_outputs),
        0u64..=u64::MAX,
    )
        .prop_flat_map(
            move |(
                mut sender_randomnesses_input,
                mut receiver_preimages_input,
                sender_randomnesses_output,
                receiver_preimages_output,
                aocl_size,
            )| {
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
                let input_triples = input_triples.clone();
                let input_lock_scripts = input_lock_scripts.to_vec();
                let input_lock_script_witnesses = input_lock_script_witnesses.to_vec();
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
                        let input_utxos = input_utxos.clone();
                        let input_removal_records = input_removal_records.clone();
                        let input_membership_proofs = input_membership_proofs.clone();
                        let type_scripts = type_scripts.clone();
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
                        let input_utxos = input_utxos.clone();
                        let input_removal_records = input_removal_records.clone();
                        let input_membership_proofs = input_membership_proofs.clone();
                        let type_scripts = type_scripts.clone();
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
                            lock_script_witnesses: input_lock_script_witnesses.clone(),
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
