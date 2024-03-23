use get_size::GetSize;
use itertools::Itertools;
use num_traits::CheckedSub;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tasm_lib::{
    structure::tasm_object::TasmObject,
    twenty_first::{
        shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
        util_types::algebraic_hasher::AlgebraicHasher,
    },
    Digest,
};

use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::Hash;
use crate::{
    models::{blockchain::type_scripts::TypeScript, state::wallet::address::generation_address},
    util_types::mutator_set::{
        ms_membership_proof::MsMembershipProof, mutator_set_accumulator::MutatorSetAccumulator,
    },
};

use super::{
    transaction_kernel::TransactionKernel,
    utxo::{LockScript, Utxo},
};

/// `SaltedUtxos` is a struct for representing a list of UTXOs in a witness object when it
/// is desirable to associate a random but consistent salt for the entire list of UTXOs.
/// This situation arises when two distinct consensus programs prove different features
/// about the same list of UTXOs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, GetSize, BFieldCodec, TasmObject)]
pub struct SaltedUtxos {
    pub utxos: Vec<Utxo>,
    pub salt: [BFieldElement; 3],
}

impl SaltedUtxos {
    /// Takes a Vec of UTXOs and returns a `SaltedUtxos` object. The salt comes from
    /// `thread_rng`.
    pub fn new(utxos: Vec<Utxo>) -> Self {
        Self {
            utxos,
            salt: thread_rng().gen(),
        }
    }

    /// Generate a `SaltedUtxos` object that contains no UTXOs. There is a random salt
    /// though, which comes from `thread_rng`.
    pub fn empty() -> Self {
        Self {
            utxos: vec![],
            salt: thread_rng().gen(),
        }
    }

    /// Concatenate two `SaltedUtxos` objects. Derives the salt from hashing the
    /// concatenation of that of the operands.
    pub fn cat(&self, other: SaltedUtxos) -> Self {
        Self {
            utxos: [self.utxos.clone(), other.utxos].concat(),
            salt: Hash::hash_varlen(&[self.salt, other.salt].concat().to_vec()).values()[0..3]
                .try_into()
                .unwrap(),
        }
    }
}

/// The raw witness is the most primitive type of transaction witness.
/// It exposes secret data and is therefore not for broadcasting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct PrimitiveWitness {
    pub input_utxos: SaltedUtxos,
    pub input_lock_scripts: Vec<LockScript>,
    pub type_scripts: Vec<TypeScript>,
    pub lock_script_witnesses: Vec<Vec<BFieldElement>>,
    pub input_membership_proofs: Vec<MsMembershipProof>,
    pub output_utxos: SaltedUtxos,
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

    /// Obtain a *balanced* set of outputs (and fee) given a fixed total input amount
    /// and (optional) coinbase. This function takes a suggestion for the output
    /// amounts and fee and mutates these values until they satisfy the no-inflation
    /// requirement. This method assumes that the total input amount and coinbase (if
    /// set) can be safely added.
    pub fn find_balanced_output_amounts_and_fee(
        total_input_amount: NeptuneCoins,
        coinbase: Option<NeptuneCoins>,
        output_amounts_suggestion: &mut [NeptuneCoins],
        fee_suggestion: &mut NeptuneCoins,
    ) {
        let mut total_output_amount = output_amounts_suggestion
            .iter()
            .cloned()
            .sum::<NeptuneCoins>();
        let total_input_plus_coinbase =
            total_input_amount + coinbase.unwrap_or_else(|| NeptuneCoins::new(0));
        let mut inflationary = total_output_amount.safe_add(*fee_suggestion).is_none()
            || (total_output_amount + *fee_suggestion != total_input_plus_coinbase);
        while inflationary {
            for amount in output_amounts_suggestion.iter_mut() {
                amount.div_two();
            }
            total_output_amount = output_amounts_suggestion
                .iter()
                .cloned()
                .sum::<NeptuneCoins>();
            match total_input_plus_coinbase.checked_sub(&total_output_amount) {
                Some(number) => {
                    *fee_suggestion = number;
                    inflationary = false;
                }
                None => {
                    inflationary = true;
                }
            }
        }
    }

    /// Generate valid output UTXOs from the amounts and seeds for the addresses
    pub fn valid_transaction_outputs_from_amounts_and_address_seeds(
        output_amounts: &[NeptuneCoins],
        address_seeds: &[Digest],
    ) -> Vec<Utxo> {
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

// Commented out during async storage refactor due to
// non-async tasm-lib trait conflicts.
//
// Seems like this belongs in a tests module anyway?

/*
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
                    Self::find_balanced_output_amounts_and_fee(
                        total_inputs,
                        maybe_coinbase,
                        &mut output_amounts,
                        &mut fee,
                    );
                    assert_eq!(
                        total_inputs + maybe_coinbase.unwrap_or(NeptuneCoins::new(0)),
                        output_amounts.iter().cloned().sum::<NeptuneCoins>() + fee
                    );
                    let output_utxos =
                        Self::valid_transaction_outputs_from_amounts_and_address_seeds(
                            &output_amounts,
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
    //  - salt (input)
    //  - sender randomness (output)
    //  - receiver preimage (output)
    //  - salt (output)
    //  - aocl size
    (
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<BFieldElement>(), 3),
        vec(arb::<Digest>(), num_outputs),
        vec(arb::<Digest>(), num_outputs),
        vec(arb::<BFieldElement>(), 3),
        0u64..=u64::MAX,
    )
        .prop_flat_map(
            move |(
                mut sender_randomnesses_input,
                mut receiver_preimages_input,
                inputs_salt,
                sender_randomnesses_output,
                receiver_preimages_output,
                outputs_salt,
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

                        let type_scripts = vec![TypeScript::new(NativeCurrency.program())];

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
                            input_utxos: SaltedUtxos {
                                utxos: input_utxos.clone(),
                                salt: inputs_salt.clone().try_into().unwrap(),
                            },
                            input_membership_proofs: input_membership_proofs.clone(),
                            type_scripts: type_scripts.clone(),
                            lock_script_witnesses: input_lock_script_witnesses.clone(),
                            output_utxos: SaltedUtxos {
                                utxos: output_utxos.clone(),
                                salt: outputs_salt.clone().try_into().unwrap(),
                            },
                            mutator_set_accumulator: mutator_set_accumulator.clone(),
                            kernel,
                        }
                    })
                    .boxed()
            },
        )
        .boxed()
}
*/

#[cfg(test)]
mod test {
    use super::PrimitiveWitness;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;

    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    // temporarily disabling this test for async storage refactor
    /*

    #[proptest(cases = 5)]
    async fn arbitrary_transaction_is_valid(
        #[strategy(1usize..3)] _num_inputs: usize,
        #[strategy(1usize..3)] _num_outputs: usize,
        #[strategy(0usize..3)] _num_public_announcements: usize
        #[strategy(PrimitiveWitness::arbitrary_with((#_num_inputs, #_num_outputs, #_num_public_announcements)))]
        transaction_primitive_witness: PrimitiveWitness,
    ) {
        let kernel_hash = transaction_primitive_witness.kernel.mast_hash();
        prop_assert!(
            TransactionValidationLogic::from(transaction_primitive_witness)
                .vast
                .verify(kernel_hash)
        );
    }
    */

    #[proptest]
    fn amounts_balancer_works_with_coinbase(
        #[strategy(arb::<NeptuneCoins>())] total_input_amount: NeptuneCoins,
        #[strategy(arb::<NeptuneCoins>())] coinbase: NeptuneCoins,
        #[strategy(vec(arb::<NeptuneCoins>(), 1..4))] mut output_amounts: Vec<NeptuneCoins>,
        #[strategy(arb::<NeptuneCoins>())] mut fee: NeptuneCoins,
    ) {
        PrimitiveWitness::find_balanced_output_amounts_and_fee(
            total_input_amount,
            Some(coinbase),
            &mut output_amounts,
            &mut fee,
        );
        prop_assert!(
            total_input_amount.safe_add(coinbase).unwrap()
                == output_amounts
                    .iter()
                    .cloned()
                    .sum::<NeptuneCoins>()
                    .safe_add(fee)
                    .unwrap()
        );
    }

    #[proptest]
    fn amounts_balancer_works_without_coinbase(
        #[strategy(arb::<NeptuneCoins>())] total_input_amount: NeptuneCoins,
        #[strategy(vec(arb::<NeptuneCoins>(), 1..4))] mut output_amounts: Vec<NeptuneCoins>,
        #[strategy(arb::<NeptuneCoins>())] mut fee: NeptuneCoins,
    ) {
        PrimitiveWitness::find_balanced_output_amounts_and_fee(
            total_input_amount,
            None,
            &mut output_amounts,
            &mut fee,
        );
        prop_assert!(
            total_input_amount
                == output_amounts
                    .iter()
                    .cloned()
                    .sum::<NeptuneCoins>()
                    .safe_add(fee)
                    .unwrap()
        );
    }
}
