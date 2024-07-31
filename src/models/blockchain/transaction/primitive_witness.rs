use std::collections::HashMap;
use std::fmt::Display;

use get_size::GetSize;
use itertools::Itertools;
use num_traits::CheckedSub;
use proptest::{
    arbitrary::Arbitrary,
    collection::vec,
    strategy::{BoxedStrategy, Strategy},
};
use proptest_arbitrary_interop::arb;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tasm_lib::{
    structure::tasm_object::TasmObject,
    triton_vm::program::NonDeterminism,
    twenty_first::{
        math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
        util_types::algebraic_hasher::AlgebraicHasher,
    },
    Digest,
};
use tracing::{debug, warn};

use crate::{
    models::blockchain::type_scripts::{
        native_currency::NativeCurrencyWitness, neptune_coins::NeptuneCoins, TypeScriptWitness,
    },
    util_types::mutator_set::commit,
};
use crate::{
    models::{
        blockchain::type_scripts::{TypeScript, TypeScriptAndWitness},
        proof_abstractions::{mast_hash::MastHash, timestamp::Timestamp},
        state::wallet::address::generation_address,
    },
    util_types::mutator_set::{
        ms_membership_proof::MsMembershipProof, mutator_set_accumulator::MutatorSetAccumulator,
    },
};
use crate::{util_types::mutator_set::msa_and_records::MsaAndRecords, Hash};

use super::lock_script::LockScript;
use super::lock_script::LockScriptAndWitness;
use super::{transaction_kernel::TransactionKernel, utxo::Utxo, PublicAnnouncement};

/// `SaltedUtxos` is a struct for representing a list of UTXOs in a witness object when it
/// is desirable to associate a random but consistent salt for the entire list of UTXOs.
/// This situation arises when two distinct consensus programs prove different features
/// about the same list of UTXOs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, GetSize, BFieldCodec, TasmObject)]
pub struct SaltedUtxos {
    pub utxos: Vec<Utxo>,
    pub salt: [BFieldElement; 3],
}

impl Display for SaltedUtxos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.utxos
                .iter()
                .enumerate()
                .map(|(i, utxo)| format!("\nutxo {i}: {utxo}"))
                .join("")
        )
    }
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
    pub input_membership_proofs: Vec<MsMembershipProof>,
    pub lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
    pub type_scripts_and_witnesses: Vec<TypeScriptAndWitness>,
    pub output_utxos: SaltedUtxos,
    pub output_sender_randomnesses: Vec<Digest>,
    pub output_receiver_digests: Vec<Digest>,
    pub mutator_set_accumulator: MutatorSetAccumulator,
    pub kernel: TransactionKernel,
}

impl Display for PrimitiveWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let coinbase_str = match self.kernel.coinbase {
            Some(cb) => format!("Yes: {cb}"),
            None => "No".to_owned(),
        };
        let utxo_digests = self.input_utxos.utxos.iter().map(Hash::hash);
        write!(
            f,
            "inputs: [{}]\noutputs: [{}]\ncoinbase: {}\nfee: {}\ntxk mast hash: {}\n\ninput canonical commitments:\n{}\n\n",
            self.input_utxos,
            self.output_utxos,
            coinbase_str,
            self.kernel.fee,
            self.kernel.mast_hash(),
            self.input_membership_proofs.iter().zip_eq(utxo_digests).map(|(msmp, utxo_digest)| msmp.addition_record(utxo_digest).canonical_commitment).join("\n")
        )
    }
}

impl PrimitiveWitness {
    pub fn transaction_inputs_from_address_seeds_and_amounts(
        address_seeds: &[Digest],
        input_amounts: &[NeptuneCoins],
    ) -> (Vec<Utxo>, Vec<LockScriptAndWitness>) {
        let input_spending_keys = address_seeds
            .iter()
            .map(|address_seed| generation_address::SpendingKey::derive_from_seed(*address_seed))
            .collect_vec();

        let input_lock_scripts_and_witnesses = input_spending_keys
            .into_iter()
            .map(|spending_key| spending_key.lock_script_and_witness())
            .collect_vec();

        let input_utxos = input_lock_scripts_and_witnesses
            .iter()
            .zip(input_amounts)
            .map(|(lock_script_and_witness, amount)| {
                Utxo::new(
                    LockScript::from(lock_script_and_witness),
                    amount.to_native_coins(),
                )
            })
            .collect_vec();
        (input_utxos, input_lock_scripts_and_witnesses)
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

    /// Verify the transaction directly from the primitive witness, without proofs or
    /// decomposing into subclaims.
    pub async fn validate(&self) -> bool {
        // verify lock scripts
        for lock_script_and_witness in self.lock_scripts_and_witnesses.iter() {
            let lock_script = lock_script_and_witness.program.clone();
            let secret_input = lock_script_and_witness.nondeterminism();

            // The lock script is satisfied if it halts gracefully (i.e.,
            // without crashing). We do not care about the output.
            let public_input = Hash::hash(self).reversed().encode();

            // we wrap triton-vm script execution in spawn_blocking as it
            // could be a lengthy CPU intensive call.
            let result = tokio::task::spawn_blocking(move || {
                lock_script.run(public_input.into(), secret_input)
            })
            .await;

            match result {
                Ok(_) => (),
                Err(err) => {
                    warn!("Failed to verify lock script of transaction. Got: \"{err}\"");
                    return false;
                }
            };
        }

        // Verify correct computation of removal records. Also, collect
        // the removal records' hashes in order to validate them against
        // those provided in the transaction kernel later.
        // We only check internal consistency not removability relative
        // to a given mutator set accumulator.
        let mut witnessed_removal_records = vec![];
        for (input_utxo, msmp) in self
            .input_utxos
            .utxos
            .iter()
            .zip(self.input_membership_proofs.iter())
        {
            let item = Hash::hash(input_utxo);
            // TODO: write these functions in tasm
            if !self.mutator_set_accumulator.verify(item, msmp) {
                warn!(
                    "Cannot generate removal record for an item with an invalid membership proof."
                );
                debug!(
                    "witness mutator set hash: {}",
                    self.mutator_set_accumulator.hash()
                );
                debug!("kernel mutator set hash: {}", self.kernel.mutator_set_hash);
                return false;
            }
            let removal_record = self.mutator_set_accumulator.drop(item, msmp);
            witnessed_removal_records.push(removal_record);
        }

        // collect type script hashes
        let type_script_hashes = self
            .output_utxos
            .utxos
            .iter()
            .flat_map(|utxo| utxo.coins.iter().map(|coin| coin.type_script_hash))
            .sorted_by_key(|d| d.values().map(|b| b.value()))
            .dedup()
            .collect_vec();

        // verify that all type script hashes are represented by the witness's type script list
        let mut type_script_dictionary = HashMap::<Digest, TypeScript>::new();
        for tsaw in self.type_scripts_and_witnesses.iter() {
            let ts = TypeScript::from(tsaw);
            type_script_dictionary.insert(tsaw.program.hash::<Hash>(), ts);
        }
        if !type_script_hashes
            .clone()
            .into_iter()
            .all(|tsh| type_script_dictionary.contains_key(&tsh))
        {
            warn!("Transaction contains input(s) or output(s) with unknown typescript.");
            return false;
        }

        // verify type scripts
        for type_script_hash in type_script_hashes {
            let Some(type_script) = type_script_dictionary.get(&type_script_hash) else {
                warn!("Type script hash not found; should not get here.");
                return false;
            };

            let public_input = self.kernel.mast_hash().encode();
            let secret_input = self
                .kernel
                .mast_sequences()
                .into_iter()
                .flatten()
                .collect_vec();

            // we wrap triton-vm script execution in spawn_blocking as it
            // could be a lengthy CPU intensive call.
            let type_script_clone = (*type_script).clone();
            let result = tokio::task::spawn_blocking(move || {
                type_script_clone
                    .program
                    .run(public_input.into(), NonDeterminism::new(secret_input))
            })
            .await;

            // The type script is satisfied if it halts gracefully, i.e.,
            // without panicking. So we don't care about the output
            if let Err(e) = result {
                warn!(
                    "Type script {} not satisfied for transaction: {}",
                    type_script_hash, e
                );
                return false;
            }
        }

        // Verify that the removal records generated from the primitive
        // witness correspond to the removal records listed in the
        // transaction kernel.
        if witnessed_removal_records
            .iter()
            .map(|rr| Hash::hash_varlen(&rr.encode()))
            .sorted_by_key(|d| d.values().iter().map(|b| b.value()).collect_vec())
            .collect_vec()
            != self
                .kernel
                .inputs
                .iter()
                .map(|rr| Hash::hash_varlen(&rr.encode()))
                .sorted_by_key(|d| d.values().iter().map(|b| b.value()).collect_vec())
                .collect_vec()
        {
            warn!("Removal records as generated from witness do not match with those listed as inputs in transaction kernel.");
            let witnessed_removal_record_hashes = witnessed_removal_records
                .iter()
                .map(|rr| Hash::hash_varlen(&rr.encode()))
                .sorted_by_key(|d| d.values().iter().map(|b| b.value()).collect_vec())
                .collect_vec();
            let listed_removal_record_hashes = self
                .kernel
                .inputs
                .iter()
                .map(|rr| Hash::hash_varlen(&rr.encode()))
                .sorted_by_key(|d| d.values().iter().map(|b| b.value()).collect_vec())
                .collect_vec();
            warn!(
                "observed: {}",
                witnessed_removal_record_hashes.iter().join(",")
            );
            warn!("listed: {}", listed_removal_record_hashes.iter().join(","));
            return false;
        }

        // Verify that the mutator set accumulator listed in the
        // primitive witness corresponds to the hash listed in the
        // transaction's kernel.
        if self.mutator_set_accumulator.hash() != self.kernel.mutator_set_hash {
            warn!("Transaction's mutator set hash does not correspond to the mutator set that the removal records were derived from. Therefore: can't verify that the inputs even exist.");
            debug!(
                "Transaction mutator set hash: {}",
                self.kernel.mutator_set_hash
            );
            debug!(
                "Witness mutator set hash: {}",
                self.mutator_set_accumulator.hash()
            );
            return false;
        }

        // in regards to public announcements: there isn't anything to verify

        true
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
            arb::<NeptuneCoins>(),
            vec(arb::<Digest>(), num_inputs),
            vec(arb::<u64>(), num_inputs),
            vec(arb::<Digest>(), num_outputs),
            vec(arb::<u64>(), num_outputs),
            vec(arb::<PublicAnnouncement>(), num_public_announcements),
            arb::<u64>(),
            arb::<Option<u64>>(),
        )
            .prop_flat_map(
                |(
                    total_amount,
                    input_address_seeds,
                    input_dist,
                    output_address_seeds,
                    output_dist,
                    public_announcements,
                    fee_dist,
                    maybe_coinbase_dist,
                )| {
                    // distribute total amount across inputs (+ coinbase)
                    let mut input_denominator = input_dist.iter().map(|u| *u as f64).sum::<f64>();
                    if let Some(d) = maybe_coinbase_dist {
                        input_denominator += d as f64;
                    }
                    let input_weights = input_dist
                        .into_iter()
                        .map(|u| (u as f64) / input_denominator)
                        .collect_vec();
                    let mut input_amounts = input_weights
                        .into_iter()
                        .map(|w| total_amount.to_nau_f64() * w)
                        .map(|f| NeptuneCoins::try_from(f).unwrap())
                        .collect_vec();
                    let maybe_coinbase = if maybe_coinbase_dist.is_some()
                        || input_amounts.is_empty()
                    {
                        Some(
                            total_amount
                                .checked_sub(&input_amounts.iter().cloned().sum::<NeptuneCoins>())
                                .unwrap(),
                        )
                    } else {
                        let sum_of_all_but_last = input_amounts
                            .iter()
                            .rev()
                            .skip(1)
                            .cloned()
                            .sum::<NeptuneCoins>();
                        *input_amounts.last_mut().unwrap() =
                            total_amount.checked_sub(&sum_of_all_but_last).unwrap();
                        None
                    };

                    // distribute total amount across outputs
                    let output_denominator =
                        output_dist.iter().map(|u| *u as f64).sum::<f64>() + (fee_dist as f64);
                    let output_weights = output_dist
                        .into_iter()
                        .map(|u| (u as f64) / output_denominator)
                        .collect_vec();
                    let output_amounts = output_weights
                        .into_iter()
                        .map(|w| total_amount.to_nau_f64() * w)
                        .map(|f| NeptuneCoins::try_from(f).unwrap())
                        .collect_vec();
                    let total_outputs = output_amounts.iter().cloned().sum::<NeptuneCoins>();
                    let fee = total_amount.checked_sub(&total_outputs).unwrap();

                    let (input_utxos, input_lock_scripts_and_witnesses) =
                        Self::transaction_inputs_from_address_seeds_and_amounts(
                            &input_address_seeds,
                            &input_amounts,
                        );
                    let total_inputs = input_amounts.iter().copied().sum::<NeptuneCoins>();

                    assert_eq!(
                        total_inputs + maybe_coinbase.unwrap_or(NeptuneCoins::new(0)),
                        total_outputs + fee
                    );
                    let output_utxos =
                        Self::valid_transaction_outputs_from_amounts_and_address_seeds(
                            &output_amounts,
                            &output_address_seeds,
                        );
                    Self::arbitrary_primitive_witness_with(
                        &input_utxos,
                        &input_lock_scripts_and_witnesses,
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

impl PrimitiveWitness {
    pub fn arbitrary_primitive_witness_with(
        input_utxos: &[Utxo],
        input_lock_scripts_and_witnesses: &[LockScriptAndWitness],
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
        let input_lock_scripts_and_witnesses = input_lock_scripts_and_witnesses.to_vec();

        // unwrap:
        //  - sender randomness (input)
        //  - receiver preimage (input)
        //  - salt (input)
        //  - sender randomness (output)
        //  - receiver preimage (output)
        //  - salt (output)
        //  - aocl size
        //  - timestamp
        (
            vec(arb::<Digest>(), num_inputs),
            vec(arb::<Digest>(), num_inputs),
            vec(arb::<BFieldElement>(), 3),
            vec(arb::<Digest>(), num_outputs),
            vec(arb::<Digest>(), num_outputs),
            vec(arb::<BFieldElement>(), 3),
            0u64..=u64::MAX,
            arb::<Timestamp>(),
        )
            .prop_flat_map(
                move |(
                    mut sender_randomnesses_input,
                    mut receiver_preimages_input,
                    inputs_salt,
                    output_sender_randomnesses,
                    output_receiver_preimages,
                    outputs_salt,
                    aocl_size,
                    timestamp,
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
                    let input_lock_scripts_and_witnesses = input_lock_scripts_and_witnesses.clone();
                    let input_utxos = input_utxos.clone();
                    let output_utxos = output_utxos.clone();
                    let public_announcements = public_announcements.clone();

                    // unwrap random mutator set accumulator with membership proofs and removal records
                    MsaAndRecords::arbitrary_with((input_triples, aocl_size))
                        .prop_map(move |msa_and_records| {
                            let mutator_set_accumulator = msa_and_records.mutator_set_accumulator;
                            let input_membership_proofs = msa_and_records.membership_proofs;
                            let input_removal_records = msa_and_records.removal_records;

                            // prepare to unwrap
                            let input_utxos = input_utxos.clone();
                            let input_lock_scripts_and_witnesses =
                                input_lock_scripts_and_witnesses.clone();
                            let input_removal_records = input_removal_records.clone();
                            let input_membership_proofs = input_membership_proofs.clone();
                            let output_utxos = output_utxos.clone();
                            let public_announcements = public_announcements.clone();
                            let sender_randomnesses_output = output_sender_randomnesses.clone();
                            let receiver_preimages_output = output_receiver_preimages.clone();

                            let output_commitments = output_utxos
                                .iter()
                                .zip(&sender_randomnesses_output)
                                .zip(&receiver_preimages_output)
                                .map(|((utxo, sender_randomness), receiver_preimage)| {
                                    commit(
                                        Hash::hash(utxo),
                                        *sender_randomness,
                                        Hash::hash(receiver_preimage),
                                    )
                                })
                                .collect_vec();

                            // prepare to unwrap
                            let input_utxos = input_utxos.clone();
                            let input_removal_records = input_removal_records.clone();
                            let input_membership_proofs = input_membership_proofs.clone();
                            let output_utxos = output_utxos.clone();
                            let public_announcements = public_announcements.clone();

                            let kernel = TransactionKernel {
                                inputs: input_removal_records.clone(),
                                outputs: output_commitments.clone(),
                                public_announcements: public_announcements.to_vec(),
                                fee,
                                coinbase,
                                timestamp,
                                mutator_set_hash: mutator_set_accumulator.hash(),
                            };

                            let salted_input_utxos = SaltedUtxos {
                                utxos: input_utxos.clone(),
                                salt: inputs_salt.clone().try_into().unwrap(),
                            };
                            let salted_output_utxos = SaltedUtxos {
                                utxos: output_utxos.clone(),
                                salt: outputs_salt.clone().try_into().unwrap(),
                            };

                            let type_scripts_and_witnesses = if num_inputs + num_outputs > 0 {
                                let native_currency_type_script_witness = NativeCurrencyWitness {
                                    salted_input_utxos: salted_input_utxos.clone(),
                                    salted_output_utxos: salted_output_utxos.clone(),
                                    kernel: kernel.clone(),
                                };
                                vec![native_currency_type_script_witness.type_script_and_witness()]
                            } else {
                                vec![]
                            };

                            PrimitiveWitness {
                                lock_scripts_and_witnesses: input_lock_scripts_and_witnesses,
                                input_utxos: salted_input_utxos,
                                input_membership_proofs: input_membership_proofs.clone(),
                                type_scripts_and_witnesses,
                                output_utxos: salted_output_utxos,
                                output_sender_randomnesses: output_sender_randomnesses.clone(),
                                output_receiver_digests: output_receiver_preimages
                                    .iter()
                                    .map(Hash::hash)
                                    .collect_vec(),
                                mutator_set_accumulator: mutator_set_accumulator.clone(),
                                kernel,
                            }
                        })
                        .boxed()
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod test {
    use super::PrimitiveWitness;
    use crate::models::blockchain::transaction::TransactionProof;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use itertools::Itertools;
    use num_bigint::BigInt;
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    #[proptest(cases = 5, async = "tokio")]
    async fn arbitrary_transaction_is_valid(
        #[strategy(1usize..3)] _num_inputs: usize,
        #[strategy(1usize..3)] _num_outputs: usize,
        #[strategy(0usize..3)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with((#_num_inputs, #_num_outputs, #_num_public_announcements)))]
        transaction_primitive_witness: PrimitiveWitness,
    ) {
        let kernel_hash = transaction_primitive_witness.kernel.mast_hash();
        prop_assert!(
            TransactionProof::Witness(transaction_primitive_witness)
                .verify(kernel_hash)
                .await
        );
    }

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

    #[proptest(cases = 5)]
    fn total_amount_is_valid(
        #[strategy(PrimitiveWitness::arbitrary_with((2,2,2)))] primitive_witness: PrimitiveWitness,
    ) {
        println!("generated primitive witness.");
        let mut total = if let Some(amount) = primitive_witness.kernel.coinbase {
            amount
        } else {
            NeptuneCoins::new(0)
        };
        for input in primitive_witness.input_utxos.utxos {
            let u32s = input.coins[0]
                .state
                .iter()
                .map(|b| b.value() as u32)
                .collect_vec();
            let amount = u32s[0] as u128
                | ((u32s[1] as u128) << 32)
                | ((u32s[2] as u128) << 64)
                | ((u32s[3] as u128) << 96);
            total = total + NeptuneCoins::from_nau(BigInt::from(amount)).unwrap();
        }
        prop_assert!(total <= NeptuneCoins::new(42000000));
    }
}
