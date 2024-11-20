use std::collections::HashMap;
use std::fmt::Display;

use get_size::GetSize;
use itertools::Itertools;
use num_traits::CheckedSub;
use num_traits::Zero;
use proptest::arbitrary::Arbitrary;
use proptest::collection::vec;
use proptest::strategy::BoxedStrategy;
use proptest::strategy::Strategy;
use proptest_arbitrary_interop::arb;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use tasm_lib::Digest;
use tracing::debug;
use tracing::warn;

use super::lock_script::LockScript;
use super::lock_script::LockScriptAndWitness;
use super::transaction_kernel::TransactionKernel;
use super::transaction_kernel::TransactionKernelProxy;
use super::utxo::Utxo;
use super::PublicAnnouncement;
use crate::models::blockchain::type_scripts::native_currency::NativeCurrencyWitness;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::blockchain::type_scripts::TypeScript;
use crate::models::blockchain::type_scripts::TypeScriptAndWitness;
use crate::models::blockchain::type_scripts::TypeScriptWitness;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::address::generation_address;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::msa_and_records::MsaAndRecords;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::Hash;

/// A list of UTXOs with an associated salt.
///
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

    pub fn new_with_rng(utxos: Vec<Utxo>, rng: &mut StdRng) -> Self {
        Self {
            utxos,
            salt: rng.gen(),
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
        let kernel_merkle_tree = self.kernel.merkle_tree();
        let kernel_mt_leafs = kernel_merkle_tree.leafs();
        write!(
            f,
            "inputs: [{}]\noutputs: [{}]\ncoinbase: {}\nfee: {}\n\
            txk mast hash: {}\n\ninput canonical commitments:\n{}\n\
            kernel mast hash leafs:\n{}\n\n\n",
            self.input_utxos,
            self.output_utxos,
            coinbase_str,
            self.kernel.fee,
            self.kernel.mast_hash(),
            self.input_membership_proofs
                .iter()
                .zip_eq(utxo_digests)
                .map(|(msmp, utxo_digest)| msmp.addition_record(utxo_digest).canonical_commitment)
                .join("\n"),
            kernel_mt_leafs.iter().join("\n"),
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
            .map(|address_seed| {
                generation_address::GenerationSpendingKey::derive_from_seed(*address_seed)
            })
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
    pub fn valid_tx_outputs_from_amounts_and_address_seeds(
        output_amounts: &[NeptuneCoins],
        address_seeds: &[Digest],
    ) -> Vec<Utxo> {
        address_seeds
            .iter()
            .zip(output_amounts)
            .map(|(seed, amount)| {
                Utxo::new(
                    generation_address::GenerationSpendingKey::derive_from_seed(*seed)
                        .to_address()
                        .lock_script(),
                    amount.to_native_coins(),
                )
            })
            .collect_vec()
    }

    /// Verify the transaction directly from the primitive witness, without proofs or
    /// decomposing into subclaims.
    #[must_use]
    pub async fn validate(&self) -> bool {
        for lock_script_and_witness in &self.lock_scripts_and_witnesses {
            let lock_script = lock_script_and_witness.program.clone();
            let secret_input = lock_script_and_witness.nondeterminism();
            let public_input = Hash::hash(self).reversed().encode().into();

            // This could be a lengthy, CPU intensive call.
            // Also, the lock script is satisfied if it halts gracefully (i.e., without crashing).
            // The output is irrelevant.
            let result = tokio::task::spawn_blocking(move || {
                VM::run(lock_script, public_input, secret_input)
            })
            .await;

            if let Err(e) = result {
                warn!("Failed to verify lock script of transaction. Got: \"{e}\"");
                return false;
            };
        }

        // Verify correct computation of removal records. Also, collect the removal
        // records' hashes in order to validate them against those provided in the
        // transaction kernel later. We only check internal consistency not removability
        // relative to a given mutator set accumulator.
        let mut witnessed_removal_records = vec![];
        for (input_utxo, membership_proof) in self
            .input_utxos
            .utxos
            .iter()
            .zip_eq(&self.input_membership_proofs)
        {
            let item = Hash::hash(input_utxo);
            // TODO: write these functions in tasm
            if !self.mutator_set_accumulator.verify(item, membership_proof) {
                warn!("Cannot generate removal record for an item with invalid membership proof.");
                let witness_msa_hash = self.mutator_set_accumulator.hash();
                debug!("witness mutator set hash: {witness_msa_hash}");
                debug!("kernel mutator set hash:  {}", self.kernel.mutator_set_hash);
                return false;
            }
            let removal_record = self.mutator_set_accumulator.drop(item, membership_proof);
            witnessed_removal_records.push(removal_record);
        }

        // verify that all type script hashes are represented by the witness's type script list
        let type_script_hashes = self
            .output_utxos
            .utxos
            .iter()
            .flat_map(|utxo| utxo.coins().iter().map(|coin| coin.type_script_hash))
            .unique()
            .collect_vec();

        let type_script_dictionary = self
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| (tsaw.program.hash(), TypeScript::from(tsaw)))
            .collect::<HashMap<_, _>>();

        if !type_script_hashes
            .iter()
            .all(|tsh| type_script_dictionary.contains_key(tsh))
        {
            warn!("Transaction contains input(s) or output(s) with unknown typescript.");
            return false;
        }

        // verify type scripts
        for type_script_hash in type_script_hashes {
            let type_script = type_script_dictionary[&type_script_hash].program().clone();
            let public_input = self.kernel.mast_hash().encode().into();
            let secret_input = self
                .kernel
                .mast_sequences()
                .into_iter()
                .flatten()
                .collect_vec()
                .into();

            // Like above: potentially lengthy, CPU intensive call, only thing that matters
            // is error-free completion.
            let result = tokio::task::spawn_blocking(move || {
                VM::run(type_script, public_input, secret_input)
            })
            .await;

            if let Err(e) = result {
                warn!("Type script {type_script_hash} not satisfied for transaction: {e}");
                return false;
            }
        }

        let witnessed_removal_record_hashes = witnessed_removal_records
            .iter()
            .map(|rr| Hash::hash_varlen(&rr.encode()))
            .sorted_by_key(|d| d.values().iter().map(|b| b.value()).collect_vec())
            .collect_vec();
        let kernel_removal_record_hashes = self
            .kernel
            .inputs
            .iter()
            .map(|rr| Hash::hash_varlen(&rr.encode()))
            .sorted_by_key(|d| d.values().iter().map(|b| b.value()).collect_vec())
            .collect_vec();
        if witnessed_removal_record_hashes != kernel_removal_record_hashes {
            warn!("Removal records generated from witness do not match transaction kernel inputs.");
            warn!(
                "in witness: {}\nin kernel:  {}",
                witnessed_removal_record_hashes.iter().join(","),
                kernel_removal_record_hashes.iter().join(",")
            );
            return false;
        }

        if self.mutator_set_accumulator.hash() != self.kernel.mutator_set_hash {
            warn!(
                "Transaction's mutator set hash does not correspond to the mutator set the removal \
                 records were derived from. Therefore: can't verify that the inputs even exist."
            );
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

        // public announcements: there isn't anything to verify

        true
    }
}

impl Arbitrary for PrimitiveWitness {
    type Parameters = (usize, usize, usize);
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
                move |(
                    total_amount,
                    input_address_seeds,
                    input_dist,
                    output_address_seeds,
                    output_dist,
                    public_announcements,
                    fee_dist,
                    maybe_coinbase_dist,
                )| {
                    // Coinbase transactions may not take inputs. This is done
                    // to force miners to pick up at least one transaction.
                    let maybe_coinbase_dist = if num_inputs.is_zero() {
                        maybe_coinbase_dist
                    } else {
                        None
                    };
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
                    let output_utxos = Self::valid_tx_outputs_from_amounts_and_address_seeds(
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

    type Strategy = BoxedStrategy<Self>;
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
        let input_utxos = input_utxos.to_vec();
        let input_lock_scripts_and_witnesses = input_lock_scripts_and_witnesses.to_vec();
        let output_utxos = output_utxos.to_vec();
        let public_announcements = public_announcements.to_vec();

        arb::<Timestamp>()
            .prop_flat_map(move |now| {
                Self::arbitrary_primitive_witness_with_timestamp_and(
                    &input_utxos,
                    &input_lock_scripts_and_witnesses,
                    &output_utxos,
                    &public_announcements,
                    fee,
                    coinbase,
                    now,
                )
            })
            .boxed()
    }

    pub fn arbitrary_primitive_witness_with_timestamp_and(
        input_utxos: &[Utxo],
        input_lock_scripts_and_witnesses: &[LockScriptAndWitness],
        output_utxos: &[Utxo],
        public_announcements: &[PublicAnnouncement],
        fee: NeptuneCoins,
        coinbase: Option<NeptuneCoins>,
        timestamp: Timestamp,
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
        (
            vec(arb::<Digest>(), num_inputs),
            vec(arb::<Digest>(), num_inputs),
            [arb::<BFieldElement>(); 3],
            vec(arb::<Digest>(), num_outputs),
            vec(arb::<Digest>(), num_outputs),
            [arb::<BFieldElement>(); 3],
            0u64..=(u64::MAX >> 1),
        )
            .prop_flat_map(
                move |(
                    mut sender_randomnesses_input,
                    mut receiver_preimages_input,
                    inputs_salt,
                    output_sender_randomnesses,
                    output_receiver_digests,
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
                    let input_lock_scripts_and_witnesses = input_lock_scripts_and_witnesses.clone();
                    let input_utxos = input_utxos.clone();
                    let output_utxos = output_utxos.clone();
                    let public_announcements = public_announcements.clone();

                    // unwrap random mutator set accumulator with membership proofs and removal records
                    MsaAndRecords::arbitrary_with((input_triples, aocl_size))
                        .prop_map(move |msa_and_records| {
                            Self::from_msa_and_records(
                                msa_and_records,
                                input_utxos.clone(),
                                input_lock_scripts_and_witnesses.clone(),
                                output_utxos.clone(),
                                public_announcements.clone(),
                                output_sender_randomnesses.clone(),
                                output_receiver_digests.clone(),
                                fee,
                                coinbase,
                                timestamp,
                                inputs_salt,
                                outputs_salt,
                            )
                        })
                        .boxed()
                },
            )
            .boxed()
    }

    #[expect(clippy::too_many_arguments, reason = "under development")]
    pub(crate) fn from_msa_and_records(
        msa_and_records: MsaAndRecords,
        input_utxos: Vec<Utxo>,
        input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        output_utxos: Vec<Utxo>,
        public_announcements: Vec<PublicAnnouncement>,
        output_sender_randomnesses: Vec<Digest>,
        output_receiver_digests: Vec<Digest>,
        fee: NeptuneCoins,
        coinbase: Option<NeptuneCoins>,
        timestamp: Timestamp,
        inputs_salt: [BFieldElement; 3],
        outputs_salt: [BFieldElement; 3],
    ) -> Self {
        let mutator_set_accumulator = msa_and_records.mutator_set_accumulator;
        let input_membership_proofs = msa_and_records.membership_proofs;
        let input_removal_records = msa_and_records.removal_records;
        assert_eq!(input_membership_proofs.len(), input_removal_records.len());

        let output_commitments = output_utxos
            .iter()
            .zip(output_sender_randomnesses.clone())
            .zip(output_receiver_digests.clone())
            .map(|((utxo, sender_randomness), receiver_digest)| {
                commit(Hash::hash(utxo), sender_randomness, receiver_digest)
            })
            .collect_vec();

        let kernel = TransactionKernelProxy {
            inputs: input_removal_records.clone(),
            outputs: output_commitments.clone(),
            public_announcements: public_announcements.to_vec(),
            fee,
            coinbase,
            timestamp,
            mutator_set_hash: mutator_set_accumulator.hash(),
        }
        .into_kernel();

        let salted_input_utxos = SaltedUtxos {
            utxos: input_utxos.clone(),
            salt: inputs_salt,
        };
        let salted_output_utxos = SaltedUtxos {
            utxos: output_utxos.clone(),
            salt: outputs_salt,
        };

        let num_inputs = input_utxos.len();
        let num_outputs = output_utxos.len();
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
            lock_scripts_and_witnesses: input_lock_scripts_and_witnesses.to_owned(),
            input_utxos: salted_input_utxos,
            input_membership_proofs: input_membership_proofs.clone(),
            type_scripts_and_witnesses,
            output_utxos: salted_output_utxos,
            output_sender_randomnesses,
            output_receiver_digests: output_receiver_digests.to_owned(),
            mutator_set_accumulator: mutator_set_accumulator.clone(),
            kernel,
        }
    }
}

#[cfg(test)]
mod test {
    use itertools::izip;
    use itertools::Itertools;
    use num_bigint::BigInt;
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::models::blockchain::transaction::TransactionProof;
    use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::proof_abstractions::mast_hash::MastHash;
    use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;

    impl Utxo {
        /// returns a new Utxo with properties:
        /// Set the number of NeptuneCoins, overriding the pre-existing number attached
        /// to the type script `NativeCurrency`, or adding a new coin with that amount
        /// and type script hash to the coins list.
        pub(crate) fn new_with_native_currency_amount(&self, amount: NeptuneCoins) -> Utxo {
            let mut coins = self.coins().to_vec();
            assert!(
                coins
                    .iter()
                    .filter(|x| x.type_script_hash == NativeCurrency.hash())
                    .count()
                    <= 1,
                "Cannot have repeated native currency coins"
            );
            let new_coin = amount.to_native_coins().first().unwrap().clone();
            if let Some(coin) = coins
                .iter_mut()
                .find(|coin| coin.type_script_hash == NativeCurrency.hash())
            {
                *coin = new_coin;
            } else {
                coins.push(new_coin);
            }
            (self.lock_script_hash(), coins).into()
        }
    }

    impl PrimitiveWitness {
        /// Arbitrary with: (num inputs, num outputs, num pub announcements)
        pub(crate) fn arbitrary_tuple_with_matching_mutator_sets<const N: usize>(
            param_sets: [(usize, usize, usize); N],
        ) -> BoxedStrategy<[PrimitiveWitness; N]> {
            (arb::<Option<NeptuneCoins>>(), 0..N)
                .prop_flat_map(move |(maybe_coinbase, coinbase_index)| {
                    Self::arbitrary_tuple_with_matching_mutator_sets_and_given_coinbase(
                        param_sets,
                        maybe_coinbase.map(|coinbase| (coinbase, coinbase_index)),
                    )
                })
                .boxed()
        }

        /// Arbitrary with:
        /// (num inputs, num outputs, num pub announcements) and optional
        /// coinbase.
        pub(crate) fn arbitrary_tuple_with_matching_mutator_sets_and_given_coinbase<
            const N: usize,
        >(
            param_sets: [(usize, usize, usize); N],
            coinbase_and_index: Option<(NeptuneCoins, usize)>,
        ) -> BoxedStrategy<[PrimitiveWitness; N]> {
            if let Some((_, index)) = coinbase_and_index {
                // assert that index lies in the range [0;N)
                assert!(index < N);
            }
            let nested_vec_strategy_digests =
                |counts: [usize; N]| counts.map(|count| vec(arb::<Digest>(), count));
            let nested_vec_strategy_pubann =
                |counts: [usize; N]| counts.map(|count| vec(arb::<PublicAnnouncement>(), count));
            let nested_vec_strategy_amounts =
                |counts: [usize; N]| counts.map(|count| vec(arb::<NeptuneCoins>(), count));
            let nested_vec_strategy_utxos =
                |counts: [usize; N]| counts.map(|count| vec(arb::<Utxo>(), count));
            let input_counts: [usize; N] = param_sets.map(|p| p.0);
            let output_counts: [usize; N] = param_sets.map(|p| p.1);
            let announcement_counts: [usize; N] = param_sets.map(|p| p.2);
            let total_num_inputs: usize = input_counts.iter().sum();

            (
                (
                    nested_vec_strategy_amounts(input_counts),
                    nested_vec_strategy_digests(input_counts),
                    nested_vec_strategy_utxos(output_counts),
                    nested_vec_strategy_pubann(announcement_counts),
                    [arb::<NeptuneCoins>(); N],
                    vec(arb::<Digest>(), total_num_inputs),
                    vec(arb::<Digest>(), total_num_inputs),
                ),
                // we broke the derive macro of Arbitrary because it only supports
                // tuples of size up to twelve
                (
                    0..(u64::MAX / 2),
                    nested_vec_strategy_digests(output_counts),
                    nested_vec_strategy_digests(output_counts),
                    [arb::<Timestamp>(); N],
                    [arb::<[BFieldElement; 3]>(); N],
                    [arb::<[BFieldElement; 3]>(); N],
                ),
            )
                .prop_flat_map(
                    move |(
                        (
                            input_amountss,
                            input_address_seedss,
                            mut output_utxos,
                            public_announcements_nested,
                            mut fees,
                            mut input_sender_randomnesses,
                            mut input_receiver_preimages,
                        ),
                        (
                            aocl_size,
                            output_sender_randomnesses_nested,
                            output_receiver_digests_nested,
                            timestamps,
                            inputs_salts,
                            outputs_salts,
                        ),
                    )| {
                        let input_amounts_per_tx: [NeptuneCoins; N] = input_amountss
                            .clone()
                            .map(|amounts| amounts.iter().copied().sum::<NeptuneCoins>());
                        let mut output_utxo_amounts_per_tx = output_utxos.clone().map(|utxos| {
                            utxos
                                .iter()
                                .map(|utxo| utxo.get_native_currency_amount())
                                .collect_vec()
                        });

                        for i in 0..N {
                            let maybe_coinbase =
                                coinbase_and_index.and_then(|(coinbase, index)| {
                                    if index == i {
                                        Some(coinbase)
                                    } else {
                                        None
                                    }
                                });
                            Self::find_balanced_output_amounts_and_fee(
                                input_amounts_per_tx[i],
                                maybe_coinbase,
                                &mut output_utxo_amounts_per_tx[i],
                                &mut fees[i],
                            );
                        }

                        output_utxos
                            .iter_mut()
                            .zip(output_utxo_amounts_per_tx)
                            .for_each(|(utxos, amounts)| {
                                utxos.iter_mut().zip_eq(amounts).for_each(|(utxo, amount)| {
                                    *utxo = utxo.new_with_native_currency_amount(amount);
                                })
                            });

                        let utxos_and_lock_scripts_and_witnesses = input_amountss
                            .iter()
                            .zip_eq(input_address_seedss)
                            .map(|(input_amounts, input_address_seeds)| {
                                Self::transaction_inputs_from_address_seeds_and_amounts(
                                    &input_address_seeds,
                                    input_amounts,
                                )
                            })
                            .collect_vec();
                        let (input_utxoss, input_lock_scripts_and_witnesses): (Vec<_>, Vec<_>) =
                            utxos_and_lock_scripts_and_witnesses.into_iter().unzip();
                        let input_utxoss: [_; N] = input_utxoss.try_into().unwrap();
                        let input_lock_scripts_and_witnesses: [_; N] =
                            input_lock_scripts_and_witnesses.try_into().unwrap();

                        let mut all_input_triples = vec![];
                        for input_utxos in input_utxoss.iter() {
                            for input_utxo in input_utxos.iter() {
                                all_input_triples.push((
                                    Hash::hash(input_utxo),
                                    input_sender_randomnesses.pop().unwrap(),
                                    input_receiver_preimages.pop().unwrap(),
                                ));
                            }
                        }

                        MsaAndRecords::arbitrary_with((all_input_triples, aocl_size))
                            .prop_map(move |msa_and_records| {
                                let split_msa_and_records = msa_and_records.split_by(input_counts);
                                izip!(
                                    0..N,
                                    split_msa_and_records,
                                    timestamps,
                                    public_announcements_nested.clone(),
                                    output_sender_randomnesses_nested.clone(),
                                    output_receiver_digests_nested.clone(),
                                    fees,
                                    inputs_salts,
                                    outputs_salts,
                                    input_utxoss.clone(),
                                    input_lock_scripts_and_witnesses.clone(),
                                    output_utxos.clone(),
                                )
                                .map(
                                    |(
                                        index,
                                        msaar,
                                        timestamp,
                                        public_announcements,
                                        output_sender_randomnesses,
                                        output_receiver_digests,
                                        fee,
                                        inputs_salt,
                                        outputs_salt,
                                        input_utxos,
                                        input_lock_scripts_and_witnesses_,
                                        output_utxos_,
                                    )| {
                                        let maybe_coinbase =
                                            coinbase_and_index.and_then(|(coinbase, i)| {
                                                if index == i {
                                                    Some(coinbase)
                                                } else {
                                                    None
                                                }
                                            });
                                        Self::from_msa_and_records(
                                            msaar,
                                            input_utxos,
                                            input_lock_scripts_and_witnesses_,
                                            output_utxos_,
                                            public_announcements,
                                            output_sender_randomnesses,
                                            output_receiver_digests,
                                            fee,
                                            maybe_coinbase,
                                            timestamp,
                                            inputs_salt,
                                            outputs_salt,
                                        )
                                    },
                                )
                                .collect_vec()
                                .try_into()
                                .unwrap()
                            })
                            .boxed()
                    },
                )
                .boxed()
        }

        pub(crate) fn arbitrary_pair_with_inputs_and_coinbase_respectively(
            num_inputs: usize,
            total_num_outputs: usize,
            total_num_announcements: usize,
        ) -> BoxedStrategy<(Self, Self)> {
            (
                (0..total_num_outputs),
                (0..total_num_announcements),
                arb::<NeptuneCoins>(),
            )
                .prop_flat_map(move |(num_outputs, num_announcements, coinbase_amount)| {
                    let parameter_sets = [
                        (num_inputs, num_outputs, num_announcements),
                        (
                            0,
                            total_num_outputs - num_outputs,
                            total_num_announcements - num_announcements,
                        ),
                    ];
                    Self::arbitrary_tuple_with_matching_mutator_sets_and_given_coinbase(
                        parameter_sets,
                        Some((coinbase_amount, 1)),
                    )
                    .prop_map(|primwit| (primwit[0].clone(), primwit[1].clone()))
                })
                .boxed()
        }

        pub(crate) fn arbitrary_pair_with_inputs_and_coinbase_respectively_from_msa_and_records(
            total_num_outputs: usize,
            total_num_announcements: usize,
            msa_and_records: MsaAndRecords,
            input_utxos: Vec<Utxo>,
            lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
            coinbase_amount: NeptuneCoins,
            timestamp: Timestamp,
        ) -> BoxedStrategy<(Self, Self)> {
            let input_removal_records = msa_and_records.removal_records;
            let input_membership_proofs = msa_and_records.membership_proofs;
            let mutator_set_accumulator = msa_and_records.mutator_set_accumulator;
            ((0..total_num_outputs), (0..total_num_announcements))
                .prop_flat_map(move |(num_outputs, num_announcements)| {
                    (
                        Self::arbitrary_given_mutator_set_accumulator_and_inputs(
                            num_outputs,
                            num_announcements,
                            None,
                            input_utxos.clone(),
                            input_removal_records.clone(),
                            input_membership_proofs.clone(),
                            lock_scripts_and_witnesses.clone(),
                            mutator_set_accumulator.clone(),
                            timestamp,
                        ),
                        Self::arbitrary_given_mutator_set_accumulator_and_inputs(
                            total_num_outputs - num_outputs,
                            total_num_announcements - num_announcements,
                            Some(coinbase_amount),
                            vec![],
                            vec![],
                            vec![],
                            vec![],
                            mutator_set_accumulator.clone(),
                            timestamp,
                        ),
                    )
                })
                .boxed()
        }

        #[allow(clippy::too_many_arguments)]
        pub(crate) fn arbitrary_given_mutator_set_accumulator_and_inputs(
            num_outputs: usize,
            num_announcements: usize,
            coinbase: Option<NeptuneCoins>,
            input_utxos: Vec<Utxo>,
            input_removal_records: Vec<RemovalRecord>,
            input_membership_proofs: Vec<MsMembershipProof>,
            lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
            mutator_set_accumulator: MutatorSetAccumulator,
            timestamp: Timestamp,
        ) -> BoxedStrategy<Self> {
            (
                vec(arb::<NeptuneCoins>(), num_outputs),
                arb::<NeptuneCoins>(),
                vec(arb::<Digest>(), num_outputs),
                vec(arb::<Digest>(), num_outputs),
                vec(arb::<Digest>(), num_outputs),
                arb::<[BFieldElement; 3]>(),
                arb::<[BFieldElement; 3]>(),
                vec(arb::<PublicAnnouncement>(), num_announcements),
            )
                .prop_map(
                    move |(
                        mut output_amounts,
                        mut fee,
                        lock_script_hashes,
                        output_sender_randomnesses,
                        output_receiver_digests,
                        input_salt,
                        output_salt,
                        public_announcements,
                    )| {
                        let total_input_amount = input_utxos
                            .iter()
                            .map(|utxo| utxo.get_native_currency_amount())
                            .sum::<NeptuneCoins>()
                            + coinbase.unwrap_or(NeptuneCoins::zero());
                        PrimitiveWitness::find_balanced_output_amounts_and_fee(
                            total_input_amount,
                            coinbase,
                            &mut output_amounts,
                            &mut fee,
                        );

                        let output_utxos = output_amounts
                            .into_iter()
                            .zip(lock_script_hashes)
                            .map(|(amount, lock_script_hash)| {
                                (lock_script_hash, amount.to_native_coins()).into()
                            })
                            .collect_vec();

                        let salted_input_utxos = SaltedUtxos {
                            utxos: input_utxos.clone(),
                            salt: input_salt,
                        };
                        let salted_output_utxos = SaltedUtxos {
                            utxos: output_utxos.clone(),
                            salt: output_salt,
                        };

                        let output_addition_records = izip!(
                            output_utxos,
                            output_sender_randomnesses.clone(),
                            output_receiver_digests.clone(),
                        )
                        .map(|(utxo, sr, rd)| commit(Tip5::hash(&utxo), sr, rd))
                        .collect_vec();

                        let kernel = TransactionKernelProxy {
                            inputs: input_removal_records.clone(),
                            outputs: output_addition_records,
                            public_announcements,
                            fee,
                            coinbase,
                            timestamp,
                            mutator_set_hash: mutator_set_accumulator.hash(),
                        }
                        .into_kernel();

                        let type_scripts_and_witnesses = vec![NativeCurrencyWitness {
                            salted_input_utxos: salted_input_utxos.clone(),
                            salted_output_utxos: salted_output_utxos.clone(),
                            kernel: kernel.clone(),
                        }
                        .type_script_and_witness()];

                        Self {
                            input_utxos: salted_input_utxos,
                            input_membership_proofs: input_membership_proofs.clone(),
                            lock_scripts_and_witnesses: lock_scripts_and_witnesses.clone(),
                            type_scripts_and_witnesses,
                            output_utxos: salted_output_utxos,
                            output_sender_randomnesses,
                            output_receiver_digests,
                            mutator_set_accumulator: mutator_set_accumulator.clone(),
                            kernel,
                        }
                    },
                )
                .boxed()
        }
    }

    #[proptest(cases = 5, async = "tokio")]
    async fn arbitrary_transaction_is_valid(
        #[strategy(1usize..3)] _num_inputs: usize,
        #[strategy(1usize..3)] _num_outputs: usize,
        #[strategy(0usize..3)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with((#_num_inputs, #_num_outputs, #_num_public_announcements)
        ))]
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
            let u32s = input.coins()[0]
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
