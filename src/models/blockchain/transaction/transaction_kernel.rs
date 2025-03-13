use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use strum::VariantArray;
use tasm_lib::structure::tasm_object::TasmObject;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::tip5::Digest;

use super::primitive_witness::PrimitiveWitness;
use super::PublicAnnouncement;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

/// TransactionKernel is immutable and its hash never changes.
///
/// See [`TransactionKernelModifier`] for generating modified copies.
#[readonly::make]
#[derive(Debug, Clone, Serialize, Deserialize, GetSize, BFieldCodec, TasmObject)]
pub struct TransactionKernel {
    // note: see field descriptions in [`TransactionKernelProxy`]
    pub inputs: Vec<RemovalRecord>,
    pub outputs: Vec<AdditionRecord>,
    pub public_announcements: Vec<PublicAnnouncement>,
    pub fee: NativeCurrencyAmount,
    pub coinbase: Option<NativeCurrencyAmount>,
    pub timestamp: Timestamp,
    pub mutator_set_hash: Digest,

    /// Indicates whether the transaction is the result of some merger.
    pub merge_bit: bool,

    // this is only here as a cache for MastHash
    // so that we lazily compute the input sequences at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[tasm_object(ignore)]
    #[get_size(ignore)]
    mast_sequences: OnceLock<Vec<Vec<BFieldElement>>>,
}

impl std::fmt::Display for TransactionKernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "
kernel hash: {mast_hash}
inputs: {inputs}
outputs: {outputs}
public_announcements: {announcements}
coinbase: {coinbase}
timestamp: {timestamp}
mutator_set_hash: {ms_hash}
merge_bit: {merge_bit}
",
            mast_hash = self.mast_hash().to_hex(),
            inputs = self.inputs.len(),
            outputs = self.outputs.len(),
            announcements = self.public_announcements.len(),
            coinbase = self
                .coinbase
                .unwrap_or_else(|| NativeCurrencyAmount::coins(0)),
            timestamp = self.timestamp,
            ms_hash = self.mutator_set_hash.to_hex(),
            merge_bit = self.merge_bit,
        )
    }
}

// we impl PartialEq manually in order to skip mast_sequences field.
// This could also be achieved with the `derivative` crate that has a
// PartialEq that can skip fields, but this way we avoid an extra dep.
impl PartialEq for TransactionKernel {
    fn eq(&self, o: &Self) -> bool {
        self.inputs == o.inputs
            && self.outputs == o.outputs
            && self.public_announcements == o.public_announcements
            && self.fee == o.fee
            && self.coinbase == o.coinbase
            && self.timestamp == o.timestamp
            && self.mutator_set_hash == o.mutator_set_hash

        // mast_sequences intentionally skipped.
    }
}

impl Eq for TransactionKernel {}

impl From<PrimitiveWitness> for TransactionKernel {
    fn from(transaction_primitive_witness: PrimitiveWitness) -> Self {
        transaction_primitive_witness.kernel
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum TransactionConfirmabilityError {
    InvalidRemovalRecord(usize),
    DuplicateInputs,
    AlreadySpentInput(usize),
}

impl TransactionKernel {
    pub(crate) fn is_confirmable_relative_to(
        &self,
        mutator_set_accumulator: &MutatorSetAccumulator,
    ) -> Result<(), TransactionConfirmabilityError> {
        // check validity of removal records
        //       ^^^^^^^^
        // meaning: a) all required membership proofs exist; and b) are valid.
        let maybe_invalid_removal_record = self
            .inputs
            .iter()
            .enumerate()
            .find(|(_, rr)| !rr.validate(mutator_set_accumulator));
        if let Some((index, _invalid_removal_record)) = maybe_invalid_removal_record {
            return Err(TransactionConfirmabilityError::InvalidRemovalRecord(index));
        }

        // check for duplicates
        let has_unique_inputs = self
            .inputs
            .iter()
            .unique_by(|rr| rr.absolute_indices)
            .count()
            == self.inputs.len();
        if !has_unique_inputs {
            return Err(TransactionConfirmabilityError::DuplicateInputs);
        }

        // check for already-spent inputs
        let already_spent_removal_record = self
            .inputs
            .iter()
            .enumerate()
            .find(|(_, rr)| !mutator_set_accumulator.can_remove(rr));
        if let Some((index, _already_spent_removal_record)) = already_spent_removal_record {
            return Err(TransactionConfirmabilityError::AlreadySpentInput(index));
        }

        Ok(())
    }
}

#[derive(VariantArray, Debug, Clone, EnumCount, Copy, strum_macros::Display)]
#[strum(serialize_all = "snake_case")]
pub enum TransactionKernelField {
    Inputs,
    Outputs,
    PublicAnnouncements,
    Fee,
    Coinbase,
    Timestamp,
    MutatorSetHash,
    MergeBit,
}

impl HasDiscriminant for TransactionKernelField {
    fn discriminant(&self) -> usize {
        *self as usize
    }
}

impl MastHash for TransactionKernel {
    type FieldEnum = TransactionKernelField;

    /// Return the sequences (= leaf preimages) of the kernel Merkle tree.
    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
        self.mast_sequences
            .get_or_init(|| {
                let input_utxos_sequence = self.inputs.encode();

                let output_utxos_sequence = self.outputs.encode();

                let pubscript_sequence = self.public_announcements.encode();

                let fee_sequence = self.fee.encode();

                let coinbase_sequence = self.coinbase.encode();

                let timestamp_sequence = self.timestamp.encode();

                let mutator_set_hash_sequence = self.mutator_set_hash.encode();

                let merge_bit_sequence = self.merge_bit.encode();

                vec![
                    input_utxos_sequence,
                    output_utxos_sequence,
                    pubscript_sequence,
                    fee_sequence,
                    coinbase_sequence,
                    timestamp_sequence,
                    mutator_set_hash_sequence,
                    merge_bit_sequence,
                ]
            })
            .clone() // can we refactor to avoid this clone?
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use arbitrary::Arbitrary;
    use itertools::Itertools;

    use super::*;

    impl<'a> Arbitrary<'a> for TransactionKernel {
        fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
            let num_inputs = u.int_in_range(0..=4)?;
            let num_outputs = u.int_in_range(0..=4)?;
            let num_public_announcements = u.int_in_range(0..=2)?;
            let inputs: Vec<RemovalRecord> = (0..num_inputs)
                .map(|_| u.arbitrary().unwrap())
                .collect_vec();
            let outputs: Vec<AdditionRecord> = (0..num_outputs)
                .map(|_| u.arbitrary().unwrap())
                .collect_vec();
            let public_announcements: Vec<PublicAnnouncement> = (0..num_public_announcements)
                .map(|_| u.arbitrary().unwrap())
                .collect_vec();
            let fee: NativeCurrencyAmount = u.arbitrary()?;
            let coinbase: Option<NativeCurrencyAmount> = u.arbitrary()?;
            let timestamp: Timestamp = u.arbitrary()?;
            let mutator_set_hash: Digest = u.arbitrary()?;
            let merge_bit: bool = u.arbitrary()?;

            let transaction_kernel = TransactionKernelProxy {
                inputs,
                outputs,
                public_announcements,
                fee,
                coinbase,
                timestamp,
                mutator_set_hash,
                merge_bit,
            }
            .into_kernel();

            Ok(transaction_kernel)
        }
    }
}

/// performs instantiation and destructuring of [TransactionKernel]
///
/// [TransactionKernel] is immutable, so it cannot be instantiated
/// by direct field access.  This proxy is mutable, and it has an
/// into_kernel() method that converts it to a [TransactionKernel].
///
/// It is also useful for destructuring kernel fields without cloning.
#[derive(Debug, Clone)]
pub struct TransactionKernelProxy {
    /// contains the transaction inputs.
    pub inputs: Vec<RemovalRecord>,

    /// contains the commitments (addition records) that go into the AOCL
    pub outputs: Vec<AdditionRecord>,

    /// list of public-announcements to include in blockchain
    pub public_announcements: Vec<PublicAnnouncement>,

    /// tx fee amount
    pub fee: NativeCurrencyAmount,

    /// optional coinbase.  applies only to miner payments.
    pub coinbase: Option<NativeCurrencyAmount>,

    /// number of milliseconds since unix epoch
    pub timestamp: Timestamp,

    /// mutator set hash *prior* to updating mutator set with this transaction.
    pub mutator_set_hash: Digest,

    /// Indicates whether the transaction is the result of some merger.
    pub merge_bit: bool,
}

impl From<TransactionKernel> for TransactionKernelProxy {
    fn from(k: TransactionKernel) -> Self {
        Self {
            inputs: k.inputs,
            outputs: k.outputs,
            public_announcements: k.public_announcements,
            fee: k.fee,
            coinbase: k.coinbase,
            timestamp: k.timestamp,
            mutator_set_hash: k.mutator_set_hash,
            merge_bit: k.merge_bit,
        }
    }
}

impl TransactionKernelProxy {
    pub fn into_kernel(self) -> TransactionKernel {
        TransactionKernel {
            inputs: self.inputs,
            outputs: self.outputs,
            public_announcements: self.public_announcements,
            fee: self.fee,
            coinbase: self.coinbase,
            timestamp: self.timestamp,
            mutator_set_hash: self.mutator_set_hash,
            merge_bit: self.merge_bit,
            mast_sequences: Default::default(),
        }
    }
}

/// performs modifications of [TransactionKernel]
///
/// [TransactionKernel] is immutable, so any modifications must
/// generate a new instance.  [TransactionKernelModifier] uses
/// a builder pattern to facilitate that task.
///
/// supports a move/modify operation and a clone/modify operation.
#[derive(Debug, Default, Clone)]
pub struct TransactionKernelModifier {
    pub inputs: Option<Vec<RemovalRecord>>,
    pub outputs: Option<Vec<AdditionRecord>>,
    pub public_announcements: Option<Vec<PublicAnnouncement>>,
    pub fee: Option<NativeCurrencyAmount>,
    pub coinbase: Option<Option<NativeCurrencyAmount>>,
    pub timestamp: Option<Timestamp>,
    pub mutator_set_hash: Option<Digest>,
    pub merge_bit: Option<bool>,
}

impl TransactionKernelModifier {
    /// set modified inputs
    pub fn inputs(mut self, inputs: Vec<RemovalRecord>) -> Self {
        self.inputs = Some(inputs);
        self
    }
    /// set modified outputs
    pub fn outputs(mut self, outputs: Vec<AdditionRecord>) -> Self {
        self.outputs = Some(outputs);
        self
    }
    /// set modified public-announcements
    pub fn public_announcements(mut self, pa: Vec<PublicAnnouncement>) -> Self {
        self.public_announcements = Some(pa);
        self
    }
    /// set modified fee
    pub fn fee(mut self, fee: NativeCurrencyAmount) -> Self {
        self.fee = Some(fee);
        self
    }
    /// set modified coinbase
    pub fn coinbase(mut self, coinbase: Option<NativeCurrencyAmount>) -> Self {
        self.coinbase = Some(coinbase);
        self
    }
    /// set modified timestamp
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
    /// set modified mutator-set-hash digest
    pub fn mutator_set_hash(mut self, mutator_set_hash: Digest) -> Self {
        self.mutator_set_hash = Some(mutator_set_hash);
        self
    }
    /// set merge-bit
    pub fn merge_bit(mut self, merge_bit: bool) -> Self {
        self.merge_bit = Some(merge_bit);
        self
    }

    /// perform move+modify operation.
    ///
    /// The input [TransactionKernel] is replaced with a copy
    /// that contains any modifications previously set in the builder.
    ///
    /// Unmodified fields from the input kernel are moved into the
    /// output kernel (no clone).
    pub fn modify(self, k: TransactionKernel) -> TransactionKernel {
        TransactionKernel {
            inputs: self.inputs.unwrap_or(k.inputs),
            outputs: self.outputs.unwrap_or(k.outputs),
            public_announcements: self.public_announcements.unwrap_or(k.public_announcements),
            fee: self.fee.unwrap_or(k.fee),
            coinbase: self.coinbase.unwrap_or(k.coinbase),
            timestamp: self.timestamp.unwrap_or(k.timestamp),
            mutator_set_hash: self.mutator_set_hash.unwrap_or(k.mutator_set_hash),
            merge_bit: self.merge_bit.unwrap_or(k.merge_bit),

            // we must not copy from original, as the modified
            // one must have a different sequence/hash.
            mast_sequences: Default::default(),
        }
    }

    /// perform clone+modify operation.
    ///
    /// The input [TransactionKernel] is replaced with a cloned copy
    /// that contains any modifications previously set in the builder.
    pub fn clone_modify(self, k: &TransactionKernel) -> TransactionKernel {
        self.modify(k.clone())
    }
}

#[cfg(test)]
pub mod transaction_kernel_tests {
    use itertools::Itertools;
    use proptest::prelude::Strategy;
    use proptest::test_runner::TestRunner;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;

    use super::*;
    use crate::models::blockchain::block::mutator_set_update::MutatorSetUpdate;
    use crate::models::blockchain::transaction::Transaction;
    use crate::models::blockchain::transaction::TransactionProof;
    use crate::tests::shared::pseudorandom_amount;
    use crate::tests::shared::pseudorandom_option;
    use crate::tests::shared::pseudorandom_public_announcement;
    use crate::tests::shared::random_public_announcement;
    use crate::tests::shared::random_transaction_kernel;
    use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::util_types::test_shared::mutator_set::pseudorandom_addition_record;
    use crate::util_types::test_shared::mutator_set::pseudorandom_removal_record;

    pub fn pseudorandom_transaction_kernel(
        seed: [u8; 32],
        num_inputs: usize,
        num_outputs: usize,
        num_public_announcements: usize,
    ) -> TransactionKernel {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let inputs = (0..num_inputs)
            .map(|_| pseudorandom_removal_record(rng.random::<[u8; 32]>()))
            .collect_vec();
        let outputs = (0..num_outputs)
            .map(|_| pseudorandom_addition_record(rng.random::<[u8; 32]>()))
            .collect_vec();
        let public_announcements = (0..num_public_announcements)
            .map(|_| pseudorandom_public_announcement(rng.random::<[u8; 32]>()))
            .collect_vec();
        let fee = pseudorandom_amount(rng.random::<[u8; 32]>());
        let coinbase =
            pseudorandom_option(rng.random(), pseudorandom_amount(rng.random::<[u8; 32]>()));
        let timestamp: Timestamp = rng.random();
        let mutator_set_hash: Digest = rng.random();
        let merge_bit: bool = rng.random();

        TransactionKernelProxy {
            inputs,
            outputs,
            public_announcements,
            fee,
            coinbase,
            timestamp,
            mutator_set_hash,
            merge_bit,
        }
        .into_kernel()
    }

    #[test]
    pub fn arbitrary_tx_kernel_is_deterministic() {
        use proptest::prelude::Strategy;
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;
        use proptest_arbitrary_interop::arb;

        let mut test_runner = TestRunner::deterministic();
        let a = arb::<TransactionKernel>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        test_runner = TestRunner::deterministic();
        let b = arb::<TransactionKernel>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        assert_eq!(a, b);
    }

    #[test]
    fn can_identify_double_spends() {
        let mut test_runner = TestRunner::deterministic();
        let pw = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mut msa = pw.mutator_set_accumulator.clone();
        let tx = Transaction {
            kernel: pw.kernel.clone(),
            proof: TransactionProof::Witness(pw),
        };
        assert_eq!(Ok(()), tx.kernel.is_confirmable_relative_to(&msa));

        let repeated_input = [tx.kernel.inputs.clone(), vec![tx.kernel.inputs[0].clone()]].concat();
        let repeated_input = TransactionKernelModifier::default()
            .inputs(repeated_input)
            .modify(tx.kernel.clone());
        assert!(matches!(
            repeated_input.is_confirmable_relative_to(&msa),
            Err(TransactionConfirmabilityError::DuplicateInputs),
        ));

        // Update the mutator set to *after* applying this tx. Then verify tx is
        // unspendable because inputs are already spent.
        let mut removal_records = tx.kernel.inputs.clone();
        let ms_update = MutatorSetUpdate::new(removal_records.clone(), tx.kernel.outputs.clone());
        ms_update
            .apply_to_accumulator_and_records(
                &mut msa,
                &mut removal_records.iter_mut().collect_vec(),
                &mut [],
            )
            .unwrap();
        let new_tx = TransactionKernelModifier::default()
            .inputs(removal_records)
            .mutator_set_hash(msa.hash())
            .modify(tx.kernel.clone());
        assert!(
            matches!(
                new_tx.is_confirmable_relative_to(&msa),
                Err(TransactionConfirmabilityError::AlreadySpentInput(_))
            ),
            "{:?}",
            repeated_input.is_confirmable_relative_to(&msa)
        );
    }

    #[test]
    pub fn decode_public_announcement() {
        let pubscript = random_public_announcement();
        let encoded = pubscript.encode();
        let decoded = *PublicAnnouncement::decode(&encoded).unwrap();
        assert_eq!(pubscript, decoded);
    }

    #[test]
    pub fn decode_public_announcements() {
        let pubscripts = vec![random_public_announcement(), random_public_announcement()];
        let encoded = pubscripts.encode();
        let decoded = *Vec::<PublicAnnouncement>::decode(&encoded).unwrap();
        assert_eq!(pubscripts, decoded);
    }

    #[test]
    pub fn test_decode_transaction_kernel() {
        let kernel = random_transaction_kernel();
        let encoded = kernel.encode();
        let decoded = *TransactionKernel::decode(&encoded).unwrap();
        assert_eq!(kernel, decoded);
    }

    #[test]
    pub fn test_decode_transaction_kernel_small() {
        let mut rng = rand::rng();
        let absolute_indices = AbsoluteIndexSet::new(
            &(0..NUM_TRIALS as usize)
                .map(|_| (u128::from(rng.next_u64()) << 64) ^ u128::from(rng.next_u64()))
                .collect_vec()
                .try_into()
                .unwrap(),
        );
        let removal_record = RemovalRecord {
            absolute_indices,
            target_chunks: Default::default(),
        };
        let kernel = TransactionKernelProxy {
            inputs: vec![removal_record],
            outputs: vec![AdditionRecord {
                canonical_commitment: random(),
            }],
            public_announcements: Default::default(),
            fee: NativeCurrencyAmount::one(),
            coinbase: None,
            timestamp: Default::default(),
            mutator_set_hash: rng.random::<Digest>(),
            merge_bit: true,
        }
        .into_kernel();
        let encoded = kernel.encode();
        println!(
            "encoded: {}",
            encoded.iter().map(|x| x.to_string()).join(", ")
        );
        let decoded = *TransactionKernel::decode(&encoded).unwrap();
        assert_eq!(kernel, decoded);
    }
}
