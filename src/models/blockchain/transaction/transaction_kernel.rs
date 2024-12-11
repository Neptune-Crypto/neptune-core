use std::sync::OnceLock;

use arbitrary::Arbitrary;
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
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::proof_abstractions::mast_hash::HasDiscriminant;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

/// TransactionKernel is immutable and its hash never changes.
///
/// See [`TransactionKernelModifier`] for generating modified copies.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, GetSize, BFieldCodec, TasmObject)]
#[readonly::make]
pub struct TransactionKernel {
    // note: see field descriptions in [`TransactionKernelProxy`]
    pub inputs: Vec<RemovalRecord>,
    pub outputs: Vec<AdditionRecord>,
    pub public_announcements: Vec<PublicAnnouncement>,
    pub fee: NeptuneCoins,
    pub coinbase: Option<NeptuneCoins>,
    pub timestamp: Timestamp,
    pub mutator_set_hash: Digest,

    // this is only here as a cache for MastHash
    // so that we lazily compute the input sequences at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[tasm_object(ignore)]
    #[get_size(ignore)]
    mast_sequences: OnceLock<Vec<Vec<BFieldElement>>>,
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

impl From<PrimitiveWitness> for TransactionKernel {
    fn from(transaction_primitive_witness: PrimitiveWitness) -> Self {
        transaction_primitive_witness.kernel
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

                vec![
                    input_utxos_sequence,
                    output_utxos_sequence,
                    pubscript_sequence,
                    fee_sequence,
                    coinbase_sequence,
                    timestamp_sequence,
                    mutator_set_hash_sequence,
                ]
            })
            .clone() // can we refactor to avoid this clone?
    }
}

impl<'a> Arbitrary<'a> for TransactionKernel {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
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
        let fee: NeptuneCoins = u.arbitrary()?;
        let coinbase: Option<NeptuneCoins> = u.arbitrary()?;
        let timestamp: Timestamp = u.arbitrary()?;
        let mutator_set_hash: Digest = u.arbitrary()?;

        let transaction_kernel = TransactionKernelProxy {
            inputs,
            outputs,
            public_announcements,
            fee,
            coinbase,
            timestamp,
            mutator_set_hash,
        }
        .into_kernel();

        Ok(transaction_kernel)
    }
}

/// performs instantiation and destructuring of [TransactionKernel]
///
/// [TransactionKernel] is immutable, so it cannot be instantiated
/// by direct field access.  This proxy is mutable, and it has an
/// into_kernel() method that converts it to a [TransactionKernel].
///
/// It is also useful for destructuring kernel fields without cloning.
pub struct TransactionKernelProxy {
    /// contains the transaction inputs.
    pub inputs: Vec<RemovalRecord>,

    /// contains the commitments (addition records) that go into the AOCL
    pub outputs: Vec<AdditionRecord>,

    /// list of public-announcements to include in blockchain
    pub public_announcements: Vec<PublicAnnouncement>,

    /// tx fee amount
    pub fee: NeptuneCoins,

    /// optional coinbase.  applies only to miner payments.
    pub coinbase: Option<NeptuneCoins>,

    /// number of milliseconds since unix epoch
    pub timestamp: Timestamp,

    /// mutator set hash *prior* to updating mutator set with this transaction.
    pub mutator_set_hash: Digest,
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
#[derive(Default)]
pub struct TransactionKernelModifier {
    pub inputs: Option<Vec<RemovalRecord>>,
    pub outputs: Option<Vec<AdditionRecord>>,
    pub public_announcements: Option<Vec<PublicAnnouncement>>,
    pub fee: Option<NeptuneCoins>,
    pub coinbase: Option<Option<NeptuneCoins>>,
    pub timestamp: Option<Timestamp>,
    pub mutator_set_hash: Option<Digest>,
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
    pub fn fee(mut self, fee: NeptuneCoins) -> Self {
        self.fee = Some(fee);
        self
    }
    /// set modified coinbase
    pub fn coinbase(mut self, coinbase: Option<NeptuneCoins>) -> Self {
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
    use rand::random;
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use rand::Rng;
    use rand::RngCore;
    use rand::SeedableRng;

    use super::*;
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
            .map(|_| pseudorandom_removal_record(rng.gen::<[u8; 32]>()))
            .collect_vec();
        let outputs = (0..num_outputs)
            .map(|_| pseudorandom_addition_record(rng.gen::<[u8; 32]>()))
            .collect_vec();
        let public_announcements = (0..num_public_announcements)
            .map(|_| pseudorandom_public_announcement(rng.gen::<[u8; 32]>()))
            .collect_vec();
        let fee = pseudorandom_amount(rng.gen::<[u8; 32]>());
        let coinbase = pseudorandom_option(rng.gen(), pseudorandom_amount(rng.gen::<[u8; 32]>()));
        let timestamp: Timestamp = rng.gen();
        let mutator_set_hash: Digest = rng.gen();

        TransactionKernelProxy {
            inputs,
            outputs,
            public_announcements,
            fee,
            coinbase,
            timestamp,
            mutator_set_hash,
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
        let mut rng = thread_rng();
        let absolute_indices = AbsoluteIndexSet::new(
            &(0..NUM_TRIALS as usize)
                .map(|_| ((rng.next_u64() as u128) << 64) ^ rng.next_u64() as u128)
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
            fee: NeptuneCoins::one(),
            coinbase: None,
            timestamp: Default::default(),
            mutator_set_hash: rng.gen::<Digest>(),
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
