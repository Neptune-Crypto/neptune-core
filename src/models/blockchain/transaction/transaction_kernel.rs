use arbitrary::Arbitrary;
use get_size::GetSize;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;
use strum::EnumCount;
use tasm_lib::structure::tasm_object::TasmObject;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::tip5::Digest;

use crate::models::blockchain::type_scripts::neptune_coins::pseudorandom_amount;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::consensus::mast_hash::HasDiscriminant;
use crate::models::consensus::mast_hash::MastHash;
use crate::models::consensus::timestamp::Timestamp;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::pseudorandom_addition_record;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::removal_record::pseudorandom_removal_record;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

use super::primitive_witness::PrimitiveWitness;
use super::PublicAnnouncement;

pub fn pseudorandom_public_announcement(seed: [u8; 32]) -> PublicAnnouncement {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let len = 10 + (rng.next_u32() % 50) as usize;
    let message = (0..len).map(|_| rng.gen()).collect_vec();
    PublicAnnouncement { message }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct TransactionKernel {
    pub inputs: Vec<RemovalRecord>,

    // `outputs` contains the commitments (addition records) that go into the AOCL
    pub outputs: Vec<AdditionRecord>,

    pub public_announcements: Vec<PublicAnnouncement>,
    pub fee: NeptuneCoins,
    pub coinbase: Option<NeptuneCoins>,

    // number of milliseconds since unix epoch
    pub timestamp: Timestamp,

    pub mutator_set_hash: Digest,
}

impl From<PrimitiveWitness> for TransactionKernel {
    fn from(transaction_primitive_witness: PrimitiveWitness) -> Self {
        transaction_primitive_witness.kernel
    }
}

#[derive(Debug, Clone, EnumCount)]
pub enum TransactionKernelField {
    InputUtxos,
    OutputUtxos,
    PublicAnnouncements,
    Fee,
    Coinbase,
    Timestamp,
    MutatorSetHash,
}

impl HasDiscriminant for TransactionKernelField {
    fn discriminant(&self) -> usize {
        self.clone() as usize
    }
}

impl MastHash for TransactionKernel {
    type FieldEnum = TransactionKernelField;

    /// Return the sequences (= leaf preimages) of the kernel Merkle tree.
    fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
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
    }
}

pub fn pseudorandom_option<T>(seed: [u8; 32], thing: T) -> Option<T> {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    if rng.next_u32() % 2 == 0 {
        None
    } else {
        Some(thing)
    }
}

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

    TransactionKernel {
        inputs,
        outputs,
        public_announcements,
        fee,
        coinbase,
        timestamp,
        mutator_set_hash,
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
        let timestamp = Timestamp::now();
        let mutator_set_hash: Digest = u.arbitrary()?;

        let transaction_kernel = TransactionKernel {
            inputs,
            outputs,
            public_announcements,
            fee,
            coinbase,
            timestamp,
            mutator_set_hash,
        };

        Ok(transaction_kernel)
    }
}

#[cfg(test)]
pub mod transaction_kernel_tests {
    use rand::random;
    use rand::thread_rng;
    use rand::Rng;
    use rand::RngCore;

    use crate::tests::shared::random_public_announcement;
    use crate::tests::shared::random_transaction_kernel;
    use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;

    use super::*;

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
        let kernel = TransactionKernel {
            inputs: vec![removal_record],
            outputs: vec![AdditionRecord {
                canonical_commitment: random(),
            }],
            public_announcements: Default::default(),
            fee: NeptuneCoins::one_nau(),
            coinbase: None,
            timestamp: Default::default(),
            mutator_set_hash: rng.gen::<Digest>(),
        };
        let encoded = kernel.encode();
        println!(
            "encoded: {}",
            encoded.iter().map(|x| x.to_string()).join(", ")
        );
        let decoded = *TransactionKernel::decode(&encoded).unwrap();
        assert_eq!(kernel, decoded);
    }
}
