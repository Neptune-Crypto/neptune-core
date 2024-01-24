use get_size::GetSize;
use itertools::Itertools;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use tasm_lib::structure::tasm_object::TasmObject;
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec, tip5::Digest},
    util_types::{
        algebraic_hasher::AlgebraicHasher,
        merkle_tree::{CpuParallel, MerkleTree},
        merkle_tree_maker::MerkleTreeMaker,
    },
};

use super::{amount::pseudorandom_amount, Amount, PublicAnnouncement};
use crate::{
    util_types::mutator_set::{
        addition_record::{pseudorandom_addition_record, AdditionRecord},
        removal_record::{pseudorandom_removal_record, RemovalRecord},
    },
    Hash,
};

pub fn pseudorandom_public_announcement(seed: [u8; 32]) -> PublicAnnouncement {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let len = 10 + (rng.next_u32() % 50) as usize;
    let message = (0..len).map(|_| rng.gen()).collect_vec();
    PublicAnnouncement { message }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct TransactionKernel {
    pub inputs: Vec<RemovalRecord<Hash>>,

    // `outputs` contains the commitments (addition records) that go into the AOCL
    pub outputs: Vec<AdditionRecord>,

    pub public_announcements: Vec<PublicAnnouncement>,
    pub fee: Amount,
    pub coinbase: Option<Amount>,

    // number of milliseconds since unix epoch
    pub timestamp: BFieldElement,

    pub mutator_set_hash: Digest,
}

pub enum TransactionKernelField {
    InputUtxos,
    OutputUtxos,
    Pubscript,
    Fee,
    Coinbase,
    Timestamp,
    MutatorSetHash,
}

impl TransactionKernelField {
    pub fn discriminant(&self) -> usize {
        match self {
            TransactionKernelField::InputUtxos => 0,
            TransactionKernelField::OutputUtxos => 1,
            TransactionKernelField::Pubscript => 2,
            TransactionKernelField::Fee => 3,
            TransactionKernelField::Coinbase => 4,
            TransactionKernelField::Timestamp => 5,
            TransactionKernelField::MutatorSetHash => 6,
        }
    }
}

impl TransactionKernel {
    /// Return the sequences (= leaf preimages) of the kernel Merkle tree.
    pub fn mast_sequences(&self) -> Vec<Vec<BFieldElement>> {
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

    fn merkle_tree(&self) -> MerkleTree<Hash> {
        // get a sequence of BFieldElements for each field
        let sequences = self.mast_sequences();

        let mut mt_leafs = sequences
            .iter()
            .map(|seq| Hash::hash_varlen(seq))
            .collect_vec();

        // pad until power of two
        while mt_leafs.len() & (mt_leafs.len() - 1) != 0 {
            mt_leafs.push(Digest::default());
        }

        // compute Merkle tree and return hash
        <CpuParallel as MerkleTreeMaker<Hash>>::from_digests(&mt_leafs)
    }

    pub fn mast_path(&self, field: TransactionKernelField) -> Vec<Digest> {
        self.merkle_tree()
            .get_authentication_structure(&[field.discriminant()])
    }

    pub fn mast_hash(&self) -> Digest {
        self.merkle_tree().get_root()
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
    num_pubscripts: usize,
) -> TransactionKernel {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let inputs = (0..num_inputs)
        .map(|_| pseudorandom_removal_record(rng.gen::<[u8; 32]>()))
        .collect_vec();
    let outputs = (0..num_outputs)
        .map(|_| pseudorandom_addition_record(rng.gen::<[u8; 32]>()))
        .collect_vec();
    let pubscripts = (0..num_pubscripts)
        .map(|_| pseudorandom_public_announcement(rng.gen::<[u8; 32]>()))
        .collect_vec();
    let fee = pseudorandom_amount(rng.gen::<[u8; 32]>());
    let coinbase = pseudorandom_option(rng.gen(), pseudorandom_amount(rng.gen::<[u8; 32]>()));
    let timestamp: BFieldElement = rng.gen();
    let mutator_set_hash: Digest = rng.gen();

    TransactionKernel {
        inputs,
        outputs,
        public_announcements: pubscripts,
        fee,
        coinbase,
        timestamp,
        mutator_set_hash,
    }
}

#[cfg(test)]
pub mod transaction_kernel_tests {

    use rand::{random, thread_rng, Rng, RngCore};

    use crate::{
        tests::shared::{random_public_announcement, random_transaction_kernel},
        util_types::mutator_set::{removal_record::AbsoluteIndexSet, shared::NUM_TRIALS},
    };

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
            fee: Amount::one(),
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
