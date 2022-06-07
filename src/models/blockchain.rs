use db_key::Key;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, convert::TryInto, fmt::Display, time::SystemTime};
use twenty_first::{
    amount::u32s::U32s,
    shared_math::{
        b_field_element::BFieldElement,
        rescue_prime_xlix::{RescuePrimeXlix, RP_DEFAULT_WIDTH},
        traits::FromVecu8,
    },
    util_types::{
        mmr::mmr_membership_proof::MmrMembershipProof,
        mutator_set::{
            ms_membership_proof::MsMembershipProof, mutator_set_accumulator::MutatorSetAccumulator,
            removal_record::RemovalRecord,
        },
    },
};

pub const AMOUNT_SIZE_FOR_U32: usize = 4;
pub const RESCUE_PRIME_OUTPUT_SIZE_IN_BFES: usize = 6;
pub const RESCUE_PRIME_DIGEST_SIZE_IN_BYTES: usize = RESCUE_PRIME_OUTPUT_SIZE_IN_BFES * 8;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RescuePrimeDigest([BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES]);
pub type Hasher = RescuePrimeXlix<RP_DEFAULT_WIDTH>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    amount: U32s<AMOUNT_SIZE_FOR_U32>,
    public_key_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<(Utxo, MsMembershipProof<Hasher>, RemovalRecord<Hasher>)>,
    pub outputs: Vec<Utxo>,
    pub public_scripts: Vec<Vec<u8>>,
    pub fee: U32s<AMOUNT_SIZE_FOR_U32>,
    pub timestamp: BFieldElement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MutatorSetUpdate {
    appended_leafs: Vec<RescuePrimeDigest>,
    leaf_mutations: Vec<(RescuePrimeDigest, MmrMembershipProof<Hasher>)>,
}

pub struct BlockHeader {
    pub version: BFieldElement,
    pub nonce: (BFieldElement, BFieldElement, BFieldElement),
    pub height: BFieldElement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub version_bits: BFieldElement,
    pub timestamp: BFieldElement,
    pub height: BFieldElement,
    pub predecessor: RescuePrimeDigest,
    pub uncles: Vec<RescuePrimeDigest>,
    pub accumulated_pow_line: BFieldElement,
    pub accumulated_pow_family: BFieldElement,
    pub target_difficulty: BFieldElement,
    pub max_size: BFieldElement,
    pub transactions: Vec<Transaction>,
    pub ms_commitment: RescuePrimeDigest,
    pub ms_accumulator: MutatorSetAccumulator<RescuePrimeXlix<RP_DEFAULT_WIDTH>>,
    pub ms_update: MutatorSetUpdate,
}

impl From<[u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES]> for RescuePrimeDigest {
    fn from(item: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES]) -> Self {
        let bfes: [BFieldElement; RESCUE_PRIME_OUTPUT_SIZE_IN_BFES] =
            [BFieldElement::ring_zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES];
        for i in 0..RESCUE_PRIME_OUTPUT_SIZE_IN_BFES {
            let start_index = i * RESCUE_PRIME_DIGEST_SIZE_IN_BYTES;
            let end_index = (i + 1) * RESCUE_PRIME_DIGEST_SIZE_IN_BYTES;
            bfes[i] = BFieldElement::ring_zero().from_vecu8(item[start_index..end_index].to_vec())
        }

        Self(bfes)
    }
}

impl Key for RescuePrimeDigest {
    fn from_u8(key: &[u8]) -> Self {
        let converted_key: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = key
            .to_owned()
            .try_into()
            .expect("slice with incorrect length used as block hash");
        converted_key.into()
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        let u8s: [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] = self.to_owned().into();
        f(&u8s)
    }
}

impl From<RescuePrimeDigest> for [u8; RESCUE_PRIME_DIGEST_SIZE_IN_BYTES] {
    fn from(item: RescuePrimeDigest) -> Self {
        let u64s = item.0.iter().map(|x| x.value());
        u64s.map(|x| x.to_ne_bytes())
            .collect::<Vec<_>>()
            .concat()
            .try_into()
            .unwrap()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeight(u64);

impl From<u64> for BlockHeight {
    fn from(item: u64) -> Self {
        BlockHeight(item)
    }
}

impl From<BlockHeight> for u64 {
    fn from(item: BlockHeight) -> u64 {
        item.0
    }
}

impl Key for BlockHeight {
    fn from_u8(key: &[u8]) -> Self {
        let val = u64::from_be_bytes(
            key.to_owned()
                .try_into()
                .expect("slice with incorrect length used as block height"),
        );
        BlockHeight(val)
    }

    fn as_slice<T, F: Fn(&[u8]) -> T>(&self, f: F) -> T {
        let val = u64::to_be_bytes(self.0);
        f(&val)
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0).cmp(&(other.0))
    }
}

impl PartialOrd for BlockHeight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
