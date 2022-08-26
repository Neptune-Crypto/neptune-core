// Mock datatypes to fascilitate progress.
use super::{
    digest::Hashable,
    transaction::{devnet_input::DevNetInput, utxo::Utxo},
};
use crate::models::blockchain::transaction::AMOUNT_SIZE_FOR_U32;
use mutator_set_tf::util_types::mutator_set::{
    chunk::Chunk, chunk_dictionary::ChunkDictionary, removal_record::RemovalRecord,
    shared::NUM_TRIALS, transfer_ms_membership_proof::TransferMsMembershipProof,
};
use num_traits::Zero;
use secp256k1::ecdsa::Signature;
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
use twenty_first::{
    amount::u32s::U32s,
    shared_math::{
        b_field_element::BFieldElement,
        rescue_prime_xlix::{RescuePrimeXlix, RP_DEFAULT_WIDTH},
    },
    util_types::{
        mmr::{self, mmr_membership_proof::MmrMembershipProof},
        simple_hasher::Hasher,
    },
};

pub type Amount = U32s<AMOUNT_SIZE_FOR_U32>;

impl super::transaction::devnet_input::DevNetInput {
    pub fn new(input_utxo: &Utxo, wallet: &SimpleWallet) -> Self {
        // This is utterly rubbish to generate a valid dummy type.
        type Hash = RescuePrimeXlix<RP_DEFAULT_WIDTH>;
        let hasher = Hash::new();

        let target_chunks = ChunkDictionary::<Hash> {
            // {chunk index => (membership proof for the whole chunk to which bit belongs, chunk value)}
            dictionary:
                HashMap::<u128, (mmr::mmr_membership_proof::MmrMembershipProof<Hash>, Chunk)>::new(),
        };

        let removal_record = RemovalRecord::<Hash> {
            bit_indices: [0u128; NUM_TRIALS],
            target_chunks: target_chunks.clone(),
        };

        let random_digest = hasher.hash(&[BFieldElement::new(42)], 42);

        let mmp = MmrMembershipProof::<Hash> {
            data_index: 42,
            authentication_path: vec![random_digest.clone(); 42],
        };

        let membership_proof = TransferMsMembershipProof::<Hash> {
            randomness: random_digest,
            auth_path_aocl: mmp,
            target_chunks,
        };

        Self {
            utxo: input_utxo.clone(),
            membership_proof,
            removal_record,
            signature: wallet.sign(input_utxo),
        }
    }
}

impl super::transaction::Transaction {
    pub fn new(inputs: Vec<Utxo>, outputs: Vec<Utxo>, wallet: &SimpleWallet) -> Self {
        let input_utxos_with_signature = inputs
            .iter()
            .map(|in_utxo| DevNetInput::new(in_utxo, wallet))
            .collect::<Vec<_>>();

        // TODO: This is probably the wrong digest.  Other code uses: output_randomness.clone().into()
        let output_utxos_with_digest = outputs
            .into_iter()
            .map(|out_utxo| (out_utxo.clone(), out_utxo.hash()))
            .collect::<Vec<_>>();

        let timestamp = BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Timestamping failed")
                .as_secs(),
        );

        Self {
            inputs: input_utxos_with_signature,
            outputs: output_utxos_with_digest,
            public_scripts: vec![],
            fee: U32s::zero(),
            timestamp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleWallet {
    utxos: Vec<Utxo>,
    /// This `secret_key` corresponds to a `master_private_key` for Bitcoin wallet.
    /// From this master key several individual UTXO private keys can be derived using this [scheme][scheme]
    /// [scheme]: https://learnmeabitcoin.com/technical/derivation-paths
    secret_key: secp256k1::SecretKey,
    pub public_key: secp256k1::PublicKey,
}

impl SimpleWallet {
    pub fn new() -> Self {
        let secp = secp256k1::Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::rngs::OsRng);
        Self {
            utxos: vec![Utxo::new(U32s::new([42, 42, 42, 42]), public_key)],
            secret_key,
            public_key,
        }
    }

    pub fn get_all_utxos(&self) -> Vec<Utxo> {
        self.utxos.clone()
    }

    pub fn get_balance(&self) -> Amount {
        self.utxos.iter().map(|utxo| utxo.amount).sum()
    }

    pub fn sign(&self, input_utxo: &Utxo) -> Signature {
        let secp = secp256k1::Secp256k1::new();

        let digest = &bincode::serialize(&input_utxo.hash()).unwrap()[..];

        let message =
            secp256k1::Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(digest);
        secp.sign_ecdsa(&message, &self.secret_key)
    }
}

impl Default for SimpleWallet {
    fn default() -> Self {
        Self::new()
    }
}
