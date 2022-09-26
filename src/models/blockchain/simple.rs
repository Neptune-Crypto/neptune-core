// Mock datatypes to fascilitate progress.
use super::{
    digest::Hashable,
    transaction::{utxo::Utxo, Amount},
};
use secp256k1::ecdsa::Signature;
use twenty_first::amount::u32s::U32s;

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
