// Mock datatypes to fascilitate progress.

use crate::models::blockchain::transaction::AMOUNT_SIZE_FOR_U32;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use twenty_first::amount::u32s::U32s;

use super::transaction::utxo::Utxo;

pub type Address = secp256k1::PublicKey;
pub type Amount = u32;
pub type TxSpec = Vec<Tx>;
pub type SimpleUtxoSet = Vec<Utxo>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Tx {
    pub recipient_address: Address,
    pub amount: Amount,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleWallet {
    utxos: SimpleUtxoSet,
    secret_key: secp256k1::SecretKey,
    pub public_key: secp256k1::PublicKey,
}

impl SimpleWallet {
    pub fn new() -> Self {
        let secp = secp256k1::Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::rngs::OsRng);
        Self {
            utxos: vec![Utxo::new(U32s::new([42, 0, 0, 0]), public_key)],
            secret_key,
            public_key,
        }
    }

    pub fn get_all_utxos(&self) -> SimpleUtxoSet {
        self.utxos.clone()
    }

    pub fn get_balance(&self) -> Amount {
        let res: BigUint = self
            .utxos
            .iter()
            .map(|utxo| utxo.amount)
            .sum::<U32s<AMOUNT_SIZE_FOR_U32>>()
            .into();
        res.try_into().unwrap()
    }

    pub fn sign(&self, tx: &UnsignedSimpleTransaction) -> SignedSimpleTransaction {
        let secp = secp256k1::Secp256k1::new();
        let message = secp256k1::Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(
            "tx".as_bytes(),
        );
        SignedSimpleTransaction {
            tx: tx.to_owned(),
            signature: secp.sign_ecdsa(&message, &self.secret_key),
        }
    }
}

impl Default for SimpleWallet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UnsignedSimpleTransaction {
    pub inputs: Vec<Utxo>,
    pub outputs: Vec<Utxo>,
}

impl UnsignedSimpleTransaction {
    pub fn new(inputs: Vec<Utxo>, outputs: Vec<Utxo>) -> Self {
        Self { inputs, outputs }
    }

    pub fn sign(&self, wallet: &SimpleWallet) -> SignedSimpleTransaction {
        wallet.sign(self)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignedSimpleTransaction {
    pub tx: UnsignedSimpleTransaction,
    signature: secp256k1::ecdsa::Signature,
}
