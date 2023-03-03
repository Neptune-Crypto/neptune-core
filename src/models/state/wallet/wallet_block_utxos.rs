use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::ops::Add;
use twenty_first::shared_math::rescue_prime_digest::Digest;

use crate::models::blockchain::transaction::{amount::Amount, utxo::Utxo};

/// The parts of a block that this wallet wants to keep track of,
/// ie. the input and output UTXOs that share this wallet's public key.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct WalletBlockUtxos {
    pub input_utxos: Vec<Utxo>,
    pub output_utxos: Vec<(Utxo, Digest)>,
}

pub struct WalletBlockIOSums {
    pub input_sum: Amount,
    pub output_sum: Amount,
}

impl Default for WalletBlockIOSums {
    fn default() -> Self {
        Self {
            input_sum: Amount::zero(),
            output_sum: Amount::zero(),
        }
    }
}

impl Add for WalletBlockIOSums {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            input_sum: self.input_sum + other.input_sum,
            output_sum: self.output_sum + other.output_sum,
        }
    }
}

impl WalletBlockUtxos {
    pub fn new(input_utxos: Vec<Utxo>, output_utxos: Vec<(Utxo, Digest)>) -> Self {
        Self {
            input_utxos,
            output_utxos,
        }
    }

    pub fn get_io_sums(&self) -> WalletBlockIOSums {
        WalletBlockIOSums {
            input_sum: self.input_utxos.iter().map(|utxo| utxo.amount).sum(),
            output_sum: self
                .output_utxos
                .iter()
                .map(|(utxo, _digest)| utxo.amount)
                .sum(),
        }
    }
}
