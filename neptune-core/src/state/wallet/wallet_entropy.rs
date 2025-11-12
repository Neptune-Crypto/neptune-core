use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe_vec;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::math::x_field_element::XFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;
use tasm_lib::twenty_first::xfe;
use zeroize::ZeroizeOnDrop;

use super::address::ReceivingAddress;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::state::wallet::address::generation_address;
use crate::state::wallet::address::symmetric_key;
use crate::state::wallet::secret_key_material::SecretKeyMaterial;

/// The wallet's one source of randomness, from which all keys are derived.
///
/// This struct wraps around [`SecretKeyMaterial`], which contains the secret
/// data. The wrapper supplies arithmetic functions for use in the context of a
/// wallet for Neptune Cash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct WalletEntropy {
    secret_seed: SecretKeyMaterial,
}

impl WalletEntropy {
    pub(crate) fn new(secret_seed: SecretKeyMaterial) -> Self {
        Self { secret_seed }
    }

    /// Create a `WalletEntropy` object with a fixed digest
    pub fn devnet_wallet() -> Self {
        let secret_seed = SecretKeyMaterial(xfe!([
            12063201067205522823_u64,
            1529663126377206632_u64,
            2090171368883726200_u64,
        ]));

        Self::new(secret_seed)
    }

    /// Returns the spending key for guesser rewards.
    pub fn guesser_fee_key(&self) -> generation_address::GenerationSpendingKey {
        self.nth_generation_spending_key(0u64)
    }

    /// Returns the spending key for prover rewards, *i.e.*, composer fee or
    /// proof-upgrader (gobbling) fee.
    pub fn composer_fee_key(&self) -> generation_address::GenerationSpendingKey {
        self.nth_generation_spending_key(0u64)
    }

    /// Returns the receiving address for prover rewards, *i.e.*, composer fee
    /// or proof-upgrader (gobbling) fee.
    pub(crate) fn prover_fee_address(&self) -> ReceivingAddress {
        self.composer_fee_key().to_address().into()
    }

    /// derives a generation spending key at `index`
    //
    // note: this is a read-only method and does not modify wallet state.  When
    // requesting a new key for purposes of a new wallet receiving address,
    // callers should use [wallet_state::WalletState::next_unused_spending_key()]
    // which takes &mut self.
    pub fn nth_generation_spending_key(
        &self,
        index: u64,
    ) -> generation_address::GenerationSpendingKey {
        // We keep n between 0 and 2^16 as this makes it possible to scan all possible addresses
        // in case you don't know with what counter you made the address
        let key_seed = Tip5::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                bfe_vec![generation_address::GENERATION_FLAG, index],
            ]
            .concat(),
        );
        generation_address::GenerationSpendingKey::derive_from_seed(key_seed)
    }

    /// derives a symmetric key at `index`
    //
    // note: this is a read-only method and does not modify wallet state.  When
    // requesting a new key for purposes of a new wallet receiving address,
    // callers should use [wallet_state::WalletState::next_unused_spending_key()]
    // which takes &mut self.
    pub fn nth_symmetric_key(&self, index: u64) -> symmetric_key::SymmetricKey {
        let key_seed = Tip5::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                bfe_vec![symmetric_key::SYMMETRIC_KEY_FLAG, index],
            ]
            .concat(),
        );
        symmetric_key::SymmetricKey::from_seed(key_seed)
    }

    // note: legacy tests were written to call nth_generation_spending_key()
    // when requesting a new address.  As such, they may be unprepared to mutate
    // wallet state.  This method enables them to compile while making clear
    // it is an improper usage.
    //
    // [wallet_state::WalletState::next_unused_generation_spending_key()] should be used
    #[cfg(test)]
    pub fn nth_generation_spending_key_for_tests(
        &self,
        counter: u64,
    ) -> generation_address::GenerationSpendingKey {
        self.nth_generation_spending_key(counter)
    }

    // note: legacy tests were written to call nth_symmetric_key()
    // when requesting a new key.  As such, they may be unprepared to mutate
    // wallet state.  This method enables them to compile while making clear
    // it is an improper usage.
    //
    // [wallet_state::WalletState::next_unused_symmetric_key()] should be used
    #[cfg(test)]
    pub fn nth_symmetric_key_for_tests(&self, counter: u64) -> symmetric_key::SymmetricKey {
        self.nth_symmetric_key(counter)
    }

    /// Return a deterministic seed that can be used to seed an RNG
    pub(crate) fn deterministic_derived_seed(&self, block_height: BlockHeight) -> Digest {
        const SEED_FLAG: u64 = 0x2315439570c4a85fu64;
        Tip5::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                bfe_vec![SEED_FLAG, block_height],
            ]
            .concat(),
        )
    }

    /// Return a seed used to randomize shuffling.
    pub(crate) fn shuffle_seed(&self, block_height: BlockHeight) -> [u8; 32] {
        let secure_seed_from_wallet = self.deterministic_derived_seed(block_height);
        let seed: [u8; Digest::BYTES] = secure_seed_from_wallet.into();

        seed[0..32].try_into().unwrap()
    }

    /// Return the secret key that is used to deterministically generate commitment pseudo-randomness
    /// for the mutator set.
    pub fn generate_sender_randomness(
        &self,
        block_height: BlockHeight,
        receiver_digest: Digest,
    ) -> Digest {
        const SENDER_RANDOMNESS_FLAG: u64 = 0x5e116e1270u64;
        Tip5::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                bfe_vec![SENDER_RANDOMNESS_FLAG, block_height],
                receiver_digest.encode(),
            ]
            .concat(),
        )
    }

    /// Convert a secret seed phrase (list of 18 valid BIP-39 words) to a
    /// [`WalletEntropy`] object
    pub fn from_phrase(phrase: &[String]) -> Result<Self> {
        let key = SecretKeyMaterial::from_phrase(phrase)?;
        Ok(Self::new(key))
    }
}

impl From<SecretKeyMaterial> for WalletEntropy {
    fn from(value: SecretKeyMaterial) -> Self {
        Self { secret_seed: value }
    }
}

impl From<WalletEntropy> for SecretKeyMaterial {
    fn from(value: WalletEntropy) -> Self {
        value.secret_seed
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    impl WalletEntropy {
        /// Create a new `WalletEntropy` object and populate it with entropy
        /// obtained via `rand::rng()` from the operating system.
        pub(crate) fn new_random() -> Self {
            Self::new_pseudorandom(rand::Rng::random(&mut rand::rng()))
        }

        /// Create a new `WalletEntropy` object and populate it by expanding a given
        /// seed.
        pub(crate) fn new_pseudorandom(seed: [u8; 32]) -> Self {
            let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);
            Self {
                secret_seed: SecretKeyMaterial(rand::Rng::random(&mut rng)),
            }
        }
    }

    #[proptest(cases = 10)]
    fn prover_fee_address_agrees_with_receiver_preimage(
        #[strategy(arb())] wallet_entropy: WalletEntropy,
    ) {
        prop_assert_eq!(
            wallet_entropy.composer_fee_key().receiver_preimage().hash(),
            wallet_entropy.prover_fee_address().privacy_digest(),
        );
    }
}
