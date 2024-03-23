use crate::prelude::twenty_first;

pub mod address;
pub mod coin_with_possible_timelock;
pub mod monitored_utxo;
pub mod rusty_wallet_database;
pub mod utxo_notification_pool;
pub mod wallet_state;
pub mod wallet_status;

use anyhow::{bail, Context, Result};
use bip39::Mnemonic;
use itertools::Itertools;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::fs::{self};
use std::path::{Path, PathBuf};
use tracing::info;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::digest::Digest;
use twenty_first::shared_math::x_field_element::XFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use zeroize::{Zeroize, ZeroizeOnDrop};

use twenty_first::shared_math::b_field_element::BFieldElement;

use crate::models::blockchain::block::block_height::BlockHeight;

use crate::Hash;

use self::address::generation_address;

pub const WALLET_DIRECTORY: &str = "wallet";
pub const WALLET_SECRET_FILE_NAME: &str = "wallet.dat";
pub const WALLET_OUTGOING_SECRETS_FILE_NAME: &str = "outgoing_randomness.dat";
pub const WALLET_INCOMING_SECRETS_FILE_NAME: &str = "incoming_randomness.dat";
const STANDARD_WALLET_NAME: &str = "standard_wallet";
const STANDARD_WALLET_VERSION: u8 = 0;
pub const WALLET_DB_NAME: &str = "wallet";
pub const WALLET_OUTPUT_COUNT_DB_NAME: &str = "wallout_output_count_db";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct SecretKeyMaterial(XFieldElement);

impl Zeroize for SecretKeyMaterial {
    fn zeroize(&mut self) {
        self.0 = XFieldElement::zero();
    }
}

/// Wallet contains the wallet-related data we want to store in a JSON file,
/// and that is not updated during regular program execution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
pub struct WalletSecret {
    name: String,

    secret_seed: SecretKeyMaterial,
    version: u8,
}

/// Struct for containing file paths for secrets. To be communicated to user upon
/// wallet creation or wallet opening.
pub struct WalletSecretFileLocations {
    pub wallet_secret_path: PathBuf,
    pub incoming_randomness_file: PathBuf,
    pub outgoing_randomness_file: PathBuf,
}

impl WalletSecret {
    pub fn wallet_secret_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_SECRET_FILE_NAME)
    }

    fn wallet_outgoing_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_OUTGOING_SECRETS_FILE_NAME)
    }

    fn wallet_incoming_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_INCOMING_SECRETS_FILE_NAME)
    }

    /// Create new `Wallet` given a `secret` key.
    fn new(secret_seed: SecretKeyMaterial) -> Self {
        Self {
            name: STANDARD_WALLET_NAME.to_string(),
            secret_seed,
            version: STANDARD_WALLET_VERSION,
        }
    }

    /// Create a new `Wallet` and populate it with a new secret seed, with entropy
    /// obtained via `thread_rng()` from the operating system.
    pub fn new_random() -> Self {
        Self::new_pseudorandom(thread_rng().gen())
    }

    /// Create a new `Wallet` and populate it by expanding a given seed.
    pub fn new_pseudorandom(seed: [u8; 32]) -> Self {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        Self {
            name: STANDARD_WALLET_NAME.to_string(),
            secret_seed: SecretKeyMaterial(rng.gen()),
            version: STANDARD_WALLET_VERSION,
        }
    }

    /// Create a `Wallet` with a fixed digest
    pub fn devnet_wallet() -> Self {
        let secret_seed = SecretKeyMaterial(XFieldElement::new([
            BFieldElement::new(12063201067205522823),
            BFieldElement::new(1529663126377206632),
            BFieldElement::new(2090171368883726200),
        ]));

        WalletSecret::new(secret_seed)
    }

    /// Read wallet from `wallet_file` if the file exists, or, if none exists, create new wallet
    /// and save it to `wallet_file`.
    /// Also create files for incoming and outgoing randomness which should be appended to
    /// on each incoming and outgoing transaction.
    /// Returns an instance of self and the path in which the wallet secret was stored.
    pub fn read_from_file_or_create(
        wallet_directory_path: &Path,
    ) -> Result<(Self, WalletSecretFileLocations)> {
        let wallet_secret_path = Self::wallet_secret_path(wallet_directory_path);
        let wallet = if wallet_secret_path.exists() {
            info!(
                "***** Reading wallet from {} *****\n\n\n",
                wallet_secret_path.display()
            );
            Self::read_from_file(&wallet_secret_path)?
        } else {
            info!(
                "***** Creating new wallet in {} *****\n\n\n",
                wallet_secret_path.display()
            );
            let new_wallet: WalletSecret = WalletSecret::new_random();
            new_wallet.save_to_disk(&wallet_secret_path)?;
            new_wallet
        };

        // Generate files for outgoing and ingoing randomness if those files
        // do not already exist
        let outgoing_randomness_file: PathBuf =
            Self::wallet_outgoing_secrets_path(wallet_directory_path);
        if !outgoing_randomness_file.exists() {
            Self::create_empty_wallet_randomness_file(&outgoing_randomness_file).expect(
                "Create file for outgoing randomness must succeed. Attempted to create file: {outgoing_randomness_file}",
            );
        }

        let incoming_randomness_file = Self::wallet_incoming_secrets_path(wallet_directory_path);
        if !incoming_randomness_file.exists() {
            Self::create_empty_wallet_randomness_file(&incoming_randomness_file).expect("Create file for outgoing randomness must succeed. Attempted to create file: {incoming_randomness_file}");
        }

        // Sanity checks that files were actually created
        if !wallet_secret_path.exists() {
            bail!(
                "Wallet secret file '{}' must exist on disk after reading/creating it.",
                wallet_secret_path.to_string_lossy()
            );
        }
        if !outgoing_randomness_file.exists() {
            bail!(
                "file containing outgoing randomness '{}' must exist on disk.",
                outgoing_randomness_file.to_string_lossy()
            );
        }
        if !incoming_randomness_file.exists() {
            bail!(
                "file containing ingoing randomness '{}' must exist on disk.",
                incoming_randomness_file.to_string_lossy()
            );
        }

        let wallet_secret_file_locations = WalletSecretFileLocations {
            wallet_secret_path,
            incoming_randomness_file,
            outgoing_randomness_file,
        };

        Ok((wallet, wallet_secret_file_locations))
    }

    pub fn nth_generation_spending_key(&self, counter: u16) -> generation_address::SpendingKey {
        assert!(
            counter.is_zero(),
            "For now we only support one generation address per wallet"
        );

        // We keep n between 0 and 2^16 as this makes it possible to scan all possible addresses
        // in case you don't know with what counter you made the address
        let key_seed = Hash::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                vec![
                    generation_address::GENERATION_FLAG,
                    BFieldElement::new(counter.into()),
                ],
            ]
            .concat(),
        );
        generation_address::SpendingKey::derive_from_seed(key_seed)
    }

    /// Return the secret key that is used to deterministically generate commitment pseudo-randomness
    /// for the mutator set.
    pub fn generate_sender_randomness(
        &self,
        block_height: BlockHeight,
        receiver_digest: Digest,
    ) -> Digest {
        const SENDER_RANDOMNESS_FLAG: u64 = 0x5e116e1270u64;
        Hash::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                vec![
                    BFieldElement::new(SENDER_RANDOMNESS_FLAG),
                    block_height.into(),
                ],
                receiver_digest.encode(),
            ]
            .concat(),
        )
    }

    /// Read Wallet from file as JSON
    pub fn read_from_file(wallet_file: &Path) -> Result<Self> {
        let wallet_file_content: String = fs::read_to_string(wallet_file).with_context(|| {
            format!(
                "Failed to read wallet from {}",
                wallet_file.to_string_lossy(),
            )
        })?;

        serde_json::from_str::<WalletSecret>(&wallet_file_content).with_context(|| {
            format!(
                "Failed to decode wallet from {}",
                wallet_file.to_string_lossy(),
            )
        })
    }

    /// Used to generate both the file for incoming and outgoing randomness
    fn create_empty_wallet_randomness_file(file_path: &Path) -> Result<()> {
        let init_value: String = String::default();

        #[cfg(unix)]
        {
            Self::create_wallet_file_unix(&file_path.to_path_buf(), init_value)
        }
        #[cfg(not(unix))]
        {
            Self::create_wallet_file_windows(&file_path.to_path_buf(), init_value)
        }
    }

    /// Save this wallet to disk. If necessary, create the file (with restrictive permissions).
    pub fn save_to_disk(&self, wallet_file: &Path) -> Result<()> {
        let wallet_secret_as_json: String = serde_json::to_string(self).unwrap();

        #[cfg(unix)]
        {
            Self::create_wallet_file_unix(&wallet_file.to_path_buf(), wallet_secret_as_json)
        }
        #[cfg(not(unix))]
        {
            Self::create_wallet_file_windows(&wallet_file.to_path_buf(), wallet_secret_as_json)
        }
    }

    #[cfg(unix)]
    /// Create a wallet file, and set restrictive permissions
    fn create_wallet_file_unix(path: &PathBuf, file_content: String) -> Result<()> {
        // On Unix/Linux we set the file permissions to 600, to disallow
        // other users on the same machine to access the secrets.
        // I don't think the `std::os::unix` library can be imported on a Windows machine,
        // so this function and the below import is only compiled on Unix machines.
        use std::os::unix::prelude::OpenOptionsExt;
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        fs::write(path.clone(), file_content).context("Failed to write wallet file to disk")
    }

    #[cfg(not(unix))]
    /// Create a wallet file, without setting restrictive UNIX permissions
    fn create_wallet_file_windows(path: &PathBuf, wallet_as_json: String) -> Result<()> {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .unwrap();
        fs::write(path.clone(), wallet_as_json).context("Failed to write wallet file to disk")
    }

    /// Convert the wallet secret into a BIP-39 phrase consisting of 18 words (for 192
    /// bits of entropy).
    pub fn to_phrase(&self) -> Vec<String> {
        let entropy = self
            .secret_seed
            .0
            .coefficients
            .iter()
            .flat_map(|bfe| bfe.value().to_le_bytes())
            .collect_vec();
        assert_eq!(
            entropy.len(),
            24,
            "Entropy for secret seed does not consist of 24 bytes."
        );
        let mnemonic = Mnemonic::from_entropy(&entropy, bip39::Language::English)
            .expect("Wrong entropy length (should be 24 bytes).");
        mnemonic
            .phrase()
            .split(' ')
            .map(|s| s.to_string())
            .collect_vec()
    }

    /// Convert a secret seed phrase (list of 18 valid BIP-39 words) to a WalletSecret
    pub fn from_phrase(phrase: &[String]) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(&phrase.iter().join(" "), bip39::Language::English)?;
        let secret_seed: [u8; 24] = mnemonic.entropy().try_into().unwrap();
        let xfe = XFieldElement::new(
            secret_seed
                .chunks(8)
                .map(|ch| u64::from_le_bytes(ch.try_into().unwrap()))
                .map(BFieldElement::new)
                .collect_vec()
                .try_into()
                .unwrap(),
        );
        Ok(Self::new(SecretKeyMaterial(xfe)))
    }
}

#[cfg(test)]
mod wallet_tests {
    use std::time::Duration;

    use crate::database::storage::storage_vec::traits::*;
    use itertools::Itertools;
    use num_traits::CheckedSub;
    use rand::random;
    use tracing_test::traced_test;
    use twenty_first::shared_math::tip5::DIGEST_LENGTH;
    use twenty_first::shared_math::x_field_element::EXTENSION_DEGREE;

    use super::monitored_utxo::MonitoredUtxo;
    use super::wallet_state::WalletState;
    use super::*;
    use crate::config_models::network::Network;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::shared::Hash;
    use crate::models::blockchain::transaction::utxo::{LockScript, Utxo};
    use crate::models::blockchain::transaction::PublicAnnouncement;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::state::wallet::utxo_notification_pool::UtxoNotifier;
    use crate::models::state::UtxoReceiverData;
    use crate::tests::shared::{
        add_block, get_mock_global_state, get_mock_wallet_state, make_mock_block,
        make_mock_transaction_with_generation_key,
    };
    use crate::util_types::mutator_set::mutator_set_trait::*;

    async fn get_monitored_utxos(wallet_state: &WalletState) -> Vec<MonitoredUtxo> {
        // note: we could just return a DbtVec here and avoid cloning...
        wallet_state.wallet_db.monitored_utxos().get_all().await
    }

    #[tokio::test]
    async fn wallet_state_constructor_with_genesis_block_test() -> Result<()> {
        let mut rng = thread_rng();
        // This test is designed to verify that the genesis block is applied
        // to the wallet state at initialization.
        let network = Network::Testnet;
        let mut wallet_state_premine_recipient =
            get_mock_wallet_state(WalletSecret::devnet_wallet(), network).await;
        let monitored_utxos_premine_wallet =
            get_monitored_utxos(&wallet_state_premine_recipient).await;
        assert_eq!(
            1,
            monitored_utxos_premine_wallet.len(),
            "Monitored UTXO list must contain premined UTXO at init, for premine-wallet"
        );

        let expected_premine_utxo = Block::premine_utxos()[0].clone();
        assert_eq!(
            expected_premine_utxo, monitored_utxos_premine_wallet[0].utxo,
            "Auth wallet's monitored UTXO must match that from genesis block at initialization"
        );

        let random_wallet = WalletSecret::new_random();
        let wallet_state_other = get_mock_wallet_state(random_wallet, network).await;
        let monitored_utxos_other = get_monitored_utxos(&wallet_state_other).await;
        assert!(
            monitored_utxos_other.is_empty(),
            "Monitored UTXO list must be empty at init if wallet is not premine-wallet"
        );

        // Add 12 blocks and verify that membership proofs are still valid
        let genesis_block = Block::genesis_block().await;
        let mut next_block = genesis_block.clone();
        let other_wallet_secret = WalletSecret::new_random();
        let other_receiver_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        for _ in 0..12 {
            let previous_block = next_block;
            let (nb, _coinbase_utxo, _sender_randomness) =
                make_mock_block(&previous_block, None, other_receiver_address, rng.gen()).await;
            next_block = nb;
            let current_mutator_set_accumulator =
                previous_block.kernel.body.mutator_set_accumulator.clone();
            wallet_state_premine_recipient
                .update_wallet_state_with_new_block(&current_mutator_set_accumulator, &next_block)
                .await?;
        }

        let monitored_utxos = get_monitored_utxos(&wallet_state_premine_recipient).await;
        assert_eq!(
            1,
            monitored_utxos.len(),
            "monitored UTXOs must be 1 after applying N blocks not mined by wallet"
        );

        let genesis_block_output_utxo = monitored_utxos[0].utxo.clone();
        let ms_membership_proof = monitored_utxos[0]
            .get_membership_proof_for_block(next_block.hash())
            .unwrap();
        assert!(
            next_block
                .kernel
                .body
                .mutator_set_accumulator
                .verify(Hash::hash(&genesis_block_output_utxo), &ms_membership_proof)
                .await,
            "Membership proof must be valid after updating wallet state with generated blocks"
        );

        Ok(())
    }

    #[tokio::test]
    async fn wallet_state_registration_of_monitored_utxos_test() -> Result<()> {
        let mut rng = thread_rng();
        let network = Network::Testnet;
        let own_wallet_secret = WalletSecret::new_random();
        let mut own_wallet_state = get_mock_wallet_state(own_wallet_secret.clone(), network).await;
        let other_wallet_secret = WalletSecret::new_random();
        let other_recipient_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();

        let mut monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        assert!(
            monitored_utxos.is_empty(),
            "Monitored UTXO list must be empty at init"
        );

        let genesis_block = Block::genesis_block().await;
        let own_spending_key = own_wallet_secret.nth_generation_spending_key(0);
        let own_recipient_address = own_spending_key.to_address();
        let (block_1, block_1_coinbase_utxo, block_1_coinbase_sender_randomness) =
            make_mock_block(&genesis_block, None, own_recipient_address, rng.gen()).await;

        own_wallet_state
            .expected_utxos
            .add_expected_utxo(
                block_1_coinbase_utxo.clone(),
                block_1_coinbase_sender_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();
        assert_eq!(
            1,
            own_wallet_state.expected_utxos.len(),
            "Expected UTXO list must have length 1 before block registration"
        );
        own_wallet_state
            .update_wallet_state_with_new_block(
                &genesis_block.kernel.body.mutator_set_accumulator,
                &block_1,
            )
            .await?;
        assert_eq!(
            1,
            own_wallet_state.expected_utxos.len(),
            "A: Expected UTXO list must have length 1 after block registration, due to potential reorganizations");
        let expected_utxos = own_wallet_state.expected_utxos.get_all_expected_utxos();
        assert_eq!(1, expected_utxos.len(), "B: Expected UTXO list must have length 1 after block registration, due to potential reorganizations");
        assert_eq!(
            block_1.hash(),
            expected_utxos[0].mined_in_block.unwrap().0,
            "Expected UTXO must be registered as being mined"
        );
        monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        assert_eq!(
            1,
            monitored_utxos.len(),
            "Monitored UTXO list be one after we mined a block"
        );

        // Ensure that the membership proof is valid
        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(block_1.hash())
                .unwrap();
            let membership_proof_is_valid = block_1
                .kernel
                .body
                .mutator_set_accumulator
                .verify(block_1_tx_output_digest, &ms_membership_proof)
                .await;
            assert!(membership_proof_is_valid);
        }

        // Create new blocks, verify that the membership proofs are *not* valid
        // under this block as tip
        let (block_2, _, _) =
            make_mock_block(&block_1, None, other_recipient_address, rng.gen()).await;
        let (block_3, _, _) =
            make_mock_block(&block_2, None, other_recipient_address, rng.gen()).await;
        monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(block_1.hash())
                .unwrap();
            let _membership_proof_is_valid = block_3
                .kernel
                .body
                .mutator_set_accumulator
                .verify(block_1_tx_output_digest, &ms_membership_proof);

            // Actually, new blocks / transactions / UTXOs do not necessarily
            // invalidate existing mutator set membership proofs (although that is
            // what usually happens). So there is no point asserting it.
            // assert!(
            //     !membership_proof_is_valid,
            //     "membership proof must be invalid before updating wallet state"
            // );
        }
        // Verify that the membership proof is valid *after* running the updater
        own_wallet_state
            .update_wallet_state_with_new_block(
                &block_1.kernel.body.mutator_set_accumulator,
                &block_2,
            )
            .await?;
        own_wallet_state
            .update_wallet_state_with_new_block(
                &block_2.kernel.body.mutator_set_accumulator,
                &block_3,
            )
            .await?;
        monitored_utxos = get_monitored_utxos(&own_wallet_state).await;

        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(block_3.hash())
                .unwrap();
            let membership_proof_is_valid = block_3
                .kernel
                .body
                .mutator_set_accumulator
                .verify(block_1_tx_output_digest, &ms_membership_proof)
                .await;
            assert!(
                membership_proof_is_valid,
                "Membership proof must be valid after updating wallet state with generated blocks"
            );
        }

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn allocate_sufficient_input_funds_test() -> Result<()> {
        let mut rng = thread_rng();
        let own_wallet_secret = WalletSecret::new_random();
        let network = Network::Testnet;
        let mut own_wallet_state = get_mock_wallet_state(own_wallet_secret, network).await;
        let own_spending_key = own_wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let genesis_block = Block::genesis_block().await;
        let (block_1, cb_utxo, cb_output_randomness) = make_mock_block(
            &genesis_block,
            None,
            own_spending_key.to_address(),
            rng.gen(),
        )
        .await;
        let mining_reward = cb_utxo.get_native_currency_amount();

        // Add block to wallet state
        own_wallet_state
            .expected_utxos
            .add_expected_utxo(
                cb_utxo,
                cb_output_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();
        own_wallet_state
            .update_wallet_state_with_new_block(
                &genesis_block.kernel.body.mutator_set_accumulator,
                &block_1,
            )
            .await?;

        // Verify that the allocater returns a sane amount
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(NeptuneCoins::one(), block_1.hash())
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(
                    mining_reward.checked_sub(&NeptuneCoins::one()).unwrap(),
                    block_1.hash()
                )
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(mining_reward, block_1.hash())
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: `mining_reward`
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(mining_reward + NeptuneCoins::one(), block_1.hash())
            .await
            .is_err());

        // Mine 21 more blocks and verify that 22 * `mining_reward` worth of UTXOs can be allocated
        let mut next_block = block_1.clone();
        for _ in 0..21 {
            let previous_block = next_block;
            let (next_block_prime, cb_utxo_prime, cb_output_randomness_prime) = make_mock_block(
                &previous_block,
                None,
                own_spending_key.to_address(),
                rng.gen(),
            )
            .await;
            own_wallet_state
                .expected_utxos
                .add_expected_utxo(
                    cb_utxo_prime,
                    cb_output_randomness_prime,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            own_wallet_state
                .update_wallet_state_with_new_block(
                    &previous_block.kernel.body.mutator_set_accumulator,
                    &next_block_prime,
                )
                .await?;
            next_block = next_block_prime;
        }

        assert_eq!(
            5,
            own_wallet_state
                .allocate_sufficient_input_funds(mining_reward.scalar_mul(5), next_block.hash())
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            6,
            own_wallet_state
                .allocate_sufficient_input_funds(
                    mining_reward.scalar_mul(5) + NeptuneCoins::one(),
                    next_block.hash()
                )
                .await
                .unwrap()
                .len()
        );

        let expected_balance = mining_reward.scalar_mul(22);
        assert_eq!(
            22,
            own_wallet_state
                .allocate_sufficient_input_funds(expected_balance, next_block.hash())
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 22 * mining reward
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(
                expected_balance + NeptuneCoins::one(),
                next_block.hash()
            )
            .await
            .is_err());

        // Make a block that spends an input, then verify that this is reflected by
        // the allocator.
        let two_utxos = own_wallet_state
            .allocate_sufficient_input_funds(mining_reward.scalar_mul(2), next_block.hash())
            .await
            .unwrap();
        assert_eq!(
            2,
            two_utxos.len(),
            "Must use two UTXOs when sending 2 x mining reward"
        );

        // This block spends two UTXOs and gives us none, so the new balance
        // becomes 2000
        let other_wallet = WalletSecret::new_random();
        let other_wallet_recipient_address =
            other_wallet.nth_generation_spending_key(0).to_address();
        assert_eq!(
            Into::<BlockHeight>::into(22u64),
            next_block.kernel.header.height
        );
        let msa_tip_previous = next_block.kernel.body.mutator_set_accumulator.clone();
        (next_block, _, _) = make_mock_block(
            &next_block.clone(),
            None,
            own_spending_key.to_address(),
            rng.gen(),
        )
        .await;
        assert_eq!(
            Into::<BlockHeight>::into(23u64),
            next_block.kernel.header.height
        );

        let receiver_data = vec![UtxoReceiverData {
            utxo: Utxo {
                lock_script_hash: LockScript::anyone_can_spend().hash(),
                coins: NeptuneCoins::new(200).to_native_coins(),
            },
            sender_randomness: random(),
            receiver_privacy_digest: other_wallet_recipient_address.privacy_digest,
            public_announcement: PublicAnnouncement::default(),
        }];
        let input_utxos_mps_keys = two_utxos
            .into_iter()
            .map(|(utxo, _lock_script, mp)| (utxo, mp, own_spending_key))
            .collect_vec();
        let tx = make_mock_transaction_with_generation_key(
            input_utxos_mps_keys,
            receiver_data,
            NeptuneCoins::zero(),
            msa_tip_previous.clone(),
        )
        .await;
        next_block
            .accumulate_transaction(tx, &msa_tip_previous)
            .await;

        own_wallet_state
            .update_wallet_state_with_new_block(&msa_tip_previous.clone(), &next_block)
            .await?;

        assert_eq!(
            20,
            own_wallet_state
                .allocate_sufficient_input_funds(NeptuneCoins::new(2000), next_block.hash())
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 2000
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(NeptuneCoins::new(2001), next_block.hash())
            .await
            .is_err());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn wallet_state_maintanence_multiple_inputs_outputs_test() -> Result<()> {
        let mut rng = thread_rng();
        // An archival state is needed for how we currently add inputs to a transaction.
        // So it's just used to generate test data, not in any of the functions that are
        // actually tested.
        let network = Network::Alpha;
        let own_wallet_secret = WalletSecret::new_random();
        let mut own_wallet_state = get_mock_wallet_state(own_wallet_secret, network).await;
        let own_spending_key = own_wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let own_address = own_spending_key.to_address();
        let genesis_block = Block::genesis_block().await;
        let premine_wallet = get_mock_wallet_state(WalletSecret::devnet_wallet(), network)
            .await
            .wallet_secret;
        let premine_receiver_global_state_lock =
            get_mock_global_state(Network::Alpha, 2, premine_wallet).await;
        let mut premine_receiver_global_state =
            premine_receiver_global_state_lock.lock_guard_mut().await;
        let launch = genesis_block.kernel.header.timestamp.value();
        let seven_months = Duration::from_millis(7 * 30 * 24 * 60 * 60 * 1000);
        let preminers_original_balance = premine_receiver_global_state
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_available_amount(launch + seven_months.as_millis() as u64);
        assert!(
            !preminers_original_balance.is_zero(),
            "Premine must have non-zero synced balance"
        );

        let previous_msa = genesis_block.kernel.body.mutator_set_accumulator.clone();
        let (mut block_1, _, _) =
            make_mock_block(&genesis_block, None, own_address, rng.gen()).await;

        let receiver_data_12_to_other = UtxoReceiverData {
            public_announcement: PublicAnnouncement::default(),
            receiver_privacy_digest: own_address.privacy_digest,
            sender_randomness: premine_receiver_global_state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(
                    genesis_block.kernel.header.height,
                    own_address.privacy_digest,
                ),
            utxo: Utxo {
                coins: NeptuneCoins::new(12).to_native_coins(),
                lock_script_hash: own_address.lock_script().hash(),
            },
        };
        let receiver_data_one_to_other = UtxoReceiverData {
            public_announcement: PublicAnnouncement::default(),
            receiver_privacy_digest: own_address.privacy_digest,
            sender_randomness: premine_receiver_global_state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(
                    genesis_block.kernel.header.height,
                    own_address.privacy_digest,
                ),
            utxo: Utxo {
                coins: NeptuneCoins::new(1).to_native_coins(),
                lock_script_hash: own_address.lock_script().hash(),
            },
        };
        let receiver_data_to_other = vec![receiver_data_12_to_other, receiver_data_one_to_other];
        let mut now = Duration::from_millis(genesis_block.kernel.header.timestamp.value());
        let valid_tx = premine_receiver_global_state
            .create_transaction(
                receiver_data_to_other.clone(),
                NeptuneCoins::new(2),
                now + seven_months,
            )
            .await
            .unwrap();

        block_1
            .accumulate_transaction(valid_tx, &previous_msa)
            .await;

        // Verify the validity of the merged transaction and block
        assert!(block_1.is_valid(&genesis_block, now + seven_months).await);

        // Update wallet state with block_1
        let mut monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        assert!(
            monitored_utxos.is_empty(),
            "List of monitored UTXOs must be empty prior to updating wallet state"
        );

        // Expect the UTXO outputs
        for receive_data in receiver_data_to_other {
            own_wallet_state
                .expected_utxos
                .add_expected_utxo(
                    receive_data.utxo,
                    receive_data.sender_randomness,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::Cli,
                )
                .unwrap();
        }
        own_wallet_state
            .update_wallet_state_with_new_block(&previous_msa, &block_1)
            .await?;
        add_block(&mut premine_receiver_global_state, block_1.clone())
            .await
            .unwrap();
        premine_receiver_global_state
            .wallet_state
            .update_wallet_state_with_new_block(&previous_msa, &block_1)
            .await?;

        assert_eq!(
            preminers_original_balance
                .checked_sub(&NeptuneCoins::new(15))
                .unwrap(),
            premine_receiver_global_state
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(launch + seven_months.as_millis() as u64),
            "Preminer must have spent 15: 12 + 1 for sent, 2 for fees"
        );

        // Verify that update added 4 UTXOs to list of monitored transactions:
        // three as regular outputs, and one as coinbase UTXO
        monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        assert_eq!(
            2,
            monitored_utxos.len(),
            "List of monitored UTXOs have length 4 after updating wallet state"
        );

        // Verify that all monitored UTXOs have valid membership proofs
        for monitored_utxo in monitored_utxos {
            assert!(
                block_1
                    .kernel
                    .body
                    .mutator_set_accumulator
                    .verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_1.hash())
                            .unwrap()
                    )
                    .await,
                "All membership proofs must be valid after block 1"
            )
        }

        // Add 17 blocks (mined by us)
        // and verify that all membership proofs are still valid
        let mut next_block = block_1.clone();
        for _ in 0..17 {
            let previous_block = next_block;
            let ret = make_mock_block(&previous_block, None, own_address, rng.gen()).await;
            next_block = ret.0;
            own_wallet_state
                .expected_utxos
                .add_expected_utxo(
                    ret.1,
                    ret.2,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            own_wallet_state
                .update_wallet_state_with_new_block(
                    &previous_block.kernel.body.mutator_set_accumulator,
                    &next_block,
                )
                .await?;
            add_block(&mut premine_receiver_global_state, block_1.clone())
                .await
                .unwrap();
            premine_receiver_global_state
                .wallet_state
                .update_wallet_state_with_new_block(
                    &previous_block.kernel.body.mutator_set_accumulator,
                    &next_block,
                )
                .await?;
        }

        let block_18 = next_block;
        monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        assert_eq!(
                2 + 17,
                monitored_utxos.len(),
                "List of monitored UTXOs have length 19 after updating wallet state and mining 17 blocks"
            );
        for monitored_utxo in monitored_utxos {
            assert!(
                block_18
                    .kernel
                    .body
                    .mutator_set_accumulator
                    .verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_18.hash())
                            .unwrap()
                    )
                    .await,
                "All membership proofs must be valid after block 18"
            )
        }

        // Sanity check
        assert_eq!(
            Into::<BlockHeight>::into(18u64),
            block_18.kernel.header.height,
            "Block height must be 18 after genesis and 18 blocks being mined"
        );

        // Check that `WalletStatus` is returned correctly
        let wallet_status = own_wallet_state
            .get_wallet_status_from_lock(block_18.hash())
            .await;
        assert_eq!(
            19,
            wallet_status.synced_unspent.len(),
            "Wallet must have 19 synced, unspent UTXOs"
        );
        assert!(
            wallet_status.synced_spent.is_empty(),
            "Wallet must have 0 synced, spent UTXOs"
        );
        assert!(
            wallet_status.unsynced_spent.is_empty(),
            "Wallet must have 0 unsynced spent UTXOs"
        );
        assert!(
            wallet_status.unsynced_unspent.is_empty(),
            "Wallet must have 0 unsynced unspent UTXOs"
        );

        // verify that membership proofs are valid after forks
        let premine_wallet_spending_key = premine_receiver_global_state
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let (block_2_b, _, _) = make_mock_block(
            &block_1,
            None,
            premine_wallet_spending_key.to_address(),
            rng.gen(),
        )
        .await;
        own_wallet_state
            .update_wallet_state_with_new_block(
                &block_1.kernel.body.mutator_set_accumulator,
                &block_2_b,
            )
            .await?;
        add_block(&mut premine_receiver_global_state, block_2_b.clone())
            .await
            .unwrap();
        premine_receiver_global_state
            .wallet_state
            .update_wallet_state_with_new_block(
                &block_1.kernel.body.mutator_set_accumulator,
                &block_2_b,
            )
            .await
            .unwrap();
        let monitored_utxos_at_2b: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|x| x.is_synced_to(block_2_b.hash()))
            .collect();
        assert_eq!(
            2,
            monitored_utxos_at_2b.len(),
            "List of synced monitored UTXOs have length 2 after updating wallet state"
        );

        // Verify that all monitored UTXOs (with synced MPs) have valid membership proofs
        for monitored_utxo in monitored_utxos_at_2b.iter() {
            assert!(
                block_2_b
                    .kernel
                    .body
                    .mutator_set_accumulator
                    .verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_2_b.hash())
                            .unwrap()
                    )
                    .await,
                "All synced membership proofs must be valid after block 2b fork"
            )
        }

        // Fork back again to the long chain and verify that the membership proofs
        // all work again
        let (block_19, _, _) = make_mock_block(
            &block_18,
            None,
            premine_wallet_spending_key.to_address(),
            rng.gen(),
        )
        .await;
        own_wallet_state
            .update_wallet_state_with_new_block(
                &block_18.kernel.body.mutator_set_accumulator,
                &block_19,
            )
            .await?;
        let monitored_utxos_block_19: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|monitored_utxo| monitored_utxo.is_synced_to(block_19.hash()))
            .collect();
        assert_eq!(
            2 + 17,
            monitored_utxos_block_19.len(),
            "List of monitored UTXOs have length 19 after returning to good fork"
        );

        // Verify that all monitored UTXOs have valid membership proofs
        for monitored_utxo in monitored_utxos_block_19.iter() {
            assert!(
                block_19
                    .kernel
                    .body
                    .mutator_set_accumulator
                    .verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_19.hash())
                            .unwrap()
                    )
                    .await,
                "All membership proofs must be valid after block 19"
            )
        }

        // Fork back to the B-chain with `block_3b` which contains two outputs for `own_wallet`,
        // one coinbase UTXO and one other UTXO
        let (mut block_3_b, cb_utxo, cb_sender_randomness) =
            make_mock_block(&block_2_b, None, own_address, rng.gen()).await;
        now = Duration::from_millis(block_3_b.kernel.header.timestamp.value());
        assert!(
            block_3_b.is_valid(&block_2_b, now).await,
            "Block must be valid before merging txs"
        );

        let receiver_data_six = UtxoReceiverData {
            public_announcement: PublicAnnouncement::default(),
            receiver_privacy_digest: own_address.privacy_digest,
            utxo: Utxo {
                coins: NeptuneCoins::new(4).to_native_coins(),
                lock_script_hash: own_address.lock_script().hash(),
            },
            sender_randomness: random(),
        };
        let tx_from_preminer = premine_receiver_global_state
            .create_transaction(vec![receiver_data_six.clone()], NeptuneCoins::new(4), now)
            .await
            .unwrap();
        block_3_b
            .accumulate_transaction(
                tx_from_preminer,
                &block_2_b.kernel.body.mutator_set_accumulator,
            )
            .await;
        assert!(
            block_3_b.is_valid(&block_2_b, now).await,
            "Block must be valid after accumulating txs"
        );
        own_wallet_state
            .expected_utxos
            .add_expected_utxo(
                cb_utxo,
                cb_sender_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();
        own_wallet_state
            .expected_utxos
            .add_expected_utxo(
                receiver_data_six.utxo,
                receiver_data_six.sender_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::Cli,
            )
            .unwrap();
        own_wallet_state
            .update_wallet_state_with_new_block(
                &block_2_b.kernel.body.mutator_set_accumulator,
                &block_3_b,
            )
            .await?;

        let monitored_utxos_3b: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|x| x.is_synced_to(block_3_b.hash()))
            .collect();
        assert_eq!(
            4,
            monitored_utxos_3b.len(),
            "List of monitored and unspent UTXOs have length 4 after receiving two"
        );
        assert_eq!(
            0,
            monitored_utxos_3b
                .iter()
                .filter(|x| x.spent_in_block.is_some())
                .count(),
            "Zero monitored UTXO must be marked as spent"
        );

        // Verify that all unspent monitored UTXOs have valid membership proofs
        for monitored_utxo in monitored_utxos_3b {
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || block_3_b
                        .kernel
                        .body
                        .mutator_set_accumulator
                        .verify(
                            Hash::hash(&monitored_utxo.utxo),
                            &monitored_utxo
                                .get_membership_proof_for_block(block_3_b.hash())
                                .unwrap()
                        )
                        .await,
                "All membership proofs of unspent UTXOs must be valid after block 3b"
            )
        }

        // Then fork back to A-chain
        let (block_20, _, _) = make_mock_block(
            &block_19,
            None,
            premine_wallet_spending_key.to_address(),
            rng.gen(),
        )
        .await;
        own_wallet_state
            .update_wallet_state_with_new_block(
                &block_19.kernel.body.mutator_set_accumulator,
                &block_20,
            )
            .await?;

        // Verify that we have two membership proofs of `forked_utxo`: one matching block20 and one matching block_3b
        let monitored_utxos_20: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|x| x.is_synced_to(block_20.hash()))
            .collect();
        assert_eq!(
                19,
                monitored_utxos_20.len(),
                "List of monitored UTXOs must be two higher than after block 19 after returning to bad fork"
            );
        for monitored_utxo in monitored_utxos_20.iter() {
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || block_20
                        .kernel
                        .body
                        .mutator_set_accumulator
                        .verify(
                            Hash::hash(&monitored_utxo.utxo),
                            &monitored_utxo
                                .get_membership_proof_for_block(block_20.hash())
                                .unwrap()
                        )
                        .await,
                "All membership proofs of unspent UTXOs must be valid after block 20"
            )
        }

        Ok(())
    }

    #[tokio::test]
    async fn basic_wallet_secret_functionality_test() {
        let random_wallet_secret = WalletSecret::new_random();
        let spending_key = random_wallet_secret.nth_generation_spending_key(0);
        let _address = spending_key.to_address();
        let _sender_randomness = random_wallet_secret
            .generate_sender_randomness(BFieldElement::new(10).into(), random());
    }

    #[test]
    fn master_seed_is_not_sender_randomness() {
        let secret = thread_rng().gen::<XFieldElement>();
        let secret_as_digest = Digest::new(
            [
                secret.coefficients.to_vec(),
                vec![BFieldElement::new(0); DIGEST_LENGTH - EXTENSION_DEGREE],
            ]
            .concat()
            .try_into()
            .unwrap(),
        );
        let wallet = WalletSecret::new(SecretKeyMaterial(secret));
        assert_ne!(
            wallet.generate_sender_randomness(BlockHeight::genesis(), random()),
            secret_as_digest
        );
    }

    #[test]
    fn get_devnet_wallet_info() {
        // Helper function/test to print the public key associated with the authority signatures
        let devnet_wallet = WalletSecret::devnet_wallet();
        let spending_key = devnet_wallet.nth_generation_spending_key(0);
        let address = spending_key.to_address();
        println!(
            "_authority_wallet address: {}",
            address.to_bech32m(Network::Alpha).unwrap()
        );
        println!("_authority_wallet spending_lock: {}", address.spending_lock);
    }

    #[test]
    fn phrase_conversion_works() {
        let wallet_secret = WalletSecret::new_random();
        let phrase = wallet_secret.to_phrase();
        let wallet_again = WalletSecret::from_phrase(&phrase).unwrap();
        let phrase_again = wallet_again.to_phrase();

        assert_eq!(wallet_secret, wallet_again);
        assert_eq!(phrase, phrase_again);
    }

    #[test]
    fn bad_phrase_conversion_fails() {
        let wallet_secret = WalletSecret::new_random();
        let mut phrase = wallet_secret.to_phrase();
        phrase.push("blank".to_string());
        assert!(WalletSecret::from_phrase(&phrase).is_err());
        assert!(WalletSecret::from_phrase(&phrase[0..phrase.len() - 2]).is_err());
        phrase[0] = "bbb".to_string();
        assert!(WalletSecret::from_phrase(&phrase[0..phrase.len() - 1]).is_err());
    }
}
