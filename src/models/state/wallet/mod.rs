pub mod address;
pub mod coin_with_possible_timelock;
pub mod expected_utxo;
pub mod monitored_utxo;
pub mod rusty_wallet_database;
pub mod unlocked_utxo;
pub mod wallet_state;
pub mod wallet_status;

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use address::generation_address;
use address::symmetric_key;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use bip39::Mnemonic;
use itertools::Itertools;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::Rng;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;
use tracing::info;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::digest::Digest;
use twenty_first::math::x_field_element::XFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

use crate::models::blockchain::block::block_height::BlockHeight;
use crate::prelude::twenty_first;
use crate::Hash;

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

    /// derives a generation spending key at `index`
    ///
    /// note: this is a read-only method and does not modify wallet state.  When
    /// requesting a new key for purposes of a new wallet receiving address,
    /// callers should use [wallet_state::WalletState::next_unused_spending_key()]
    /// which takes &mut self.
    pub fn nth_generation_spending_key(
        &self,
        index: u16,
    ) -> generation_address::GenerationSpendingKey {
        assert!(
            index.is_zero(),
            "For now we only support one generation address per wallet"
        );

        // We keep n between 0 and 2^16 as this makes it possible to scan all possible addresses
        // in case you don't know with what counter you made the address
        let key_seed = Hash::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                vec![
                    generation_address::GENERATION_FLAG,
                    BFieldElement::new(index.into()),
                ],
            ]
            .concat(),
        );
        generation_address::GenerationSpendingKey::derive_from_seed(key_seed)
    }

    /// derives a symmetric key at `index`
    ///
    /// note: this is a read-only method and does not modify wallet state.  When
    /// requesting a new key for purposes of a new wallet receiving address,
    /// callers should use [wallet_state::WalletState::next_unused_spending_key()]
    /// which takes &mut self.
    pub fn nth_symmetric_key(&self, index: u64) -> symmetric_key::SymmetricKey {
        assert!(
            index.is_zero(),
            "For now we only support one symmetric key per wallet"
        );

        let key_seed = Hash::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                vec![symmetric_key::SYMMETRIC_KEY_FLAG, BFieldElement::new(index)],
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
        counter: u16,
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
        Hash::hash_varlen(
            &[
                self.secret_seed.0.encode(),
                vec![BFieldElement::new(SEED_FLAG), block_height.into()],
            ]
            .concat(),
        )
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
            .truncate(false)
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
            .truncate(false)
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
    use expected_utxo::ExpectedUtxo;
    use num_traits::CheckedSub;
    use rand::random;
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;
    use twenty_first::math::tip5::Digest;
    use twenty_first::math::x_field_element::EXTENSION_DEGREE;

    use super::monitored_utxo::MonitoredUtxo;
    use super::wallet_state::WalletState;
    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::database::storage::storage_vec::traits::*;
    use crate::job_queue::triton_vm::TritonVmJobPriority;
    use crate::job_queue::triton_vm::TritonVmJobQueue;
    use crate::mine_loop::make_coinbase_transaction;
    use crate::models::blockchain::block::block_header::MINIMUM_BLOCK_TIME;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::shared::Hash;
    use crate::models::blockchain::transaction::lock_script::LockScript;
    use crate::models::blockchain::transaction::transaction_output::TxOutput;
    use crate::models::blockchain::transaction::transaction_output::TxOutputList;
    use crate::models::blockchain::transaction::transaction_output::UtxoNotificationMedium;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
    use crate::models::proof_abstractions::timestamp::Timestamp;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::expected_utxo::UtxoNotifier;
    use crate::models::state::GlobalStateLock;
    use crate::tests::shared::invalid_block_with_transaction;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::make_mock_transaction_with_mutator_set_hash;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::tests::shared::mock_genesis_wallet_state;

    async fn get_monitored_utxos(wallet_state: &WalletState) -> Vec<MonitoredUtxo> {
        // note: we could just return a DbtVec here and avoid cloning...
        wallet_state.wallet_db.monitored_utxos().get_all().await
    }

    #[tokio::test]
    async fn wallet_state_constructor_with_genesis_block_test() {
        // This test is designed to verify that the genesis block is applied
        // to the wallet state at initialization. For all networks.

        let mut rng = thread_rng();
        for network in Network::iter() {
            let mut alice = mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network).await;
            let alice_wallet = get_monitored_utxos(&alice).await;
            assert_eq!(
                1,
                alice_wallet.len(),
                "Monitored UTXO list must contain premined UTXO at init, for premine-wallet"
            );

            let expected_utxo = Block::premine_utxos(network)[0].clone();
            assert_eq!(
                expected_utxo, alice_wallet[0].utxo,
                "Devnet wallet's monitored UTXO must match that from genesis block at initialization"
            );

            let bob_wallet = WalletSecret::new_pseudorandom(rng.gen());
            let bob_wallet = mock_genesis_wallet_state(bob_wallet, network).await;
            let bob_mutxos = get_monitored_utxos(&bob_wallet).await;
            assert!(
                bob_mutxos.is_empty(),
                "Monitored UTXO list must be empty at init if wallet is not premine-wallet"
            );

            // Add 12 blocks and verify that membership proofs are still valid
            let genesis_block = Block::genesis_block(network);
            let mut next_block = genesis_block.clone();
            let charlie_wallet = WalletSecret::new_pseudorandom(rng.gen());
            let charlie_address = charlie_wallet
                .nth_generation_spending_key_for_tests(0)
                .to_address();
            for _ in 0..12 {
                let previous_block = next_block;
                let (nb, _coinbase_utxo, _sender_randomness) =
                    make_mock_block(&previous_block, None, charlie_address, rng.gen());
                next_block = nb;
                alice
                    .update_wallet_state_with_new_block(
                        previous_block.mutator_set_accumulator(),
                        previous_block.guesser_fee_addition_records(),
                        &next_block,
                    )
                    .await
                    .unwrap();
            }

            let alice_mutxos = get_monitored_utxos(&alice).await;
            assert_eq!(
                1,
                alice_mutxos.len(),
                "monitored UTXOs must be 1 after applying N blocks not mined by wallet"
            );

            let genesis_block_utxo = alice_mutxos[0].utxo.clone();
            let ms_membership_proof = alice_mutxos[0]
                .get_membership_proof_for_block(next_block.hash())
                .unwrap();
            assert!(
                next_block
                    .mutator_set_accumulator()
                    .verify(Hash::hash(&genesis_block_utxo), &ms_membership_proof),
                "Membership proof must be valid after updating wallet state with generated blocks"
            );
        }
    }

    #[tokio::test]
    async fn wallet_state_correctly_updates_monitored_and_expected_utxos() {
        let mut rng = thread_rng();
        let network = Network::RegTest;
        let alice_wallet = WalletSecret::new_random();
        let mut alice_wallet = mock_genesis_wallet_state(alice_wallet.clone(), network).await;
        let bob_wallet = WalletSecret::new_random();
        let bob_address = bob_wallet
            .nth_generation_spending_key_for_tests(0)
            .to_address();

        assert!(
            get_monitored_utxos(&alice_wallet).await.is_empty(),
            "Monitored UTXO list must be empty at init"
        );

        let genesis_block = Block::genesis_block(network);
        let alice_spending_key = alice_wallet
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let alice_address = alice_spending_key.to_address();
        let (block_1, block_1_coinbase_utxo, block_1_coinbase_sender_randomness) =
            make_mock_block(&genesis_block, None, alice_address, rng.gen());

        alice_wallet
            .add_expected_utxo(ExpectedUtxo::new(
                block_1_coinbase_utxo.clone(),
                block_1_coinbase_sender_randomness,
                alice_spending_key.privacy_preimage,
                UtxoNotifier::OwnMinerComposeBlock,
            ))
            .await;
        assert_eq!(
            1,
            alice_wallet.wallet_db.expected_utxos().len().await,
            "Expected UTXO list must have length 1 before block registration"
        );
        alice_wallet
            .update_wallet_state_with_new_block(
                genesis_block.mutator_set_accumulator(),
                vec![],
                &block_1,
            )
            .await
            .unwrap();
        assert_eq!(
            1,
            alice_wallet.wallet_db.expected_utxos().len().await,
            "A: Expected UTXO list must still be 1 after receiving tx, due to potential reorganization."
        );

        let alice_expected_utxos = alice_wallet.wallet_db.expected_utxos().get_all().await;

        assert_eq!(1, alice_expected_utxos.len(), "B: Expected UTXO list must have length 1 after block registration, due to potential reorganizations");
        assert_eq!(
            block_1.hash(),
            alice_expected_utxos[0].mined_in_block.unwrap().0,
            "Expected UTXO must be registered as being mined"
        );
        let alice_mutxos_block1 = get_monitored_utxos(&alice_wallet).await;
        assert_eq!(
            1,
            alice_mutxos_block1.len(),
            "Monitored UTXO list be one after we mined a block"
        );

        // Ensure that the membership proof is valid
        let alice_block_1_cb_item = Hash::hash(&block_1_coinbase_utxo);
        let ms_membership_proof_block1 = alice_mutxos_block1[0]
            .get_membership_proof_for_block(block_1.hash())
            .unwrap();
        assert!(block_1
            .mutator_set_accumulator()
            .verify(alice_block_1_cb_item, &ms_membership_proof_block1));

        // Create new blocks, verify that the membership proofs are *not* valid
        // under this block as tip
        let (block_2, _, _) = make_mock_block(&block_1, None, bob_address, rng.gen());
        let (block_3, _, _) = make_mock_block(&block_2, None, bob_address, rng.gen());

        if ms_membership_proof_block1
            .auth_path_aocl
            .authentication_path
            .is_empty()
        {
            // We *know* that Alice's membership proof is invalid now, since
            // the extra blocks would have invalidated the AOCL-MMR proof --
            // if the inserted UTXO was a peak (indicated by its authentication
            // path having a length of zero).
            assert!(
                !block_3
                    .mutator_set_accumulator()
                    .verify(alice_block_1_cb_item, &ms_membership_proof_block1),
                "membership proof must be invalid before updating wallet state"
            );
        }

        // Verify that the membership proof is valid *after* running the updater
        alice_wallet
            .update_wallet_state_with_new_block(
                block_1.mutator_set_accumulator(),
                block_1.guesser_fee_addition_records(),
                &block_2,
            )
            .await
            .unwrap();
        alice_wallet
            .update_wallet_state_with_new_block(
                block_2.mutator_set_accumulator(),
                block_2.guesser_fee_addition_records(),
                &block_3,
            )
            .await
            .unwrap();

        let alice_mutxos_block3 = get_monitored_utxos(&alice_wallet).await;
        assert_eq!(1, alice_mutxos_block3.len(), "Still only one MUTXO");

        {
            let ms_membership_proof_block3 = alice_mutxos_block3[0]
                .get_membership_proof_for_block(block_3.hash())
                .unwrap();
            let membership_proof_is_valid = block_3
                .mutator_set_accumulator()
                .verify(alice_block_1_cb_item, &ms_membership_proof_block3);
            assert!(
                membership_proof_is_valid,
                "Membership proof must be valid after updating wallet state with generated blocks"
            );
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn allocate_sufficient_input_funds_test() {
        // Scenario:
        // Alice is not coinbase recipient. She mines many blocks. It is tested
        // that the method [WalletState::allocate_sufficient_input_funds]
        // returns consistent results.
        // Produces blocks and transactions with invalid proofs, as this is not
        // a test of block validity logic.

        let network = Network::Main;
        let alice_wallet_secret = WalletSecret::new_random();
        let mut alice =
            mock_genesis_global_state(network, 1, alice_wallet_secret, cli_args::Args::default())
                .await;
        let alice_vm_job_queue = alice.vm_job_queue().clone();
        let alice_spending_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let genesis_block = Block::genesis_block(network);

        let mut rng = thread_rng();
        let (block_1, cb_utxo, cb_output_randomness) = make_mock_block(
            &genesis_block,
            None,
            alice_spending_key.to_address(),
            rng.gen(),
        );
        let mining_reward = cb_utxo.get_native_currency_amount();
        let now = genesis_block.header().timestamp + Timestamp::months(10);

        let input_len = |alice_: GlobalStateLock, amount: NeptuneCoins| async move {
            let tip_digest = alice_.lock_guard().await.chain.light_state().hash();
            alice_
                .lock_guard()
                .await
                .wallet_state
                .allocate_sufficient_input_funds(amount, tip_digest, now)
                .await
                .map(|x| x.len())
        };

        assert!(
            input_len(alice.clone(), NeptuneCoins::new(1),)
                .await
                .is_err(),
            "Cannot allocate anything when wallet is empty"
        );

        // Add block 1 to wallet state
        {
            let mut alice_mut = alice.lock_guard_mut().await;
            alice_mut
                .wallet_state
                .add_expected_utxo(ExpectedUtxo::new(
                    cb_utxo,
                    cb_output_randomness,
                    alice_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMinerComposeBlock,
                ))
                .await;
            alice_mut
                .set_new_tip(block_1.clone(), &alice_vm_job_queue)
                .await
                .unwrap();
        }

        // Verify that the allocater returns a sane amount
        let one_coin = NeptuneCoins::new(1);
        assert_eq!(1, input_len(alice.clone(), one_coin).await.unwrap(),);
        assert_eq!(
            1,
            input_len(alice.clone(), mining_reward.checked_sub(&one_coin).unwrap(),)
                .await
                .unwrap(),
        );
        assert_eq!(1, input_len(alice.clone(), mining_reward).await.unwrap());

        // Cannot allocate more than we have: `mining_reward`
        assert!(input_len(alice.clone(), mining_reward + one_coin)
            .await
            .is_err());

        // Mine 21 more blocks and verify that 22 * `mining_reward` worth of UTXOs can be allocated
        let mut next_block = block_1.clone();
        {
            let mut alice = alice.lock_guard_mut().await;
            for _ in 0..21 {
                let previous_block = next_block;
                let (next_block_prime, cb_utxo_prime, cb_output_randomness_prime) = make_mock_block(
                    &previous_block,
                    None,
                    alice_spending_key.to_address(),
                    rng.gen(),
                );
                alice
                    .wallet_state
                    .add_expected_utxo(ExpectedUtxo::new(
                        cb_utxo_prime,
                        cb_output_randomness_prime,
                        alice_spending_key.privacy_preimage,
                        UtxoNotifier::OwnMinerComposeBlock,
                    ))
                    .await;
                alice
                    .set_new_tip(next_block_prime.clone(), &alice_vm_job_queue)
                    .await
                    .unwrap();
                next_block = next_block_prime;
            }
        }

        assert_eq!(
            5,
            input_len(alice.clone(), mining_reward.scalar_mul(5))
                .await
                .unwrap()
        );
        assert_eq!(
            6,
            input_len(alice.clone(), mining_reward.scalar_mul(5) + one_coin)
                .await
                .unwrap()
        );

        let expected_balance = mining_reward.scalar_mul(22);
        assert_eq!(
            22,
            input_len(alice.clone(), expected_balance).await.unwrap()
        );

        // Cannot allocate more than we have: 22 * mining reward
        assert!(input_len(alice.clone(), expected_balance + one_coin)
            .await
            .is_err());

        // Make a block that spends an input, then verify that this is reflected by
        // the allocator.
        let tx_inputs_two_utxos = alice
            .lock_guard()
            .await
            .wallet_state
            .allocate_sufficient_input_funds(mining_reward.scalar_mul(2), next_block.hash(), now)
            .await
            .unwrap();
        assert_eq!(
            2,
            tx_inputs_two_utxos.len(),
            "Must use two UTXOs when sending 2 x mining reward"
        );

        // This block throws away two UTXOs. So the new balance becomes 2000.
        let msa_tip_previous = next_block.mutator_set_accumulator().clone();
        let output_utxo =
            Utxo::new_native_currency(LockScript::anyone_can_spend(), NeptuneCoins::new(200));
        let tx_outputs: TxOutputList =
            vec![TxOutput::no_notification(output_utxo, random(), random())].into();

        let removal_records = tx_inputs_two_utxos
            .iter()
            .map(|txi| txi.removal_record(&msa_tip_previous))
            .collect_vec();
        let addition_records = tx_outputs.addition_records();
        let tx = make_mock_transaction_with_mutator_set_hash(
            removal_records,
            addition_records,
            next_block.mutator_set_accumulator().hash(),
        );

        let next_block = Block::block_template_invalid_proof(
            &next_block.clone(),
            tx,
            now,
            Digest::default(),
            None,
        );
        assert_eq!(
            Into::<BlockHeight>::into(23u64),
            next_block.kernel.header.height
        );

        alice.set_new_tip(next_block.clone()).await.unwrap();

        assert_eq!(
            20,
            input_len(alice.clone(), NeptuneCoins::new(2000))
                .await
                .unwrap()
        );

        // Cannot allocate more than we have: 2000
        assert!(input_len(alice.clone(), NeptuneCoins::new(2001))
            .await
            .is_err());
    }

    #[traced_test]
    #[tokio::test]
    async fn wallet_state_maintenence_multiple_inputs_outputs_test() {
        // Bob is premine receiver, Alice is not. They send coins back and forth
        // and the blockchain forks.

        let network = Network::Main;
        let mut rng: StdRng = StdRng::seed_from_u64(456416);
        let alice_wallet_secret = WalletSecret::new_pseudorandom(rng.gen());
        let mut alice =
            mock_genesis_global_state(network, 2, alice_wallet_secret, cli_args::Args::default())
                .await;
        let alice_spending_key = alice
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let alice_address = alice_spending_key.to_address();
        let genesis_block = Block::genesis_block(network);
        let bob_wallet = mock_genesis_wallet_state(WalletSecret::devnet_wallet(), network)
            .await
            .wallet_secret;
        let mut bob_global_lock =
            mock_genesis_global_state(network, 2, bob_wallet.clone(), cli_args::Args::default())
                .await;
        let bob_vm_job_queue = bob_global_lock.vm_job_queue().clone();
        let mut bob = bob_global_lock.lock_guard_mut().await;
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);

        let bobs_original_balance = bob
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_available_amount(in_seven_months);
        assert!(
            !bobs_original_balance.is_zero(),
            "Premine must have non-zero synced balance"
        );

        let bob_sender_randomness = bob.wallet_state.wallet_secret.generate_sender_randomness(
            genesis_block.kernel.header.height,
            alice_address.privacy_digest,
        );
        let receiver_data_12_to_alice = TxOutput::offchain_native_currency(
            NeptuneCoins::new(12),
            bob_sender_randomness,
            alice_address.into(),
        );
        let receiver_data_1_to_alice = TxOutput::offchain_native_currency(
            NeptuneCoins::new(1),
            bob_sender_randomness,
            alice_address.into(),
        );

        let receiver_data_to_alice: TxOutputList =
            vec![receiver_data_12_to_alice, receiver_data_1_to_alice].into();
        let (tx, _change_output) = bob
            .create_transaction_with_prover_capability(
                receiver_data_to_alice.clone(),
                bob_wallet.nth_generation_spending_key_for_tests(0).into(),
                UtxoNotificationMedium::OnChain,
                NeptuneCoins::new(2),
                in_seven_months,
                TxProvingCapability::SingleProof,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        let block_1 = invalid_block_with_transaction(&genesis_block, tx);

        // Update wallet state with block_1
        assert!(
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .is_empty(),
            "List of monitored UTXOs must be empty prior to updating wallet state"
        );

        // Notification for Bob's change happens on-chain. No need to ask
        // wallet to expect change UTXO.
        bob.set_new_tip(block_1.clone(), &bob_vm_job_queue)
            .await
            .unwrap();

        assert_eq!(
            bobs_original_balance
                .checked_sub(&NeptuneCoins::new(15))
                .unwrap(),
            bob.get_wallet_status_for_tip()
                .await
                .synced_unspent_available_amount(in_seven_months),
            "Preminer must have spent 15: 12 + 1 for sent, 2 for fees"
        );

        let expected_utxos_alice = alice
            .lock_guard()
            .await
            .wallet_state
            .extract_expected_utxos(receiver_data_to_alice, UtxoNotifier::Cli);
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos_alice)
            .await;
        alice.set_new_tip(block_1.clone()).await.unwrap();

        // Verify that update added 2 UTXOs to list of monitored transactions,
        // from Bob's tx.
        let mut alice_monitored_utxos =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state).await;
        assert_eq!(
            2,
            alice_monitored_utxos.len(),
            "List of monitored UTXOs have length 2 after updating wallet state"
        );

        // Verify that all monitored UTXOs have valid membership proofs
        for monitored_utxo in alice_monitored_utxos {
            assert!(
                block_1.mutator_set_accumulator().verify(
                    Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_1.hash())
                        .unwrap()
                ),
                "All membership proofs must be valid after block 1"
            )
        }

        // Alice mines
        let num_blocks_mined_by_alice = 4;
        // verify that all membership proofs are still valid
        let mut next_block = block_1.clone();
        for i in 0..num_blocks_mined_by_alice {
            let previous_block = next_block;
            let (block, cb_utxo, cb_sender_randomness) = make_mock_block(
                &previous_block,
                Some(in_seven_months + MINIMUM_BLOCK_TIME * i),
                alice_address,
                rng.gen(),
            );
            next_block = block;
            let expected_utxo = ExpectedUtxo::new(
                cb_utxo,
                cb_sender_randomness,
                alice_spending_key.privacy_preimage,
                UtxoNotifier::OwnMinerComposeBlock,
            );
            alice
                .lock_guard_mut()
                .await
                .wallet_state
                .add_expected_utxo(expected_utxo)
                .await;
            alice.set_new_tip(next_block.clone()).await.unwrap();
            bob.set_new_tip(next_block.clone(), &bob_vm_job_queue)
                .await
                .unwrap();
        }

        let first_block_after_spree = next_block;
        alice_monitored_utxos = get_monitored_utxos(&alice.lock_guard().await.wallet_state).await;
        assert_eq!(
            2 + num_blocks_mined_by_alice,
            alice_monitored_utxos.len(),
            "List of monitored UTXOs must match blocks mined plus two"
        );
        for monitored_utxo in alice_monitored_utxos {
            assert!(
                first_block_after_spree.mutator_set_accumulator().verify(
                    Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(first_block_after_spree.hash())
                        .unwrap()
                ),
                "All membership proofs must be valid after this block"
            )
        }

        // Sanity check
        assert_eq!(
            Into::<BlockHeight>::into(1u64 + u64::try_from(num_blocks_mined_by_alice).unwrap()),
            first_block_after_spree.kernel.header.height,
            "Block height must be {} after genesis and {} blocks being mined in Alice's spree",
            num_blocks_mined_by_alice + 1,
            num_blocks_mined_by_alice
        );

        // Check that `WalletStatus` is returned correctly
        let alice_wallet_status = alice
            .lock_guard()
            .await
            .wallet_state
            .get_wallet_status_from_lock(first_block_after_spree.hash())
            .await;
        assert_eq!(
            num_blocks_mined_by_alice + 2,
            alice_wallet_status.synced_unspent.len(),
            "Wallet must have {} synced, unspent UTXOs",
            num_blocks_mined_by_alice + 2
        );
        assert!(
            alice_wallet_status.synced_spent.is_empty(),
            "Wallet must have 0 synced, spent UTXOs"
        );
        assert!(
            alice_wallet_status.unsynced_spent.is_empty(),
            "Wallet must have 0 unsynced spent UTXOs"
        );
        assert!(
            alice_wallet_status.unsynced_unspent.is_empty(),
            "Wallet must have 0 unsynced unspent UTXOs"
        );

        // Bob mines a block, ignoring Alice's spree and forking instead
        let bob_wallet_spending_key = bob
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key_for_tests(0);
        let (block_2_b, _, _) = make_mock_block(
            &block_1,
            None,
            bob_wallet_spending_key.to_address(),
            rng.gen(),
        );
        alice.set_new_tip(block_2_b.clone()).await.unwrap();
        bob.set_new_tip(block_2_b.clone(), &bob_vm_job_queue)
            .await
            .unwrap();
        let alice_monitored_utxos_at_2b: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|x| x.is_synced_to(block_2_b.hash()))
                .collect();
        assert_eq!(
            2,
            alice_monitored_utxos_at_2b.len(),
            "List of synced monitored UTXOs have length 2 after updating wallet state"
        );

        // Verify that all monitored UTXOs (with synced MPs) have valid membership proofs
        for monitored_utxo in alice_monitored_utxos_at_2b.iter() {
            assert!(
                block_2_b.mutator_set_accumulator().verify(
                    Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_2_b.hash())
                        .unwrap()
                ),
                "All synced membership proofs must be valid after block 2b fork"
            )
        }

        // Fork back again to the long chain and verify that the membership proofs
        // all work again
        let (first_block_continuing_spree, _, _) = make_mock_block(
            &first_block_after_spree,
            None,
            bob_wallet_spending_key.to_address(),
            rng.gen(),
        );
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                first_block_after_spree.mutator_set_accumulator(),
                first_block_after_spree.guesser_fee_addition_records(),
                &first_block_continuing_spree,
            )
            .await
            .unwrap();
        let alice_monitored_utxos_after_continued_spree: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|monitored_utxo| {
                    monitored_utxo.is_synced_to(first_block_continuing_spree.hash())
                })
                .collect();
        assert_eq!(
            2 + num_blocks_mined_by_alice,
            alice_monitored_utxos_after_continued_spree.len(),
            "List of monitored UTXOs have length {} after returning to good fork",
            2 + num_blocks_mined_by_alice
        );

        // Verify that all monitored UTXOs have valid membership proofs
        for monitored_utxo in alice_monitored_utxos_after_continued_spree.iter() {
            assert!(
                first_block_continuing_spree
                    .mutator_set_accumulator()
                    .verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(first_block_continuing_spree.hash())
                            .unwrap()
                    ),
                "All membership proofs must be valid after first block  of continued"
            )
        }

        // Fork back to the B-chain with `block_3b` which contains two outputs
        // for Alice, one coinbase UTXO and one other UTXO.
        let receiver_data_1_to_alice_new = TxOutput::offchain_native_currency(
            NeptuneCoins::new(1),
            rng.gen(),
            alice_address.into(),
        );

        let (tx_from_bob, _maybe_change_output) = bob
            .create_transaction_with_prover_capability(
                vec![receiver_data_1_to_alice_new.clone()].into(),
                bob_wallet.nth_generation_spending_key_for_tests(0).into(),
                UtxoNotificationMedium::OffChain,
                NeptuneCoins::new(4),
                block_2_b.header().timestamp + MINIMUM_BLOCK_TIME,
                TxProvingCapability::SingleProof,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();

        let guesser_fraction = 0f64;
        let (coinbase_tx, expected_composer_utxos) = make_coinbase_transaction(
            &alice,
            guesser_fraction,
            block_2_b.header().timestamp + MINIMUM_BLOCK_TIME,
        )
        .await
        .unwrap();
        let merged_tx = coinbase_tx
            .merge_with(
                tx_from_bob,
                Default::default(),
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
        let timestamp = merged_tx.kernel.timestamp;
        let block_3_b = Block::compose(
            &block_2_b,
            merged_tx,
            timestamp,
            Digest::default(),
            None,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();
        assert!(
            block_3_b.is_valid(&block_2_b, in_seven_months),
            "Block must be valid after accumulating txs"
        );
        let expected_utxos_for_alice_cb = expected_composer_utxos
            .into_iter()
            .map(|expected_utxo| {
                ExpectedUtxo::new(
                    expected_utxo.utxo,
                    expected_utxo.sender_randomness,
                    alice_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMinerComposeBlock,
                )
            })
            .collect_vec();

        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxos(expected_utxos_for_alice_cb)
            .await;
        let expected_utxo_for_alice = ExpectedUtxo::new(
            receiver_data_1_to_alice_new.utxo(),
            receiver_data_1_to_alice_new.sender_randomness(),
            alice_spending_key.privacy_preimage,
            UtxoNotifier::Cli,
        );
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .add_expected_utxo(expected_utxo_for_alice)
            .await;
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                block_2_b.mutator_set_accumulator(),
                block_2_b.guesser_fee_addition_records(),
                &block_3_b,
            )
            .await
            .unwrap();

        let alice_monitored_utxos_3b: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|x| x.is_synced_to(block_3_b.hash()))
                .collect();
        assert_eq!(
            4,
            alice_monitored_utxos_3b.len(),
            "List of monitored and unspent UTXOs have length 4 after receiving two"
        );
        assert_eq!(
            0,
            alice_monitored_utxos_3b
                .iter()
                .filter(|x| x.spent_in_block.is_some())
                .count(),
            "Zero monitored UTXO must be marked as spent"
        );

        // Verify that all unspent monitored UTXOs have valid membership proofs
        for monitored_utxo in alice_monitored_utxos_3b {
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || block_3_b.mutator_set_accumulator().verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_3_b.hash())
                            .unwrap()
                    ),
                "All membership proofs of unspent UTXOs must be valid after block 3b"
            )
        }

        // Then fork back to A-chain
        let (second_block_continuing_spree, _, _) = make_mock_block(
            &first_block_continuing_spree,
            None,
            bob_wallet_spending_key.to_address(),
            rng.gen(),
        );
        alice
            .lock_guard_mut()
            .await
            .wallet_state
            .update_wallet_state_with_new_block(
                first_block_continuing_spree.mutator_set_accumulator(),
                first_block_continuing_spree.guesser_fee_addition_records(),
                &second_block_continuing_spree,
            )
            .await
            .unwrap();

        // Verify that we have two membership proofs of `forked_utxo`: one
        // matching abandoned block and one matching block_3b.
        let alice_monitored_utxos_after_second_block_after_spree: Vec<_> =
            get_monitored_utxos(&alice.lock_guard().await.wallet_state)
                .await
                .into_iter()
                .filter(|x| x.is_synced_to(second_block_continuing_spree.hash()))
                .collect();
        assert_eq!(
            2 + num_blocks_mined_by_alice,
            alice_monitored_utxos_after_second_block_after_spree.len(),
            "List of monitored UTXOs must be two higher after returning to bad fork"
        );
        for monitored_utxo in alice_monitored_utxos_after_second_block_after_spree.iter() {
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || second_block_continuing_spree
                        .mutator_set_accumulator()
                        .verify(
                            Hash::hash(&monitored_utxo.utxo),
                            &monitored_utxo
                                .get_membership_proof_for_block(
                                    second_block_continuing_spree.hash()
                                )
                                .unwrap()
                        ),
                "All membership proofs of unspent UTXOs must be valid after block on longest chain"
            )
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn allow_consumption_of_genesis_output_test() {
        let network = Network::Main;
        let genesis_block = Block::genesis_block(network);
        let in_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
        let bob = mock_genesis_global_state(
            network,
            42,
            WalletSecret::devnet_wallet(),
            cli_args::Args::default(),
        )
        .await;

        let mut rng = StdRng::seed_from_u64(87255549301u64);

        let guesser_fraction = 0f64;
        let (cbtx, _cb_expected) =
            make_coinbase_transaction(&bob, guesser_fraction, in_seven_months)
                .await
                .unwrap();
        let one_money: NeptuneCoins = NeptuneCoins::new(1);
        let anyone_can_spend_utxo =
            Utxo::new_native_currency(LockScript::anyone_can_spend(), one_money);
        let tx_output = TxOutput::no_notification(anyone_can_spend_utxo, rng.gen(), rng.gen());
        let change_key = WalletSecret::devnet_wallet().nth_symmetric_key_for_tests(0);
        let (sender_tx, _change_output) = bob
            .lock_guard()
            .await
            .create_transaction_with_prover_capability(
                vec![tx_output].into(),
                change_key.into(),
                UtxoNotificationMedium::OffChain,
                one_money,
                in_seven_months,
                TxProvingCapability::SingleProof,
                &TritonVmJobQueue::dummy(),
            )
            .await
            .unwrap();
        let tx_for_block = sender_tx
            .merge_with(
                cbtx,
                Default::default(),
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();
        let block_1 = Block::compose(
            &genesis_block,
            tx_for_block,
            in_seven_months,
            Digest::default(),
            None,
            &TritonVmJobQueue::dummy(),
            TritonVmJobPriority::default().into(),
        )
        .await
        .unwrap();

        // The entire block must be valid, i.e., have a valid block proof, and
        // be valid in other respects. We don't care about PoW, though.
        assert!(block_1.is_valid(&genesis_block, in_seven_months));

        // 3 outputs: 1 coinbase, 1 for recipient of tx, 1 for change.
        assert_eq!(3, block_1.body().transaction_kernel.outputs.len());
    }

    #[tokio::test]
    async fn basic_wallet_secret_functionality_test() {
        let random_wallet_secret = WalletSecret::new_random();
        let spending_key = random_wallet_secret.nth_generation_spending_key_for_tests(0);
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
                vec![BFieldElement::new(0); Digest::LEN - EXTENSION_DEGREE],
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
        let spending_key = devnet_wallet.nth_generation_spending_key_for_tests(0);
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
