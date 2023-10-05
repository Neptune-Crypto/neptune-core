pub mod address;
pub mod monitored_utxo;
pub mod rusty_wallet_database;
pub mod utxo_notification_pool;
pub mod wallet_state;
pub mod wallet_status;

use anyhow::{bail, Context, Result};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::fs::{self};
use std::path::{Path, PathBuf};
use tracing::info;
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::digest::Digest;
use twenty_first::shared_math::other::random_elements_array;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

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

/// Generate a new secret
pub fn generate_secret_key() -> Digest {
    Digest::new(random_elements_array())
}

/// Wallet contains the wallet-related data we want to store in a JSON file,
/// and that is not updated during regular program execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSecret {
    name: String,

    pub secret_seed: Digest,
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
    fn wallet_secret_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_SECRET_FILE_NAME)
    }

    fn wallet_outgoing_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_OUTGOING_SECRETS_FILE_NAME)
    }

    fn wallet_incoming_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_INCOMING_SECRETS_FILE_NAME)
    }

    /// Create new `Wallet` given a `secret` key.
    pub fn new(secret_seed: Digest) -> Self {
        Self {
            name: STANDARD_WALLET_NAME.to_string(),
            secret_seed,
            version: STANDARD_WALLET_VERSION,
        }
    }

    /// Create a `Wallet` with a fixed digest
    pub fn devnet_wallet() -> Self {
        let secret_seed = Digest::new([
            BFieldElement::new(12063201067205522823),
            BFieldElement::new(1529663126377206632),
            BFieldElement::new(2090171368883726200),
            BFieldElement::new(12975872837767296928),
            BFieldElement::new(11492877804687889759),
        ]);

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
            let new_secret: Digest = generate_secret_key();
            let new_wallet: WalletSecret = WalletSecret::new(new_secret);
            new_wallet.create_wallet_secret_file(&wallet_secret_path)?;
            new_wallet
        };

        // Generate files for outgoing and ingoing randomness if those files
        // do not already exist
        let outgoing_randomness_file = Self::wallet_outgoing_secrets_path(wallet_directory_path);
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
                self.secret_seed.encode(),
                vec![
                    generation_address::GENERATION_FLAG,
                    BFieldElement::new(counter.try_into().unwrap()),
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
                self.secret_seed.encode(),
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
    fn read_from_file(wallet_file: &Path) -> Result<Self> {
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

    /// Create wallet file with restrictive permissions and save this wallet to disk
    fn create_wallet_secret_file(&self, wallet_file: &Path) -> Result<()> {
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
}

#[cfg(test)]
mod wallet_tests {
    use std::sync::Arc;

    use itertools::Itertools;
    use num_traits::CheckedSub;
    use rand::random;
    use tokio::sync::Mutex;
    use tracing_test::traced_test;
    use twenty_first::util_types::storage_vec::StorageVec;

    use crate::config_models::network::Network;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::shared::Hash;
    use crate::models::blockchain::transaction::amount::{Amount, AmountLike};
    use crate::models::blockchain::transaction::utxo::{LockScript, Utxo};
    use crate::models::blockchain::transaction::PubScript;
    use crate::models::state::wallet::utxo_notification_pool::UtxoNotifier;
    use crate::models::state::UtxoReceiverData;
    use crate::tests::shared::{
        add_block, get_mock_global_state, get_mock_wallet_state, make_mock_block,
        make_mock_transaction_with_generation_key,
    };
    use crate::util_types::mutator_set::mutator_set_trait::MutatorSet;

    use super::monitored_utxo::MonitoredUtxo;
    use super::wallet_state::WalletState;
    use super::*;

    async fn get_monitored_utxos(wallet_state: &WalletState) -> Vec<MonitoredUtxo> {
        let lock = wallet_state.wallet_db.lock().await;
        let num_monitored_utxos = lock.monitored_utxos.len();
        let mut monitored_utxos = vec![];
        for i in 0..num_monitored_utxos {
            monitored_utxos.push(lock.monitored_utxos.get(i));
        }
        monitored_utxos
    }

    #[tokio::test]
    async fn wallet_state_constructor_with_genesis_block_test() -> Result<()> {
        // This test is designed to verify that the genesis block is applied
        // to the wallet state at initialization.
        let network = Network::Testnet;
        let wallet_state_premine_recipient = get_mock_wallet_state(None, network).await;
        let monitored_utxos_premine_wallet =
            get_monitored_utxos(&wallet_state_premine_recipient).await;
        assert_eq!(
            1,
            monitored_utxos_premine_wallet.len(),
            "Monitored UTXO list must contain premined UTXO at init, for premine-wallet"
        );

        let premine_receiver_spending_key = wallet_state_premine_recipient
            .wallet_secret
            .nth_generation_spending_key(0);
        let premine_receiver_address = premine_receiver_spending_key.to_address();
        let expected_premine_utxo = Utxo {
            coins: Block::premine_distribution()[0].1.to_native_coins(),
            lock_script_hash: premine_receiver_address.lock_script().hash(),
        };
        assert_eq!(
            expected_premine_utxo, monitored_utxos_premine_wallet[0].utxo,
            "Auth wallet's monitored UTXO must match that from genesis block at initialization"
        );

        let random_wallet = WalletSecret::new(generate_secret_key());
        let wallet_state_other = get_mock_wallet_state(Some(random_wallet), network).await;
        let monitored_utxos_other = get_monitored_utxos(&wallet_state_other).await;
        assert!(
            monitored_utxos_other.is_empty(),
            "Monitored UTXO list must be empty at init if wallet is not premine-wallet"
        );

        // Add 12 blocks and verify that membership proofs are still valid
        let genesis_block = Block::genesis_block();
        let mut next_block = genesis_block.clone();
        let other_wallet_secret = WalletSecret::new(random());
        let other_receiver_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        for _ in 0..12 {
            let previous_block = next_block;
            let (nb, _coinbase_utxo, _sender_randomness) =
                make_mock_block(&previous_block, None, other_receiver_address);
            next_block = nb;
            wallet_state_premine_recipient.update_wallet_state_with_new_block(
                &next_block,
                &mut wallet_state_premine_recipient.wallet_db.lock().await,
            )?;
        }

        let monitored_utxos = get_monitored_utxos(&wallet_state_premine_recipient).await;
        assert_eq!(
            1,
            monitored_utxos.len(),
            "monitored UTXOs must be 1 after applying N blocks not mined by wallet"
        );

        let genesis_block_output_utxo = monitored_utxos[0].utxo.clone();
        let ms_membership_proof = monitored_utxos[0]
            .get_membership_proof_for_block(next_block.hash)
            .unwrap();
        assert!(
            next_block
                .body
                .next_mutator_set_accumulator
                .verify(Hash::hash(&genesis_block_output_utxo), &ms_membership_proof),
            "Membership proof must be valid after updating wallet state with generated blocks"
        );

        Ok(())
    }

    #[tokio::test]
    async fn wallet_state_registration_of_monitored_utxos_test() -> Result<()> {
        let network = Network::Testnet;
        let own_wallet_secret = WalletSecret::new(generate_secret_key());
        let own_wallet_state =
            get_mock_wallet_state(Some(own_wallet_secret.clone()), network).await;
        let other_wallet_secret = WalletSecret::new(generate_secret_key());
        let other_recipient_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();

        let mut monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        assert!(
            monitored_utxos.is_empty(),
            "Monitored UTXO list must be empty at init"
        );

        let genesis_block = Block::genesis_block();
        let own_spending_key = own_wallet_secret.nth_generation_spending_key(0);
        let own_recipient_address = own_spending_key.to_address();
        let (block_1, block_1_coinbase_utxo, block_1_coinbase_sender_randomness) =
            make_mock_block(&genesis_block, None, own_recipient_address);

        own_wallet_state
            .expected_utxos
            .write()
            .unwrap()
            .add_expected_utxo(
                block_1_coinbase_utxo.clone(),
                block_1_coinbase_sender_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();
        assert_eq!(
            1,
            own_wallet_state.expected_utxos.read().unwrap().len(),
            "Expected UTXO list must have length 1 before block registration"
        );
        own_wallet_state.update_wallet_state_with_new_block(
            &block_1,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        assert_eq!(
            1,
            own_wallet_state.expected_utxos.read().unwrap().len(),
            "A: Expected UTXO list must have length 1 after block registration, due to potential reorganizations");
        let expected_utxos = own_wallet_state
            .expected_utxos
            .read()
            .unwrap()
            .get_all_expected_utxos();
        assert_eq!(1, expected_utxos.len(), "B: Expected UTXO list must have length 1 after block registration, due to potential reorganizations");
        assert_eq!(
            block_1.hash,
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
                .get_membership_proof_for_block(block_1.hash)
                .unwrap();
            let membership_proof_is_valid = block_1
                .body
                .next_mutator_set_accumulator
                .verify(block_1_tx_output_digest, &ms_membership_proof);
            assert!(membership_proof_is_valid);
        }

        // Create new blocks, verify that the membership proofs are *not* valid
        // under this block as tip
        let (block_2, _, _) = make_mock_block(&block_1, None, other_recipient_address);
        let (block_3, _, _) = make_mock_block(&block_2, None, other_recipient_address);
        monitored_utxos = get_monitored_utxos(&own_wallet_state).await;
        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(block_1.hash)
                .unwrap();
            let membership_proof_is_valid = block_3
                .body
                .next_mutator_set_accumulator
                .verify(block_1_tx_output_digest, &ms_membership_proof);
            assert!(
                !membership_proof_is_valid,
                "membership proof must be invalid before updating wallet state"
            );
        }
        // Verify that the membership proof is valid *after* running the updater
        own_wallet_state.update_wallet_state_with_new_block(
            &block_2,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        own_wallet_state.update_wallet_state_with_new_block(
            &block_3,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        monitored_utxos = get_monitored_utxos(&own_wallet_state).await;

        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(block_3.hash)
                .unwrap();
            let membership_proof_is_valid = block_3
                .body
                .next_mutator_set_accumulator
                .verify(block_1_tx_output_digest, &ms_membership_proof);
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
        let own_wallet_secret = WalletSecret::new(generate_secret_key());
        let network = Network::Testnet;
        let own_wallet_state = get_mock_wallet_state(Some(own_wallet_secret), network).await;
        let own_spending_key = own_wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let genesis_block = Block::genesis_block();
        let (block_1, cb_utxo, cb_output_randomness) =
            make_mock_block(&genesis_block, None, own_spending_key.to_address());
        let mining_reward = cb_utxo.get_native_coin_amount();

        // Add block to wallet state
        own_wallet_state
            .expected_utxos
            .write()
            .unwrap()
            .add_expected_utxo(
                cb_utxo,
                cb_output_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();
        own_wallet_state.update_wallet_state_with_new_block(
            &block_1,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        // wrap block
        let wrapped_block = Arc::new(Mutex::new(block_1.clone()));
        let locked_block = wrapped_block.lock().await;

        // Verify that the allocater returns a sane amount
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(Amount::one(), &locked_block)
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(
                    mining_reward.checked_sub(&Amount::one()).unwrap(),
                    &locked_block
                )
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(mining_reward, &locked_block)
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: `mining_reward`
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(mining_reward + Amount::one(), &locked_block)
            .await
            .is_err());

        // Mine 21 more blocks and verify that 22 * `mining_reward` worth of UTXOs can be allocated
        let mut next_block = block_1.clone();
        for _ in 0..21 {
            let previous_block = next_block;
            let (next_block_prime, cb_utxo_prime, cb_output_randomness_prime) =
                make_mock_block(&previous_block, None, own_spending_key.to_address());
            own_wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    cb_utxo_prime,
                    cb_output_randomness_prime,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            own_wallet_state.update_wallet_state_with_new_block(
                &next_block_prime,
                &mut own_wallet_state.wallet_db.lock().await,
            )?;
            next_block = next_block_prime;
        }

        let wrapped_block_ = Arc::new(Mutex::new(next_block.clone()));
        let block_lock = wrapped_block_.lock().await;

        assert_eq!(
            5,
            own_wallet_state
                .allocate_sufficient_input_funds(mining_reward.scalar_mul(5), &block_lock)
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            6,
            own_wallet_state
                .allocate_sufficient_input_funds(
                    mining_reward.scalar_mul(5) + Amount::one(),
                    &block_lock
                )
                .await
                .unwrap()
                .len()
        );

        let expected_balance = mining_reward.scalar_mul(22);
        assert_eq!(
            22,
            own_wallet_state
                .allocate_sufficient_input_funds(expected_balance, &block_lock)
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 22 * mining reward
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(expected_balance + Amount::one(), &block_lock)
            .await
            .is_err());

        // Make a block that spends an input, then verify that this is reflected by
        // the allocator.
        let two_utxos = own_wallet_state
            .allocate_sufficient_input_funds(mining_reward.scalar_mul(2), &block_lock)
            .await
            .unwrap();
        assert_eq!(
            2,
            two_utxos.len(),
            "Must use two UTXOs when sending 2 x mining reward"
        );

        // This block spends two UTXOs and gives us none, so the new balance
        // becomes 2000
        let other_wallet = WalletSecret::new(generate_secret_key());
        let other_wallet_recipient_address =
            other_wallet.nth_generation_spending_key(0).to_address();
        assert_eq!(Into::<BlockHeight>::into(22u64), next_block.header.height);
        (next_block, _, _) =
            make_mock_block(&next_block.clone(), None, own_spending_key.to_address());
        assert_eq!(Into::<BlockHeight>::into(23u64), next_block.header.height);
        let msa_tip_previous = next_block.body.previous_mutator_set_accumulator.clone();

        let receiver_data = vec![UtxoReceiverData {
            utxo: Utxo {
                lock_script_hash: LockScript::anyone_can_spend().hash(),
                coins: Into::<Amount>::into(200).to_native_coins(),
            },
            sender_randomness: random(),
            receiver_privacy_digest: other_wallet_recipient_address.privacy_digest,
            pubscript: PubScript::default(),
            pubscript_input: vec![],
        }];
        let input_utxos_mps_keys = two_utxos
            .into_iter()
            .map(|(utxo, _lock_script, mp)| (utxo, mp, own_spending_key))
            .collect_vec();
        let tx = make_mock_transaction_with_generation_key(
            input_utxos_mps_keys,
            receiver_data,
            Amount::zero(),
            msa_tip_previous,
        );
        next_block.accumulate_transaction(tx);

        own_wallet_state.update_wallet_state_with_new_block(
            &next_block,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        assert_eq!(
            20,
            own_wallet_state
                .allocate_sufficient_input_funds(2000.into(), &next_block)
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 2000
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(2001.into(), &block_lock)
            .await
            .is_err());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn wallet_state_maintanence_multiple_inputs_outputs_test() -> Result<()> {
        // An archival state is needed for how we currently add inputs to a transaction.
        // So it's just used to generate test data, not in any of the functions that are
        // actually tested.
        let network = Network::Alpha;
        let own_wallet_secret = WalletSecret::new(generate_secret_key());
        let own_wallet_state = get_mock_wallet_state(Some(own_wallet_secret), network).await;
        let own_spending_key = own_wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let own_address = own_spending_key.to_address();
        let genesis_block = Block::genesis_block();
        let premine_wallet = get_mock_wallet_state(None, network).await.wallet_secret;
        let premine_receiver_global_state =
            get_mock_global_state(Network::Alpha, 2, Some(premine_wallet)).await;
        let preminers_original_balance = premine_receiver_global_state
            .get_wallet_status_for_tip()
            .await
            .synced_unspent_amount;
        assert!(
            !preminers_original_balance.is_zero(),
            "Premine must have non-zero synced balance"
        );

        let (mut block_1, _, _) = make_mock_block(&genesis_block, None, own_address);

        let receiver_data_12_to_other = UtxoReceiverData {
            pubscript: PubScript::default(),
            pubscript_input: vec![],
            receiver_privacy_digest: own_address.privacy_digest,
            sender_randomness: premine_receiver_global_state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(
                    genesis_block.header.height,
                    own_address.privacy_digest,
                ),
            utxo: Utxo {
                coins: Into::<Amount>::into(12).to_native_coins(),
                lock_script_hash: own_address.lock_script().hash(),
            },
        };
        let receiver_data_one_to_other = UtxoReceiverData {
            pubscript: PubScript::default(),
            pubscript_input: vec![],
            receiver_privacy_digest: own_address.privacy_digest,
            sender_randomness: premine_receiver_global_state
                .wallet_state
                .wallet_secret
                .generate_sender_randomness(
                    genesis_block.header.height,
                    own_address.privacy_digest,
                ),
            utxo: Utxo {
                coins: Into::<Amount>::into(1).to_native_coins(),
                lock_script_hash: own_address.lock_script().hash(),
            },
        };
        let receiver_data_to_other = vec![receiver_data_12_to_other, receiver_data_one_to_other];
        let valid_tx = premine_receiver_global_state
            .create_transaction(receiver_data_to_other.clone(), Into::<Amount>::into(2))
            .await
            .unwrap();

        block_1.accumulate_transaction(valid_tx);

        // Verify the validity of the merged transaction and block
        assert!(block_1.is_valid(&genesis_block));

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
                .write()
                .unwrap()
                .add_expected_utxo(
                    receive_data.utxo,
                    receive_data.sender_randomness,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::Cli,
                )
                .unwrap();
        }
        own_wallet_state.update_wallet_state_with_new_block(
            &block_1,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        add_block(&premine_receiver_global_state, block_1.clone())
            .await
            .unwrap();
        premine_receiver_global_state
            .wallet_state
            .update_wallet_state_with_new_block(
                &block_1,
                &mut premine_receiver_global_state
                    .wallet_state
                    .wallet_db
                    .lock()
                    .await,
            )?;
        assert_eq!(
            preminers_original_balance
                .checked_sub(&Into::<Amount>::into(15))
                .unwrap(),
            premine_receiver_global_state
                .get_wallet_status_for_tip()
                .await
                .synced_unspent_amount,
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
                block_1.body.next_mutator_set_accumulator.verify(
                    Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_1.hash)
                        .unwrap()
                ),
                "All membership proofs must be valid after block 1"
            )
        }

        // Add 17 blocks (mined by us)
        // and verify that all membership proofs are still valid
        let mut next_block = block_1.clone();
        for _ in 0..17 {
            let previous_block = next_block;
            let ret = make_mock_block(&previous_block, None, own_address);
            next_block = ret.0;
            own_wallet_state
                .expected_utxos
                .write()
                .unwrap()
                .add_expected_utxo(
                    ret.1,
                    ret.2,
                    own_spending_key.privacy_preimage,
                    UtxoNotifier::OwnMiner,
                )
                .unwrap();
            own_wallet_state.update_wallet_state_with_new_block(
                &next_block,
                &mut own_wallet_state.wallet_db.lock().await,
            )?;
            add_block(&premine_receiver_global_state, block_1.clone())
                .await
                .unwrap();
            premine_receiver_global_state
                .wallet_state
                .update_wallet_state_with_new_block(
                    &next_block,
                    &mut premine_receiver_global_state
                        .wallet_state
                        .wallet_db
                        .lock()
                        .await,
                )?;
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
                block_18.body.next_mutator_set_accumulator.verify(
                    Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_18.hash)
                        .unwrap()
                ),
                "All membership proofs must be valid after block 18"
            )
        }

        // Sanity check
        assert_eq!(
            Into::<BlockHeight>::into(18u64),
            block_18.header.height,
            "Block height must be 18 after genesis and 18 blocks being mined"
        );

        // Check that `WalletStatus` is returned correctly
        let wallet_status = {
            let mut wallet_db_lock = own_wallet_state.wallet_db.lock().await;
            own_wallet_state.get_wallet_status_from_lock(&mut wallet_db_lock, &block_18)
        };
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
        let (block_2_b, _, _) =
            make_mock_block(&block_1, None, premine_wallet_spending_key.to_address());
        own_wallet_state.update_wallet_state_with_new_block(
            &block_2_b,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        add_block(&premine_receiver_global_state, block_2_b.clone())
            .await
            .unwrap();
        premine_receiver_global_state
            .wallet_state
            .update_wallet_state_with_new_block(
                &block_2_b,
                &mut premine_receiver_global_state
                    .wallet_state
                    .wallet_db
                    .lock()
                    .await,
            )
            .unwrap();
        let monitored_utxos_at_2b: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|x| x.is_synced_to(block_2_b.hash))
            .collect();
        assert_eq!(
            2,
            monitored_utxos_at_2b.len(),
            "List of synced monitored UTXOs have length 2 after updating wallet state"
        );

        // Verify that all monitored UTXOs (with synced MPs) have valid membership proofs
        for monitored_utxo in monitored_utxos_at_2b.iter() {
            assert!(
                block_2_b.body.next_mutator_set_accumulator.verify(
                    Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_2_b.hash)
                        .unwrap()
                ),
                "All synced membership proofs must be valid after block 2b fork"
            )
        }

        // Fork back again to the long chain and verify that the membership proofs
        // all work again
        let (block_19, _, _) =
            make_mock_block(&block_18, None, premine_wallet_spending_key.to_address());
        own_wallet_state.update_wallet_state_with_new_block(
            &block_19,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        let monitored_utxos_block_19: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|monitored_utxo| monitored_utxo.is_synced_to(block_19.hash))
            .collect();
        assert_eq!(
            2 + 17,
            monitored_utxos_block_19.len(),
            "List of monitored UTXOs have length 19 after returning to good fork"
        );

        // Verify that all monitored UTXOs have valid membership proofs
        for monitored_utxo in monitored_utxos_block_19.iter() {
            assert!(
                block_19.body.next_mutator_set_accumulator.verify(
                    Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(block_19.hash)
                        .unwrap()
                ),
                "All membership proofs must be valid after block 19"
            )
        }

        // Fork back to the B-chain with `block_3b` which contains two outputs for `own_wallet`,
        // one coinbase UTXO and one other UTXO
        let (mut block_3_b, cb_utxo, cb_sender_randomness) =
            make_mock_block(&block_2_b, None, own_address);
        assert!(
            block_3_b.is_valid(&block_2_b),
            "Block must be valid before merging txs"
        );

        let receiver_data_six = UtxoReceiverData {
            pubscript: PubScript::default(),
            pubscript_input: vec![],
            receiver_privacy_digest: own_address.privacy_digest,
            utxo: Utxo {
                coins: Into::<Amount>::into(6).to_native_coins(),
                lock_script_hash: own_address.lock_script().hash(),
            },
            sender_randomness: random(),
        };
        let tx_from_preminer = premine_receiver_global_state
            .create_transaction(vec![receiver_data_six.clone()], Into::<Amount>::into(4))
            .await
            .unwrap();
        block_3_b.accumulate_transaction(tx_from_preminer);
        assert!(
            block_3_b.is_valid(&block_2_b),
            "Block must be valid after accumulating txs"
        );
        own_wallet_state
            .expected_utxos
            .write()
            .unwrap()
            .add_expected_utxo(
                cb_utxo,
                cb_sender_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::OwnMiner,
            )
            .unwrap();
        own_wallet_state
            .expected_utxos
            .write()
            .unwrap()
            .add_expected_utxo(
                receiver_data_six.utxo,
                receiver_data_six.sender_randomness,
                own_spending_key.privacy_preimage,
                UtxoNotifier::Cli,
            )
            .unwrap();
        own_wallet_state.update_wallet_state_with_new_block(
            &block_3_b,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        let monitored_utxos_3b: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|x| x.is_synced_to(block_3_b.hash))
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
                    || block_3_b.body.next_mutator_set_accumulator.verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_3_b.hash)
                            .unwrap()
                    ),
                "All membership proofs of unspent UTXOs must be valid after block 3b"
            )
        }

        // Then fork back to A-chain
        let (block_20, _, _) =
            make_mock_block(&block_19, None, premine_wallet_spending_key.to_address());
        own_wallet_state.update_wallet_state_with_new_block(
            &block_20,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        // Verify that we have two membership proofs of `forked_utxo`: one matching block20 and one matching block_3b
        let monitored_utxos_20: Vec<_> = get_monitored_utxos(&own_wallet_state)
            .await
            .into_iter()
            .filter(|x| x.is_synced_to(block_20.hash))
            .collect();
        assert_eq!(
                19,
                monitored_utxos_20.len(),
                "List of monitored UTXOs must be two higher than after block 19 after returning to bad fork"
            );
        for monitored_utxo in monitored_utxos_20.iter() {
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || block_20.body.next_mutator_set_accumulator.verify(
                        Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(block_20.hash)
                            .unwrap()
                    ),
                "All membership proofs of unspent UTXOs must be valid after block 20"
            )
        }

        Ok(())
    }

    #[tokio::test]
    async fn basic_wallet_secret_functionality_test() {
        let random_wallet_secret = WalletSecret::new(generate_secret_key());
        let spending_key = random_wallet_secret.nth_generation_spending_key(0);
        let _address = spending_key.to_address();
        let _sender_randomness = random_wallet_secret
            .generate_sender_randomness(BFieldElement::new(10).into(), random());
    }

    #[test]
    fn master_seed_is_not_sender_randomness() {
        let secret = generate_secret_key();
        let wallet = WalletSecret::new(secret);
        assert_ne!(
            wallet.generate_sender_randomness(BlockHeight::genesis(), random()),
            secret
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
}
