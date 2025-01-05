pub mod address;
pub mod monitored_utxo;
pub mod rusty_wallet_database;
pub mod utxo_notification_pool;
pub mod wallet_state;
pub mod wallet_status;

use anyhow::{bail, Context, Result};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::fs;
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
pub const WALLET_DB_NAME: &str = "wallet_block_db";
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

    fn wallet_secret_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_SECRET_FILE_NAME)
    }

    fn wallet_outgoing_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_OUTGOING_SECRETS_FILE_NAME)
    }

    fn wallet_incoming_secrets_path(wallet_directory_path: &Path) -> PathBuf {
        wallet_directory_path.join(WALLET_INCOMING_SECRETS_FILE_NAME)
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
        self.nth_generation_spending_key_worker(counter)
    }

    fn nth_generation_spending_key_worker(&self, counter: u16) -> generation_address::SpendingKey {
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

        if cfg!(not(unix)) {
            Self::create_wallet_file_windows(&file_path.to_path_buf(), init_value)
        } else {
            Self::create_wallet_file_unix(&file_path.to_path_buf(), init_value)
        }
    }

    /// Create wallet file with restrictive permissions and save this wallet to disk
    fn create_wallet_secret_file(&self, wallet_file: &Path) -> Result<()> {
        let wallet_secret_as_json: String = serde_json::to_string(self).unwrap();

        if cfg!(windows) {
            Self::create_wallet_file_windows(&wallet_file.to_path_buf(), wallet_secret_as_json)
        } else {
            Self::create_wallet_file_unix(&wallet_file.to_path_buf(), wallet_secret_as_json)
        }
    }

    #[cfg(target_family = "unix")]
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
        let wallet_state_premine_recipient = get_mock_wallet_state(None).await;
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
        let wallet_state_other = get_mock_wallet_state(Some(random_wallet)).await;
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
            .get_membership_proof_for_block(&next_block.hash)
            .unwrap();
        assert!(
            next_block.body.next_mutator_set_accumulator.verify(
                &Hash::hash(&genesis_block_output_utxo),
                &ms_membership_proof
            ),
            "Membership proof must be valid after updating wallet state with generated blocks"
        );

        Ok(())
    }

    #[tokio::test]
    async fn wallet_state_registration_of_monitored_utxos_test() -> Result<()> {
        let own_wallet_secret = WalletSecret::new(generate_secret_key());
        let wallet_state = get_mock_wallet_state(Some(own_wallet_secret.clone())).await;
        let other_wallet_secret = WalletSecret::new(generate_secret_key());
        let other_recipient_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();

        let mut monitored_utxos = get_monitored_utxos(&wallet_state).await;
        assert!(
            monitored_utxos.is_empty(),
            "Monitored UTXO list must be empty at init"
        );

        let genesis_block = Block::genesis_block();
        let own_spending_key = own_wallet_secret.nth_generation_spending_key(0);
        let own_recipient_address = own_spending_key.to_address();
        let (block_1, block_1_coinbase_utxo, block_1_coinbase_sender_randomness) =
            make_mock_block(&genesis_block, None, own_recipient_address);

        wallet_state
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
            wallet_state.expected_utxos.read().unwrap().len(),
            "Expected UTXO list must have length 1 before block registration"
        );
        wallet_state.update_wallet_state_with_new_block(
            &block_1,
            &mut wallet_state.wallet_db.lock().await,
        )?;
        assert_eq!(
            1,
            wallet_state.expected_utxos.read().unwrap().len(),
            "A: Expected UTXO list must have length 1 after block registration, due to potential reorganizations");
        let expected_utxos = wallet_state
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
        monitored_utxos = get_monitored_utxos(&wallet_state).await;
        assert_eq!(
            1,
            monitored_utxos.len(),
            "Monitored UTXO list be one after we mined a block"
        );

        // Ensure that the membership proof is valid
        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(&block_1.hash)
                .unwrap();
            let membership_proof_is_valid = block_1
                .body
                .next_mutator_set_accumulator
                .verify(&block_1_tx_output_digest, &ms_membership_proof);
            assert!(membership_proof_is_valid);
        }

        // Create new blocks, verify that the membership proofs are *not* valid
        // under this block as tip
        let (block_2, _, _) = make_mock_block(&block_1, None, other_recipient_address);
        let (block_3, _, _) = make_mock_block(&block_2, None, other_recipient_address);
        monitored_utxos = get_monitored_utxos(&wallet_state).await;
        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(&block_1.hash)
                .unwrap();
            let membership_proof_is_valid = block_3
                .body
                .next_mutator_set_accumulator
                .verify(&block_1_tx_output_digest, &ms_membership_proof);
            assert!(
                !membership_proof_is_valid,
                "membership proof must be invalid before updating wallet state"
            );
        }
        // Verify that the membership proof is valid *after* running the updater
        wallet_state.update_wallet_state_with_new_block(
            &block_2,
            &mut wallet_state.wallet_db.lock().await,
        )?;
        wallet_state.update_wallet_state_with_new_block(
            &block_3,
            &mut wallet_state.wallet_db.lock().await,
        )?;
        monitored_utxos = get_monitored_utxos(&wallet_state).await;

        {
            let block_1_tx_output_digest = Hash::hash(&block_1_coinbase_utxo);
            let ms_membership_proof = monitored_utxos[0]
                .get_membership_proof_for_block(&block_3.hash)
                .unwrap();
            let membership_proof_is_valid = block_3
                .body
                .next_mutator_set_accumulator
                .verify(&block_1_tx_output_digest, &ms_membership_proof);
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
        let own_wallet_state = get_mock_wallet_state(Some(own_wallet_secret)).await;
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
        // let (archival_state, _peer_databases) = make_unit_test_archival_state(Network::Main).await;
        let own_wallet_secret = WalletSecret::new(generate_secret_key());
        let own_wallet_state = get_mock_wallet_state(Some(own_wallet_secret)).await;
        let own_spending_key = own_wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let own_address = own_spending_key.to_address();
        let genesis_block = Block::genesis_block();
        let premine_wallet = get_mock_wallet_state(None).await.wallet_secret;
        let premine_receiver_global_state =
            get_mock_global_state(Network::Alpha, 2, Some(premine_wallet)).await;
        let preminers_original_balance = premine_receiver_global_state
            .wallet_state
            .get_balance()
            .await;

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
                .wallet_state
                .get_balance()
                .await,
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
                    &Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(&block_1.hash)
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
                    &Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(&block_18.hash)
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
            .filter(|x| x.is_synced_to(&block_2_b.hash))
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
                    &Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(&block_2_b.hash)
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
            .filter(|monitored_utxo| monitored_utxo.is_synced_to(&block_19.hash))
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
                    &Hash::hash(&monitored_utxo.utxo),
                    &monitored_utxo
                        .get_membership_proof_for_block(&block_19.hash)
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
            .filter(|x| x.is_synced_to(&block_3_b.hash))
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
                        &Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(&block_3_b.hash)
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
            .filter(|x| x.is_synced_to(&block_20.hash))
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
                        &Hash::hash(&monitored_utxo.utxo),
                        &monitored_utxo
                            .get_membership_proof_for_block(&block_20.hash)
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

    mod generation_key_derivation {
        use super::*;

        // This test derives a set of generation keys and compares the derived
        // set against a "known-good" hard-coded set that were generated from
        // the alphanet branch.
        //
        // The test will fail if the key format or derivation method ever changes.
        #[test]
        fn verify_derived_generation_keys() {
            let devnet_wallet = WalletSecret::devnet_wallet();
            let indexes = worker::known_key_indexes();
            let known_keys = worker::known_keys();

            // verify indexes match
            assert_eq!(
                indexes.to_vec(),
                known_keys.iter().map(|(i, _)| *i).collect_vec()
            );

            for (index, key) in known_keys {
                assert_eq!(devnet_wallet.nth_generation_spending_key_worker(index), key);
            }
        }

        // This test derives a set of generation addresses and compares the derived
        // set against a "known-good" hard-coded set that were generated from
        // the alphanet branch.
        //
        // Both sets use the bech32m encoding for Network::Alpha.
        //
        // The test will fail if the address format or derivation method ever changes.
        #[test]
        fn verify_derived_generation_addrs() {
            let network = Network::Alpha;
            let devnet_wallet = WalletSecret::devnet_wallet();
            let indexes = worker::known_key_indexes();
            let known_addrs = worker::known_addrs();

            // verify indexes match
            assert_eq!(
                indexes.to_vec(),
                known_addrs.iter().map(|(i, _)| *i).collect_vec()
            );

            for (index, known_addr) in known_addrs {
                let derived_addr = devnet_wallet.nth_generation_spending_key_worker(index).to_address().to_bech32m(network).unwrap();

                assert_eq!(derived_addr, known_addr);
            }
        }        

        // this is not really a test.  It just prints out json-serialized
        // spending keys.  The resulting serialized string is embedded in
        // json_serialized_known_keys.
        //
        // The test verify_derived_generation_keys() derives keys and compares
        // against the hard-coded keys.  Thus the test can detect if
        // key format or derivation ever changes.
        //
        // This fn is left here to:
        //  1. document how the hard-coded keys were generated
        //  2. in case we ever need to generate them again.
        #[test]
        fn print_json_serialized_generation_spending_keys() {
            let devnet_wallet = WalletSecret::devnet_wallet();
            let indexes = worker::known_key_indexes();

            let addrs = indexes
                .into_iter()
                .map(|i| (i, devnet_wallet.nth_generation_spending_key_worker(i)))
                .collect_vec();

            println!("{}", serde_json::to_string(&addrs).unwrap());
        }

        // this is not really a test.  It just prints out json-serialized
        // string containing pairs of (derivation_index, address) where
        // the address is bech32m-encoded for Network::Alpha.
        //
        // The resulting serialized string is embedded in 
        // fn json_serialized_known_addrs().
        //
        // The test verify_derived_generation_addrs() derives addresses and compares
        // against the hard-coded addresses.  Thus the test can detect if
        // key format or encoding or derivation ever changes.
        //
        // This fn is left here to:
        //  1. document how the hard-coded addrs were generated
        //  2. in case we ever need to generate them again.        
        #[test]
        fn print_json_serialized_generation_receiving_addrs() {
            let network = Network::Alpha;
            let devnet_wallet = WalletSecret::devnet_wallet();
            let indexes = worker::known_key_indexes();

            let addrs = indexes
                .into_iter()
                .map(|i| (i, devnet_wallet.nth_generation_spending_key_worker(i).to_address().to_bech32m(network).unwrap()))
                .collect_vec();

            println!("{}", serde_json::to_string(&addrs).unwrap());
        }        

        mod worker {
            use super::*;

            // provides the set of indexes to derive keys at
            pub fn known_key_indexes() -> [u16; 13] {
                [
                    0,
                    1,
                    2,
                    3,
                    8,
                    16,
                    256,
                    512,
                    1024,
                    2048,
                    4096,
                    u16::MAX / 2,
                    u16::MAX,
                ]
            }

            // returns a vec of hard-coded bech32m addrs that were generated from alphanet branch,
            // note: Network::Alpha
            pub fn known_addrs() -> Vec<(u16, String)> {
                serde_json::from_str(json_serialized_known_addrs()).unwrap()
            }

            // returns a json-serialized string of generation bech32m-encoded addrs generated from alphanet branch.
            // note: Network::Alpha
            pub fn json_serialized_known_addrs() -> &'static str {
                r#"
[[0,"ngam10y756kkjqlye95arwt9mgfwqgu406xksep6yg8n6p3r6xv8e6kljpemdul4h7440zp5065q0nyw3w8mzt39wjfgt5vy70au4la6yd96n2acq0f6wreuvvjhq7yan74eat6nudjxvzrnxtys00yxpk8yuzprfhzzhnr5pz9mfaj69kyrv4xk5hyzu9rk0dj93zh977wpf9ad7qh9036sn996gkkdxssqz896uwv8h4pc84afaqlpvh025slwt59nyse9nt9lt9p3uh0mr3pc944cgf585yprjnrm05gjqlu0w0jy8l7cr5dd7n6sd7wykf5ztqk2588ayjsqq8wm880quhku0djk3jn6whwds47tjrdmlpjdudwp44efkgtj2glymn8qswutp8l8wj2kpyesnr5ejhlexthq39jypudddx6mp27n8alepy3k9vqqypfjxuwlrx6j54l294cg4yh9wsxmv2ux6jx38ctxn4lmg6lpn4pamrl99z246xzm6c328zw2apn8ljr5pcmhzwz69weukevxtnfr99s9wfqx0fa8ps4uwn8e95m4s68wevp2kvnya8nj00nngfydvhk2fe6ukav8kmsl98dkd5nm2rycrjjmczmvcxts5zlvw9t52lu47s0htwzhy7mr49mkkafwycmv6gxrphuszlm04ksxrvz4zwrkj5w9w5qmy0z5rgp3hc5mja293qvtxhq5taw9jk0cn2cnu5d9fw3nvh5qzzevmdngnuprg234jx6ayycwuw7nng27pzkms0jjqj2wvjd4wp97sudvklqawyyyhnxshx3ydtsy7ztrxxfctkfsj5ug0lf72qvh5yfa07yvg6xnxarnclc8vwl49x3f2gzhm6gjdgwgjtnsuzjhx6unsgccfcw986k2e0fx76wlu2774r8prduflepyeqw9dnzf6795p7fg35r7dz5y4yu6ew4973smmafwnscy9e69h9kvpe3zjpjthke3mtj25ryd0mhy92paqsyzq7yd7xcekp63ryx0xvrdgq06aghdyra0y4kr0v4meynxfhdvxmvkp2mjzm846v8cf84z0d8y5casmay8zv5hlrz990sfsjd2r89uml7ddzf2ruv2m46q8yefj9sdpvw7nc467q62ysvl08w3sj3c6tz7268kx0c680rfffu4kgm5emp252j6pr79aj7f0fn42mxjt0nwu2shl2je6c8lxak82k3y4srnwat9z0rkjgtx5myadn8mlsvzc0ueuh4k8lyz3hgsdmak6wpzevr9sty85e7mut7r7whczrp9uexgy3xwstn7m82yxsgshrg5x5p4vpmafm86a4nc5ayq3ty54jmavx30ey70gmh3mf507ktr8hg9sx0rl809xd9vwxxw784n0h8h4wkkvgu2lznm5qeryts7yx68m2y32qg4j9utp2sk2ajdhzguh6cja4stj5u8rv4f50rgehhf9yqt8qaxfshcp4n9zh373j0yf2ydalftge3rs3e2xj92fnsm70zkll9hp85ghvsrtf4zhqkxlmq3ly4ystplrrawc2zlx2qpdcvhzzr2rgj9stvcw66229pvgvc6fcftynu4p0cqe0emx7f3ff6n0u70ksh08u7a0pwfgtvx0ze09l0932vlgjs0c6les0nvfpqke57w40gsr6xuljts9auqrl3gjmlht2nglwa5lvcndcte53yekhun9nxg50t525ek68838zah23edrzcsuscaw97mx0l4aem2d3833ussl6tytj3xwqx2jek4rcqvy737q5vgxcejvr0nnxqvdhj0gsklly47z4m74kku50l7r6kk6f9rvx7777fj992zusasq58ldap5jzpa7wfp080ksnh3d522sxgnxy9telufjtwsvdf327jqy6knet3kmkensxfgh6gw4cjsjr6cnd8dw7efvgze3emk9gjh55tewt3xe9p5wwg03l0d9694gq5cwpspsyaezua3yvcjs03gk7vd6z4kfc9fahqdqhhc5ee24juuyau9pljwvsjmdl2pu4e4n5gyea0nm88fc8aeeasnv3jy752gavjq7a6pd4phzjhwdn6e47k29665axpwzzvxhl72wnmcya5wll238pdkgrfy6j874teu0thvx7d3r8037lcmqz7ql69e8aff5fzad5hugh07jkuvx4har3ncarcd2w403ntutu0yhq2mr4k6h03pxsugzzp69vvlc2e0x0a8v599zck0h0faj8wtd037t5tfy8n8nadq4vyhfavpnm3pe5m5yu2jdxu8m9l5gv56twk5mve52ylxlafu8cmrwjrwpn2ll6t2q70r08fqr7pfp9gj6w927rn9m05gdcn4kt459hph4sywhe3ta9cfq74wz83rjy65exhnnkc34uqwcelf2hp2gecxzrhzuggaxgjgqf788ha2tgrf5chtz4j8al8px3vmsgccmeqtw75cyd2uymjwyhjnud8cgppxw2uk0dp6cd62lcpwzgzjc74cuv95vwk228e02kp2ahdgywehuautc5v7cq9cwa993fm08s5njfcnqk0j70qhrqtvu0qn7vwxunshxs0cqy28uyj4gme2k6h4yuvye9ds6c987ez6d9eluhmqjfug7cqwwfwafv6ppts9fz3xchq97edc73c2pherhupdanhcphn8h2j5drmtz3h24rvcaqfdjf4upsmqwjxvs94ssxy69655dqj6xf55cwdjsn6eej2c5t4ln9ytxluc8amn5pz3hcr3qwnfwyqdh9jy4hleftkdh3ewyngaj8ugjfumenqahdfzauhqf3puk7kqaffjyxq0erjk4v9g9g5zql520hl4rut6ys7syxyppd0adu7hx3uj3rxclvj79t03uvzwd0js0z0wd02rf87qu7ax2k6ytkulj8a4yu7y4rfpdxmerdckclyg9wnns6566qx339y3t9e4wusqa4yd2ye9lmfeuhgmzyu0n9yjususgl2wsypzhznxrk6darh25qkhy9mc8y3ejdmgsr0p9maf38pzyxzar8r28slp2mfzsh3vxnjfqwqsshysx5kp3ajkj8shfj3lwra7qx3lp3rnjqm06m8u8cyqwc984ej84rpa4a33au88s6lw3w97qs3xnyqc0um6w7qew9rxug2nh9sfyd5cjdzz8576260c9t6kn4tgcy2xtq5rxafhexn29upfncazyv7w48l9dsja44z2sp0de25nng23s39xcz8m7c9jh9gh0pj0u8jjfa047qey0ymh8m7vgfy2fsu3m3rqvmup0rmzfzhpczdmpfqev4sm2nwq9tsudrt7hl703f92njjd7mc70ah20x86zcrh3xakdy4j6a3cpjum2npexjclz9jkg9g0955rptftmezxfskux42ldkeytr05pwt2l4vc"],[1,"ngam1m70ekv4xznpwz49a47khwwqhkzg96693sj6kxyw200gmefn599qa3uq7muyydkd5279x4vyfyg46cj8yzu8celstt4t7acxan75zuj6ehdmez457ny3fadnpufq2kpew6r0rnxahs8d8zg3vezne50r7j6x5mym6dtpyj6wul2ku8v9tpxzm5pwl5wxkm8qlzrd5ctn4cwdwtatvr3q00g4ww0atnewt3cscqcfk0edrrgtsy0j65l7shcungmlf7lrnc3aequsasngmhptr4y2dqrqaernpv3exah38rrkg7vlyw6ft8xmjcq4yut4nnh5trsq7f3e8txr26nd5cne5r70y2at9s0kzsez9j508kf575nj6krdpxr06py5mhht5d2z2pg4vsxl09y9sann0cldqm0v39vajswpss0f6uysz5k4kp0hc3cmsvkwhns4jvdsgma7qzpfzkfzqdmzndez4l3cucjujqncc7yf8alyamgsxv7u3q7u9vqm7992kjegljt2vlnkg7gx5glepqlurms4zkvyahxjukzkrq00wmg6ukpr9y4h9sf8qvumspv4ydx9u5g8agg6fj8kas65mnnc9rxp259ycf3ef7zjhpzehp6ggn6s4mshx3evgruw9zfut896cjf3lkadm4yvtfrznsd9ma8ynyqukrz7q5g87wxygk3arrtntp0mkt5je5889t394vz05a8fckwm6aqpu5yh2t9fcr9vs85xud3xsuwz6zfq8upa8zrga3lw43vsaaz3aht6nard9eva5jckftksm800cgdym0m0unwjyje8zu8m9dezwsl9plckg0mvn3jnfr6c5tvvj9ak3dph7wy0wxq9uy7fqhwvx4wdjepltstw4tshhd6jlzw7lzmj9k905wna3r9gwx5pyzpt6h4valw9ldggtqzphh94u3xlz3s4r9pnw75g5zn7nxdwehj0waxsmar9qczmc4mwj0rld2avq8wvaau802mtex8petj77pc02dyqlpkla9dkpaufsy5dr3h9vllgzfpuems08nzp2yzff6ghkru64a3h5n3f78qc6caf4ehzh7n3sqpxvw5h8ulus5ry057psclppsd78axkmvu0l44skmnnmtd5w2fwvahkxu3s2hjxyaket73vkk57ggrcu6sp8r062zthpnplj0yuehnmgnqks3s7728p660p4dwtpvrd5kqesnzn4myaqzlxq0epaakvnmeju555qv9ulvhmux5qmucyeul07cznnw9fg490v35ucq73stzhpsgyplv86yczg9846kzvuekzu6lu8kpj79ezmtg5agz4qa2keznzwe6ytfqn8j6vkpnpwg4xyy6ldkj377wprezgnaad28l5xgtc20r842ejwsj08yqmwwfmg8mdnsvnx953m44uz6lg7pq064wdq6zkl8s058gavemu9sgz0y0m3yhm2uap9xdfs9x7g48jlt785hawnqxze6yzrrmhjq5r3tctqpt3l3prcgtzustv0a7j0vpk7x2ug3phlaguj5xmmgdkfrfs4ld7d88gd45qyte66a5hx5selnq2vt87ua9ch5z45wasxgq2hjutgkvpj8c842zup7m68399wfs8jfpgmn03jez7ra3pp45vcdtt4j9sjx9vwa2h3yqvsp0eua9japra4heyuwhw2jxyhtmynmpkla9jwpa62nyzvs06q62hgkx7xj8vf9ry2r5cr5g3nnf3z38fcs95zzv93hrswdrsswp7rgcj7k9q0ux9sw7pz2lzzu5r2pl5g73wqc4syvydrw6zczjq8t3g7edw5hkttxyyjjx3zwd2ldj9qm6utrldu3evml678cac7syrgg03ld028s9qxgmr0adfesj845a9lef03p3f5s2qdxvwgcegflmmeps7j7sfpzesrkhvzhagvpdt7jgm87eyphup0ej57ratqrzqy3q53th9fc7ar7hlfatk6w5gx07dhtjfaw6k0clx6dqg0pf4g204rz84s2x9nm2mavsd859m52hyexc7huzl8js7w4jt26dz52ayeuq2zszuajv3tkdr6eln3qyfayu0ztxhmddx5vzntefjqeprfl9n3nvm4leyzlmyhnyh8v545xr52lvql7m4zdscq62k9auezjq7m5g5240wv6plt03cewp3rzuj22pny255w5e5tker9q5kqutrasykg0p4n75e6g9l7gmzdgathx69rdxf4evw9l9rn3dtaerumc5k92h9fw33ramef9d5859jl39pgqyprg4a0uhsmnp23xp2jlt3u7qtnz5gs0ajdum3zp97c467m24r6u4rske9keykugclrxs2zy2l3slytvu9n8xpu6jv0ry7axme9hmvjzhyx0feqkg4cnzqssxuw5xt4n4ueg3th3u9r5444gnag0h7akctmyjrj5g869az2a6t7xwd8pcm3zk6fr0xwmpw2d4al6ylq8rz48ztlnce74c9fmt96nzewt9cs0t942hrylu3ahdhmeshgu28xnqwne8u8ttuvtdpq42jqtjh3k09h6yzjl8sssg5778fe4gkfs7ytm3cy9wjv8nn9e23w6rsnv7alxrsyvn8exntf9amae2e6mjmk233jdwm7w7j3s7elf3xf0lsh2wy7nfdt6r4zfwcucn5vtcrev9n8wxx8q6lcxhk4z7c6hjgucs7a70737ww44tyh9c5yk6zrcg9unxqee3l3s6dqrx9nu530r3mmxm04vp6jj05ppv38gvuxtxyqed64zah2tlcw4mjh0h5zp0ctswjk68s2p9ytehlndgh4rls2387lk0zrjdk6hx979z2jng3tvdc0t44hnetdvasyal98uguvxkukfw7xyad8n8pm8jp7v0vme83yufauta4z939kazueu9504l8wk8dyvvjsnqcf9rp4ne62xvkx68995txk60mhnfqp5f0q49vw4pn3e3362nplvjg93sexae3jcyw4ldffcnvw0l2pl8tx8c92u6p2lpw26j2cqex4m529xxg323vstue5avh7tssw2r7tnc4kzuenqfrghm9sllf8pek4f725csc0r43s8j4j4a8mq8yjn975s9775nseawj79qzpesl2h5275we6q9s26v60zjx3fv3n5yjr5cdtkymjy0h37yhwyf2qzslrlcfyruclpkxcczetrwxgmgeaku2nya0nr2q6dkgyu9uwnt39jmy48shkmr37dy4q2dlk00n92vrexh2vz79kvgd9ftm250xs4kcalds63e29e0m6ezu3lf54r9p93kvax5xxhkheyglmqzdrzv3ls5lq0uvgqqc0enjppc5w08mpf3a87w20gf2wt3hhqwr6p30r6463tdukk46n6a9phwwj35pphl8k3m3k9y6ey5h4x68uvhjsxvg54v2"],[2,"ngam1zkvjg2a0e66xcf09mr5mhxm8h2d2226zt4yam2wkl4kfp5axp99w3shrv7lru4hcm5d58fghvky3cf7z9h26z2x82mx9plezl7lzgng5rum5gjadl3xpsf4sev4zjqnkvdv0540qm6trx9srv2hhz3mnjs68qtj9w0g2t37llgxzf29kmrk92fwdspt23wrc6rpnc5tl6cv5ccfwg0hyncqpqwrmlqnc9kr7u3t3758rr4el5gzhpy0qx5zu5asjqkmlh6v0z33uau89gkpvsqah2wn02x0drv6cwpy8arafhdssmy9kg05r3zqapefgz5zea3l94y0d8m8tgqmaee0mf93vmmn4e3ydmn4tjsqtn4vcdft595wkcmjuez6cc8zh8q4jqslfs8x2judcheqjwyj4tdq5x6sqldmwezzhewvppca70cxxx3snp5hyxv7a0uqx3ntalhchwz7wrv8hv8yeewl2wsvkmc8sv3pq3ljmt78tk4pkuklee4rvvzxn6wu8dt2cm8cc0h932x7wrktrj2r4mvk8acp86ey4s36jmedtzzmactxjz9ds6vc6jnn6gll3cv62q8nds2yv6f7g7557vr8dnhnyldsll2sej3w4wdvjyl0c932e3ach6h6g7ncmr7l8hvpn4axaa52045rzaewa0m69mranttewk0qhxhf43dh470kvdtj36r5vupv6d3q82c4eyrkutp7sxa6h5uwv9m454exdqnqm9tdjl5p284570kn0jvsjkz8dagq2wftmku0encym6g6jmdjg9m8ptfj49m6aq27epyg66c9m5axxpa0m02amzy4en5am95yea3g2yqhv0nmeczr7q25jzp5ps0wrg6yv2ah387q5ha0209mnjf7newayc8q9rffkrltl9r4uuhe65xvsj2kpgfy85pv896dde39fnjg67a94mr3wqqvlvgv026mmeytquhzpvnxycpwhe99lncye3pgvcapatcew40el56vtj6uw9e4cqwtkmej29wrhfffru8gyftazhaay267t4fcpnwzdhqxj3evh8geauducjva4csakuwg8jxgfccz5w26ngl8x9gfrpp29j36qdwdyqzvfu6d555g58tn8a94vc8v49uvqylnq6knw3esp6rf7gk5hatl9f7gt5944sjnlmfendnajtsf75c6w39gwrsf0m3hs4ke8u355j7pw8u95yyzrt3cvl5tec9fldgwx435ex6pg38d0p0vtrtsaanv7gfshn8qt97zp6dkjh08ytvh8n9s8ylwc58d8cemqtl3dasa47gkewqv76axkl7wyztfl3j7rv9xjje0cx86qnscwheayfwmdxyld6rhdukv775mnc6gl0gk48e44nh53jcdfl5d2zgvj4sgsqhlqefqz6ek59wndh0r8sqhq3edsrzzp7twpsa7lcrmsf0g3ut3rhnqqk9xy282tdmvq5w277qd60j38l6zjvsdrpd82hujrj9xh9nv8mctmuqq5xnz6ahv9kenm89ycq3fy00djdx2fvlslh5msegfcwhvqghgazne8vmtv3zsn3vlcwd5hpcyjs3zx8u4w97yfs45na3ft3ysazn5hejchxedx3d6fd3y5zfzzen6rmk3uqte8507gznv8j3px4yvl9ur3p678l449szztru7k7htlcwkklfmj5yreukdux7vycl24pnf82zhwlmff3gn8wvz4jyxt8lmwqvlku4q2pl64znr6ty7fcryvxxdx6gyztnre2xwyke6hxghefatjkd2935ea09eenyg5yjecuvwmzh45zpsmer7prsznr88pvl2geyua57s2g2a6t45etyelat7ethajufprchcl3hkgh5ln2lec2cq739anrj475djv94pk3nwsh7sfzm76ctzzxfv9qrdlumzaehf0lcfkhhxj04yzvg26gpk979dhkueg9le0j88jlwgg6gj7y4jt8t6w9knqta7y0fshulkuhq4j7krlt0cdrvvfwn64dgzzeeye5mwygywuwttjgx8d3rcwsjdmznmty5glj6n83mcrrmmkrw6g3ha2zhqly2c7egwpmqf03krc8zjyec5vry5hsrp99kw82s4skvgjas9lv7apcjhs9g5v9ca38hw40ua3rr8sn4ltjrhg584kde7qppa27gtmt5cvn3qu8vnyvx30gxysnmpx3mkjx29slawqhqw9g64em60tncdypk632d70a0q6x7psuwp68x4n83gvl3msv3w3zvlrgsv8ghgt45lzslqpe5a2ztx86jndw0vc8hvgrkamyfttr9ejt80su3x5yx4z0rzkamqktsn9d0w20w936mskpkjgwc6u35hqvr95jxlpwhlej6rerhucy324p22yag8ntpmhdx8v560yakz35ffk96q8sdj279mzqtrw0s3hluxfm5en295xszyaswzmmz2w07d2qveedkrway9dd3adtzqjsfytk7qgf9fgq5n524g7nfgkh8ccajxmanxrfh74k0pec2gf8z8y2ynftppzra7ufushz368np6ways9cnvkanrzw7y9rxke0vt34k9gh0l299n6hhy88tepp0v8rvp68hjgvqd755j8d82sn2ed5gtvrnm8f4ylqdam5xlvcmckj4l4xcxe36rtpjpd8u7tj4n30s06czculcjnxyhcxt0lsna0malcevthukdlrpghnxs94tqygklrqplfl0juwhav4wgz2pqwm2ejgakffmrfjrw4y2w27wzzduu3666t7l4pw8teucfmwz974e0xvvjhszfdf0rx5ygel39agkggc3fpr4vuzac7q0ruznmus8g869cjqssux9q7m75xawdvxrcjneqx4phqezvgxhr03x5ygyc0rp8zyfum8nucu9x529arsml3hz9nfjpr5nxreg83vysy220qg4d2r4607a4e839smtw8k9yc3f2rcy7tulk84nfseukp66pgw87khux3a03px4uphyh289tgy86uvrxjnw6usf3ekguf3psfad4hpa2u0rn3rmpg6s0qv4sw265kht0x7ja39w4wx2n4kvg7zucjf2ym54emp2r9j70errupffenr6k9c0e7qyc2jn9gw8eua5kjqlvec6gn4xt0w4r9kv43fwetsmfth3ycvc2c6nqtt7dxa2qpvczmlsfev92vdre3x9x6wpter3xx8q2ms5ztmk532nsgv3pen3800xkxyapk2tj6apkgy7wp0sdsndsl6puj3z23g222ch990yl0pvkr8w8l8x3xxwaujg402qewmx2p68a8jrw04dtzvad2cs2mn5wg2xqxmm5en93lp9dm83cmcsgszqtscpaw5raldkag83ljf0xna7tmd3p6de3ye3py83l00lr8y36xgkyx7mn7zqy9qsmkze9qqdl"],[3,"ngam1nlfkrdfrymca5aj0uc0yepe6xckm3jqgcxd72wadv77u624x32gnpd784pw6esuse65aaz2r9hjkwguu6ja4eyhaw5nc5d7phdwy5r8znznt7s37yvr86ge02naee2syg20ef92rawrsv7gagsxqeduf5pjqdndu6pzcq3ur4xfpjm74a89jharqswpje6kd33gdtfv2ehcju38mlmgnazv442u0zgjsdemqs3vm45443pk4h0uh6lcewqxur3xlsq2xs7qr2lvuhw30lzj8n27qx6482554eardrq44huktccltz7lexjfjj0uschl73n80wc693je2ddzcm76rcdadw5ykxhre8uevkqmgvs6meqq6xk4zgpyvk7epqyl4n2a482tl0t6ekp0k8yd6gqmxg2rfkrku97fnzy4znva6l7c4mz27yyfqkahl5vmyfr8ecs7fryqltvj4gqeqa4m9cw9pzy5vknnayvg7npwesqztj40ju8m0zkgy3mx3p96ucslkz286ks97tngle7gk2aw6z48f2r5thefpl90d0tcxt3ka2k0nev2ph8jxeavy7zyexlxfhfj2mxau54tgued7v355uyklh067dmv9caz9cg5d8plkgnvala5n6ukwufep85z5sh25pmvpdze3s63ptw3hdr6h4yjz08qa2y472fq55pvj44jxewstarcf4s50xpq6jqchs0g00nly3qzksu2nsw2t952l9wx9zmrpt8fdm4tdg4ayjke0amc5xxrchze0tsck7paq2ty37na7txdnqmahdzu3zyphze66ngvxg5vzvzlqsd6783g63z09uxcv560slnhzuzaym5h45m2j863nxeyzhh9zrdpxtqmul5ua89wu8xwk3lzgrujmz50z3y92k39x3zp5d6xtkhtagvsjllue9uy2tjcl66c8me73z5zxk66pw654j6ufcjc32lm2jvlvpvrzp5ncz4n7k8c3ffu2a5ll82mz8j5dyn33kf003uknnxkevlexjdqd08xfx3ppe8xw3ja0k8wpmhls33uu09tzzlw5dqgp87sagwl42lp2zkskwr95kyxpct6yjxvehj49t9kez2nsa9xv5deyuw887muhqapzr5qh0s47lzcruh7y3ajyr7vrj7lfm47ughyu9rag4zltz9egd4vwqxv4yad9lxflae5qxmt953h2av4vm8uus53jcxg3azt8c3j5hm9dygckw3whdr7pl55hehjruqv60wpu9nm97dz2adxnrfv5vvc354q38gc63mgtxnmlsg8wpnm4n7knpd64qy2zhh9qyv32msyll4vfjmhcxrdzkz36t8qz2e4aj03yjqztds5wlalfz9fttrjwylw6fdhmws0htcc3hjx200sdgsr03n9vlddwexzca6ffduww5jx0vw63w0qhcsz5vfgpaklp0m3wfutaqvga2spfy943gg289y2rr5xfgq9c5ft98z42yh7yawjza5gxjzejc7fze3vqjp8tvlny7v7aqccglaguy8x2gcrkyt04d4z0wc7jmwwex0xlpg446g8wyjezhfnkaft2dj2ualukauynysrzv0tu4gz3q45fsvkhjvu5nf8ncqp2pwrc0cauc969wjtnq4yvqtcwuapqhxwunmqmk3f7svwzm3qe9axupsfl5dq2e56jnm8d6vd5pn66ttpdm49myjx4nj93evs8g8fv8rw4py57nnzc48xkjt95jjggyrlp0dgs7ap6pt2v4sxwuajxu83c95m73ugrg3utatndgehsfxcdskz4jg8k6yc0pzns4t8t0aaftqev50qv0cnm5wrpsqv0r3he3jxj5tfzc6pkjfafuw8arqxptf42zl4h0ntkaq9drea3yx0x4f20vqfrq95748txeyqcjjpzf8ezf5fjkae7javqdq3pg8ca2fmvfm0tuastxpjxm28lxf72dycsldtk8gvx6mr0qsx92klv2vw4l87klje7rzacvc5438vfhgmymnxme0vyuas370qmqft2x56w5n2wtn9gmfda7wzl5rlvwwezuuc2mqml256x24a8xpzu76fgdyww72r85s6546gmd4k8fuc979gtag37sjca65uzly4t3vvhq6argdq5gjzn5c23ws5elp97mc0q8wujcacjrjjy5jzpp5drjfezj2w73jmlk0s52kwgu6j7tmfyz9zfjzpyxlkk9g2kzmk4ly2dxsauwuxe9xf0qsuxtcaj5s4rs2x4g3gv9x70nmc5qd2rcz8v8rksptxk7h2s2mjdjax40hsktc6a30yatd5ddtf0herld8tsllhuy5v6rekd3dcft7n3d490qtl9s87dhgatjzxc3jzv7pjsmxyd5cy4y7yarpty9y4ngncxmxr8pntaskjdda78lgc4fngv0558jjqnc4ju209903r0rfc75zfw5z3lqu8yp4hynfapyggkemsr3qgzrfyr7rr8kzulfr7kh7hzxufynxgcnjp7ge950046978hy70xhkdel098d98d3cfsyaftrfxpayvmjep7lk2v6ts7u6g4zh39xz4phfpdk4zfyd3ckjspdjj5yw4d6vdwf9vt4t6jhmrazuall3qekv8llc0vurudm7vylqxfqvsmac8hzxduqjhcx469fgh8jzl550955cn8dg6z56yme43d840hqd23nhg8qmh3rlzg6yk09ge3n7yd3x6war0mfyvcjgerc6p3whq3etelulk5cut0hlkdtx796znx5ahkuan2djkknmxz2dh85mhr0seq99pydmc0h4h0lsxx3u9fkjj9vhanqqtvwhnje6r4yuwnh2hsn2g29r36ln79jc77tvrs3nxj94yfvj9ch3226gxxnmehh7g7yky3a4pdqyngupgztpyfce7skw5zhyncd44er327cdrx4saqrqtrnm0st9ger56cy0ktepljvsw6dtc656erk8td7q7u3d78hjzfcjs2pegykz3lzt9wrrvaay8hjrf3p69nfrhq8qlyt5645hr4dpqtpxns0k4gu0q4ml0qkm9rqa2dxle9kzhgyf6kd8uhurl69mm7uxgy0l2jqx4lhnf9gs8n5gquq5gql3qhav59pn7cvrn427utp6huawc4fv7gn7lfngy26uhdyz63mn6h70drrfrrxzl24zcjdf4a6tqsnyv2ghvpjhm7rfa5jdnpgjyd66pu7s05zt7yc4tt3s8alfmynuad8q4mgygxpuqut58y4j6hhflee6xs5l2ax9w4a8xnv32xdv3xqvrutw9u0rafr4dh7lxl8l0k5hlvgy943ycswj2pwn3yfhsgmf464ypq8x3pzvq5zr3mefsnmrswrjn4q870wd49j8tesxqs4rvfll5nncs8y2mr5nhfd7za37jsht4yxnqufnxetdg4g9w6qz8"],[8,"ngam1gpnqh07n92qmlpn7kyvd9eza7gcjkv5wg66mfycftapj75p74k8x0r3uzrddnz9nam2sfg787scd2kg7feercl4hq2d5826q28eu97rxpyncl7zpf8s6m0g0yrr9j2ltvexkccd22lukrh85rezan3qtv4008a5t3an5qgu8s45qg7dvf5qgrnv8zemt6f0ag3dy4y4ah8mk2mdp5re2qg4t0ddf74j9576g6gf0gn92hdz9g2n5us3axyhn78hysq0a8n5rpzpk5m4efsuhlmlxh3vxw7ea07ek76f5c6wykvmn2pjfatcm4fslyqf4fsv88a7gh30pdn50uwc053n28vcp0ygfc444462w5s5cq8qwfqvcsyn9fpmm45vdtua9qfqterwrd9ghmkcm7alu8n9jeu9xf83pm9jt8ysa6cev3gpn48whpm0u0mthfy2zv3y9kyhy5ux2w45ph72ax4dw0gpdss2vt88czts9hwwh2y3h6qzpernxqv02ddwh3hykd4f4pddrcqz7wj5jk5x60plzdhnq04slt7wjfgsvs29k48dh9nrzukcshfcu4yh3zu8ygr2rasuk73skw7dcc8wjzn35rrtp37gz3egc3yxqy0z6t20dndkzfsvx4demjecm5j8v0hh5p6xs6a238r8vusffzpk6v4mwyqzfx3g95h3uemfq0z20gfnlv8j3xl4uw7sk8hwef0wcukwemp76qgl2kh9hkpj9qxy7lrhempmjry2kqe8auld9kj0vlym2nhs268qedmvz28jkuvy24595csfhkp8rjf883lklcnzyt7d9xun55j422rjqjegdnnp3ff9zv2cyh7q2x4s0yvum3xkk4fj60fmecqw492z4m4nhyxvs4c2ehvq3wqmp06kz74a2z9676me876cdqwau8zs45d4vdcm5yw3u3ar0l3smqpls4zg05wjqxs6jv2s7t6e3zp3q9kt3s8aejha79eugx09qwwe6qf85musxqx87dq42djdeuujlkqe739wmwch7eznvc50d0xqz2h24ncmc058cchm4aqmmxgjwa2rax85ner80qt5zhxjgl58jh4h02lzfrua8apleqws2e88uxgusulss22p9pl5ppsf8pkhduw8waawcx5rmnnajzghwac626m0sacf5txvqgjt56dyc7c646pklltsv4nvgqzqyanx5ynfa48nez45vndwvk3r7t7x5arrju2ttn52fq7jaar5gzgpluq7a968mnwmpr9vzfhce6d9q6wy57dehlmkwkm482aqtdrh7y34p9k47g959vyvx4k7yy69vpz0jjn9eew6m2vd5cslrwh067fhp23q4waamezcdlau5rjrw84t42f678ms8uut7wuruwlm9u342ru6zh602n3s4ryxds3tclzg55fpu9fn8e3vaelt9gs9y202quaqlars89p385vthdfl3zws5y47r0zw0mmyq8wcceemj42q7q6r5xuv5xe3jln32vqfafu45xrewqqq4gavwnrgckmwhmqq4hu9kcurfzl5ge8p9wyvaa8pkk2xru6e0qnu3rl6guc7xd5vfwsuxlf7nrkvss3kk0wfzu694rr4tf7wfpscplcsumpm5hp8gnr36648ly2p2ss5gda3ndmctqhx5nfaxe82fxcw52kxf5q6kzh68zf6v3gklxvaspw2vqgwmcas5xqqe8e4yn7cjc68ch7zae2zuxcsxp04h8vn7sr53yt0hg9ufcektz7kyz8htwn2seawh6ajq93a2mspyrprv3dzy8chdmhv3v8qeg9yw3c9xwadsu6l0u69pauq349jf7fh68zv7lvxrvddy5elm98t2lxzjhzkj6n8j4epk85mjrmwhtd8857qx6wc44p70jav2hqas2rdunsx4r82phgkn9dsfpqzg46psv0zrhtlmwussd7hc6f4gyqfz9k2sy2fp238jesh2yn5jr9nmuu6e5hpfwky8g8vwy4p83hy9p0lkts5um5f7gum972wmmavd4c6lrrmpg85g24cmnfj2w7vnyxj54jw8v7v5phzd6m862nhmz8nyhp3pjksqt68hgaxgq30zt7nyhnhzsze2rq2h3p29q3s9ljkth59dyqxqsa9hml0dq9mvnp3emzrntlsnpzdqchh5ux4r699clkf2uyyukndxk7qavh3n0sserqv7j0eqc42krepdkqwe7uplpnyglnmfjk33uwy385v8qacrddjr3gvnkkzntnpl4urw0ez57x3yk45dd8z2drw6uhd4hw28t0c2duxazqcssa35cg3mtz5hl2fuh8pqpn0f9fy2pta5qmha7lexdkwsw8gmwvjgla7f630s2urr0d6thx5592p6q9lu9g9advl8chcjs6tea9mj9r0fknu3cp6rp05zn5dgm2cweeu8ac0nzdk6wt6ygz3kyggw3qxr365334p6uy976apy9j9u5gmsd03dqnhrw55qm74w065dd79fahcwu3ffnz7sfkrzev6kvn6056tl9nxwte2skh3pd5qldgdlrcddselvw4xtfpmnc38nq3tkahakhl0cdhx57klsnx8e8825qu8tw9paqp8w0807v7ll5cwyaxkz6lcy4xync7qx5e7sn9jaumvdh9943dvhppwzt52f8sq4mr2f6usd8vldqzau0pxr9djyy64wm28ydunvt76qtu69y3va0dh23rzq763kqkfdx9snz0dzuf00y2qv7x9pju30qv7adezeqpuzmn8y4g6u9hfhw0zhv04zmtwtsdnf0ygm8ffrlfcmzph942r9jkrcnm5gd2w7w37dydpces7vsqcpwqqd5dgw3z0x50ptf39clyc02e56m9ma5sz096ectm002d44vqjttyg2w37a3rzej82wxrhfkrurmy536tegjtnyvxfr2zycekr3x7z3yde8lc2rh0xg8zqeds7cqr37ug53fsgfzcxrdzwxje3kyaj4uj0e2ljx2sk274zvpqf0zxmx82ujrtd5t4j0hgjp9v03nuufdyg44sajq9s26y0k28n33slp9fcen937n7hua8qv9cukxpm7m5hfgdkmafgjvjx7xr4ztmquy5kck03xe99nflcunf399gyltgyrrz8rysats92ta9vsz8rkr7ehmrys2r0ltn2k34umyfu5s4esk3llu4c60u2f783efdeqdsdc2vv2hcfdcrq355sghld66ptsrye6nv90rfddjq0fzk5j65lvaeymx4nfy0kvheyt5r28t5xclkd6jaafcxhm0d0rune9zm8jza2hr2t8h7tr3830r7n32wcd2n28yuk5jm9uqrvh6m3amj6mz9qggtvfzxkju74sg2ch3lzzgkn4s2d45tv00dvkva6lmc8scgc9amclj3rn4svh7g9df4fkc6f6uw9"],[16,"ngam1ar7ltnt062yhh7yt9wyfm9ptcym03qs3ky0fa85nry6hmr0u6g6vj8cqaf665hv4hymj8rwpnv7mu40w46a4exkyjswx9za9f00x7hne769fwd0waaqf4wkgezfwffaurnw4hhwgvtaj6pp75vapcyurkmrmfshera5we8m7wt0m2f6tpwgd0evlyxfd9hy3djtc9rnz8547ls8zxf6al40ez7mvnjrjnervpx4ztgg3038gm5tsw7uw0gnnfyyr687hxyra82ngsavvf74e5qa8s06hnq62cnpqkpt3zhmrs33v4v84l0ur4d6te5483j2z4vgr2xkgl8zp00gcvtuewq3c74ftuem5kkwepnq3hma6nfhr33dc0ky90cspwshe0ws2nz674h0ee6fjlqfsna68vl87fumcm20tpmqa79nfqtnehg8e4pcqjjzq3ugspml0sds046xm5shwpka0t9ygxp8janwpxz3u9s633clgp0xjcmxaysqak33lmagwzy7ucz7e7pkt7zsdr2ts06fyaw8v8fjqnkgd6mgr5hswp9u583nf8un6ylkfe6smfefqa9s6ds4yjzs4q54mre6zeagdeklka42sr3remn7ql9zzhzgnryu355ynpekldg9lf7dv3ea3ece4sn7kzs053282rls8q7teys57wks6rgcruk53zm95z7trdskmuspgyh85x2qv2srczswtlymsz64aq8s7t8ueljlxwvm5qqssmyd3vrye98552h7y8shd4x2fvl3k6dmf9x2rr9uwmdv3vj0qlzuqtt40awp6axf6c3d66nsrygt3eveycstc8tgjntcn4juf8gwy7d3wge8qy9z3jwczrax2mag09jr5c59g27gqyxf700mjdc35y5kklkeafv0m5xdlzsy2leenj4d96d9ja6sem92sencs0zxl6sjmh97x4wv5vsayr0k7dmg2tj46q70lkftckfvtwx5t3vc48753wwg8v93euysmqr0j7fu4q4l5xz8c638x9m0egjpep9s9dugcck9x0gvgmz0746e33mumjwqcvefhwf3znz7urjrlxu5k9zkqqse3h2cde7q8zhs9ya89qpl6jtewyvcu9hu672prdywxf49xprr7lxeaawwh4d6hmnzapw9t2gnfex0svfucsen6se2zuex0k9ppfkxaazcss08yc2uls43d5tujdywt3vl8jc73fgjd4chk7ltagdk3fkma724sj0x2nnec8hrz9h689ak0j0n746frxzlw3c3rxxccfn8f8zy2t27qa3x0a8g40dna7fd786zdqpemgy9upnnrddfgddcglfuxjtlfhpturkdrczz46ck6nhe2r7hktcrrz37lx56wunkttpsr6ny9gcsx7xnkqlc5vnwvgjg4p6q0tfvtpzuw9t27ur9quw9e5dwgeggme7p3u7rjt9kvpnqkgexuc5l59kcg7vrvwuq45dk9cu4yjln2ujeuttw6g76et4n0mv4zqhyjsa2njd9d6mx7gflzl95g4rcrvxu2ltyhfhemytsc0rnt2q826ajxq2wjdacjzl2qp3l40srrammr7h4zscqk2rdt6tynxdeaakfmtpdphfs7skuyy30ugf3ca0aztdlarwk3uk58qdwldf8692phggdl6rytefx73kzgt36fck8ld9saf3zv78dn47lfnjhun9htsvdp99cnsa9t8wa6h9w72nnrz4fphc68jx9cuu693cacd8w3tzmxqvkgxugq4xg3rn9k5et5klm4502vdgs7p340krq6sex32sgrfasfm2eu0g7c376g5xq7wdwqlapaz5jzlcmdk3ragcuslve0wppf4s9x67wqqv9uy9nw88aklw6q8yykyc3l0lfad57dlxf5jvp6pjqmvc2hujz80r5n5rjnz6kmz7m33zk0nqw66prwjy2mztgy965dg6058xsazcn80jddsr0g2x9vv6akv57pz2e2epumg3pv67rdjxykl2zw89udjklked3spxp7lqe8sur40scswz682cd4gu8gupm39yuzmek2yjxdd0pmvfzc8zwt7xdfl5q3sd4ws6ll00hxr2jnxsw7gka3fsd4eqagesx6anx6s40j3mq2l3f5m4e4yzptmyx39uhgdmkrc7tuqar6d3naxwy0lj6penrzxy3fax24ma4xqhq8ccu4z785x70lcxwxmwz30heyz7d2056gksf6n473phu8zxrmyzwcume9vgza6mxmzksq392pdxhlqyg703la7ql54s8e9k9gwr36zerdqjexdt6mx8jnkk74zluvpndx0p89h46fxykkg9vm97c2792ywjqq7zedqdm3phds7z9z2ntvkhn7psd8yjkmtcap8ushvya2xjd523xw8av07jyc4056htvc2k89z5sz9yz6p59tsmlx4mqwe5r6aym9wtmmah78znqlv7jwelrk2d64crww5qzne6hs7hrczujyz2q3xq7t5axan9xa65e4thwqs2kxs3gc29zeje8jdpdchmkm8r27ayd70kznymulynf6hxa3kyhpxk97d3gdpcw7qn5kaljsyfhuusa25sfd6x34yf624crar934lslxm335qp569zxtyjj8xe0egthv4wnpaczv3h7jjx77875q6j77dws3grffqf2eh4ldujs0yaa7x6a9cdp5m0aak22mans0dvlzmq9anv8vu55nhavzecn0avqmfmd4j0ryv0uc953sh4zndlnsyle82l5pnlckq46s6unpcguxq0pyh59a5tmdenzfpj9xxfdekckla7z7qthz4y40kczt3wl6a2swudlzaztnkruj5x6lwmrqtdnhhqcpz6l6grdqhzdx44a4h6ux5rk30lp6c8as0nul2qvu25q7wn4swzjjsp467s6cf3zuwz8m8rzvg79pjc2mtrxyqmpv0pl266fgxnpunn96e95xc60kz5kycr43mm8hux2ddu0s05nfvndh4zl0uks5ml3ttavdafnj44drw05qaygece549jxy9mqte2085xdf9gj4vtttag49c5czuyuy66z7kt8qvd7w3xr2fsrzeesy54ypcgg89cxmvug00wwqr3wf2xe08khxlcnsc793cgtjhfmgkemyfnmljvpl5g6cjlx95z77x4kha3t5xhk99m8c0nuurwjgr3lh5tfhcpu4rnxpcj2n488frm9knufwj46saru0xqm497zddxxfwju66slx580d32jpe6us0tcpkm0nr8f8lc3yrh85tayvlvn6ed7aagmwc8m39yu3chyc8guvpww52vwq7k28afu8lvtzkav9ht5wsy37p03c5h0qdn8t9d6066duwmqqf367ap25eqxllmpr6kcraq8pem3v5l79ndpw35mmf8ug7js4ddknakp7suqkske"],[256,"ngam1er3ehml0p70zwexsqyx4wes8u83zdzhuwuv7t7pey5t8xps8py2xjz3ddtzgzdn0kytjnuagz64xyxnp59cl5smcjrld9cgets96u93607erq0e75zgj5etxxhpd8chtefh8vyk3s4z7w49geev32fly8gkr7nwqkr208c05nwvp0e5hz3dyml030sdn0j5evcywm50mkpu4fx7vkfwr9e0yx24eth2vgtqc2xzeprj70yg00kqg6wsny8pcr2x3lwuyvsnjjjm2pw4w4jj0f2cmuamr45asguayqq46jg2p05k68wqqhvdzcfkdt6gq325dvrfs6x0uvrgca7320z6vw0825je288na5qvw2fwqdkn8zj3vknukjgw3rvprre577vysc2udzd8zx76rdnzmzkyh2jnmmqrkw35dz07grrqrwndaj9cxfkahsgt90fju3fcxg6x5m8p25p38ffedf4wgnhgfp8hhmzkk8r8d6j43l558k0zrxtsykklg4c94rqey6gsdxa6z8c3e2xh5tekjvseljgy2qeztmc4gmqsug58egc5zpuqsqft5qmehdz093afeqkgu77khqt9uvxtd2eqpy8zu9f6fd9mwrcla2gq8wwnvjjtalsu8yf8382hk44kkag29zh7m8t3vp4j3pxyj47d8c22sxreyqm9tn5nv9pc8enwym33pp6nj9vquq5r772xl45ugfg4fcdukrm5pm0gf8tw5kn0nc7n7gqnkge690l6e2jykj83ntve7lu4w458zxx4hr6y9gnsxrlxgy7eccxlcw432p96ch0px8zwgclyxg7lvkwu0aalvne4ydlm4778eac0w55muqjwrepv634297uwe9wnen02u4gugtp9e7qvu03j0xfhf2huxazye3m8x63r8ztv54esy6rwt0zudvt7ey4wkrey3lvga9tust4mlm9e02lnfpwr8dv53hwmtw78unpll903wcpgtemy23cmnk0whvdxqqp49fg0sz08pzkpmk3e5s2v9sfhpugxnaspyzkzgdmla39sv4ndp35pv4dczl8msmzg95h88ggphl0mpy0jcpg279f6gw4pajjftv86ns89pahx9hzxvaqls96hmdavt24uzcq7kjfcltwv9zygg6u0jm9xu5mz9jul0qtuzy5fq0yfqwr0ehx3q8te4lc0chzc5gfxvuelkyvsyn8tg7dz6ehuuqeg32s8dednc3wht4rppehnjjg7zp2vawxjz709p6cu3vuu7xd347ult0ek8xv5v5vaxnqfal3f3ln506rscmk3hmwkqhcrqre39supxzt8qlge5mx3f75zn6v6f7c23yjurcq2ysq6pp4vt575hm8jsvnqx0c5pjvzv2vly3nzrpa8scg5a07glzq70jkeamx9gw9xg4pm6guutym0s7494zc2q6uylvtd970dgv63qdhpwe9je6k6eyru3ayldq2ajrq06h7dj7yc43ffcj3zy2yq7gfzvegzfglaeck37qkqpn2kjh4hzkujwz5uv0ggmyf87yv2ulagx7ll39t8fkq5try348h0jvfss80unwykz05kw5qwg4jga0e5setmr6ye642dcq3yns79nhu4tknd84q7eyk99gaxc2xkwkzwgdrd6z6uz428aee3cuyccz2w4g4rg8fkrv4v3c6dasl6vd78de2mpkgm2l0rd2efurqyjwlsre9z4zk2095ffl6zj4vjvk5r67dlv9u094l3469vj8f9sqlmznst3cuf9m06w8dg63ky4ue484nkj907g0zqz6c88na859zm978gxxh5axtu8nmlkyw6ze7srg2vltsjmk24rkalnhmp665yqpgfyqw9gesl7dnvxd58rdqyq9zkr6zfwnxyx4mqjux60grzzvu6mnzycfcs9vgycefcvp5g456sf3zrcdrglvu4vrfe0zqs5g0rtca0g05q2ftq0w33nzah7yxx006zu2jffxnpgtltz9f82dwrrdyru3d8jhkq7fvgf72kjxcunjjk8mfl75elvrcd0aeuc6yz2hgph5j7kyxpp7yesh4apmvy23z8r5tn63e6tenyexytaeac7yjyuztuh6lt69ek4jwl9exmz5mnw2j5l6rpf25v969fyw4kcaweumcca47x52rtaqyau2ajl7hftf8l5kk2saa3z23xgkqfd8pt7ktlj4s9t02r6sa4cqdupr7a2lgx0ftztkzu8p08pftjd7vda4muq405sdc0yqwkvw0dqz8lpupesflyt4erv6antytl88ya6jyyyfmq8wsh9xsw35y9wcv2luttcwszgrt3z8p53jxru04ma3qqszz2anfjzwwteyvlq0034fjaseyd4n62swwuv3650fz28wgr24ntte3ya8zfln8tx4j44the9dfkj9pnhwlxy2f95ycfzhyfpe00hawl60q329xwpq4g6k7ztprjwnztepuxkmwxw0h5gmr06tz5ktk9yxc87n0sedjtsedj5u8k6w8rdlk0wwem6rfjj8juzqrk3egyu2tnq5hyt74mx7x09u5ad5w60sk65mryc66wqp7v7prmkeaevkwqe0xmc9429tl9suf2rzxqlnnqgcm2h8yxhlzerttk2hfqj7gltzy4lxajav29nnewdlfd7puvhgnpcyxda3kmrwpzlxj2q2d5q93f5rm5y5sphlskqrppnlnntyczvcjv97zacccm8rlhgfnftskunxsct0u8c3lk3ayyqgswfkjxj398zu5q5k2scdm4zcxyywh7duaeztxg7820qyqugnz0k4tvtnaflkjv9clqdt85afyhhxp0hcc2h3dn2463nyj0rj45wg8fwpleem6c0a2ggzgkfwm3yzmpyl2r6tncge7n48dyyvuynmxq4z522df8ljqukzmzj3gl4dalyvnjj4jun9ya09nv2zye28hpmsgttgupy2g4q2jud7cnewyss3muz4c87hvr47wkklxlmpqw2dp9m7748f6qq2lg9ravz8uzq8wk4gdqn4l28pdfcv39fr6z5fwccsn8zzg3taaselcsgj9xmcgxuhcpys08qvh43w6z0tam2y4ypzp97nxe0uglnykhqxk5l09fwe5npg3e6k4ayzqpw5p07290ukeydrvczw7qq7ltr9g75mm2zkms7qdpr68cthzvpw0rfnleh4ee3d4yhs3vczg8sa5trgdwc5twdn35am8feyggx0j0vvfcv3haxggfssrrzaxu6hhrzet54aly8e4vzlyvct6c05ke38k53sh4gsx4t3kv9v77pdfvvpnn9f2unk6e9mn3w0mj0rfphpnec4hz2warhj4xsx8kf6658vnalpusehycze9jk58pcc9yqjtz2nc65xaeutk4x4hgsrk9rp0kjxymmdwkw5wx4svsx2j4yj30apw8"],[512,"ngam1dfm37zkqpzc2fan0k0ev5fm05lhrhcw0wrxf3nwzz9zcw3ljtuhdyc6h5ftx6xhhp49pfk7tfy79gt6au80nnua8tnwg6wxee3xyzjtrtv0lt5m97zw9y04zvrzae2cxqzc0czhv9y7g7qmzh6m8prcgjs0t99vmf837ldulg3m2l7u64dgar4u5hvaxx6j678763hufyqxwfv664fa5n5289ywf9jtfxydehwpqxntmeumup9j7csce30j0ar3njxyt0wz2zg5pcqj24s6k7ufnqnnfpwmar0etqwl4ysn0lmqlyjrl6l8rjr7amxhdr6c4rs0hxl290xf4rq6vqx2xjzatqa9mpq7r0htqgl6t28rj9jaskhyh2qx48x8xdv6rkvglfg4htzzjq6hzdu6u5slesu433mdclzzn525pqhc3mv4x0f2zpg59nzatjrdrhynyq2yph8yf6ka8lvq9x5m3ueyh88pv8sspzfqvd94yz7nxcjyk8v2kk2xnalh8mxr58aduzzclguqtp7f8hyc4fuum726ctggwna5d5skjaeacspzeur9relkd78u9h96fc5cdcds2hyykrprn2h387kfpfwpl9rqsd4j0gsqqg4mk04lnuaq35agl3f6hwq2pxw0t063cc3py9089xte3xa54up0ekrtpwj5tksjg82acqjt35n3sz8xud9usy5xk8fcqygjmllfkwkuzn6v2hjy6s6zrwyx53cm2pvelhvk2wtxs4t5rptuzrwr3m8jz4caluu3n7klmxkyv29047qxqnmt00wpnyx046xu7emeldkj88ah6ndyfhnvr2txzqteq2hzvz0ws3jxh9gtjrjgghg6zdknqqlth7lg976vm4pks0wlgyrue6stuww7dpzynejewf34fum66ja6hxdtq0jqeg90nyg3gn9xdt5kwcuglt372fdclfjhpkts7tqsc00z5yvq0y23v7er5p3pl8ur9y909qtv0efpgnh2ez4td6gay9dr95rcekjwsd26wlfzmcxw3wmkfxyezalcqmcnq85qfwt46q7yp67vcyg0vu7mhyh3lug9txadmzs6xhfvyxurcerg5hwcq06r4hajj0gpea896zx73w046zdrltvhymxudy9665gmx0va5m6l4ekxf08lmvuwcgrjk3nxg0f7645fyzwlyh75mtq5cppfgtt5hu7z035al53mvj3vkjwwkyp2j27ve3ps20q5gdd05u8t9tcsrupcwdnw8z39kshp75vu6lkhkxqepmkx7y5fdp28jzaenv682zamq892fa2t3k7yjguk57x2z6d65rl0ylnkxyg3fhetvwper7mvl9e0nttzrnqfc5wjexfu3hyaaxhppfx87a9khe82252g5967fdruwkhq0f4qs9sdhyg5cd3j588tvlhplqs4xgm7rpyuu97sq8m8a79rpp4999lzuy9tjc77unf04al5pt8y0qjltrkmkn06fmn0vxglkazgd60lqkhe706zvrsnfx9298ytmxheyqrd3832f8lkr6j0ctwah3vqkltw5awprkrm57jjjmm9fx0fffmc877p8evj0uwqfjnv3v9gfm9vltq3rnxj3k5s9q03vahnux4nfsglxpzsqpz5rey7fh7jp0njrdmkpj3x2tp9zptakkgu0pgv5ccy6jnjvtfyla5fwfc324lnxf79ycm9968tmqjr0mandveza2nymj69k3tg8nc8dwtd8tcvp5pt9teacejwgaqs2cnf0efucqd5pcv00pfhvkmdf5a8hhqgudgr9u5x8mdac6u53qv6fgvqkm00et8uu6zejcwvxzqdktwkk3me74s24cerxwtyrvntkudnqwrmevw0ksj8j4ltdy0sk4k485ghk2wcjlutup20utgj7dcujrkhyzed6vmpw64ak843v872ea4rka5587apqjlhggdln4f2qczsk0s7zqyfe3lqu4n7cj0wvy9c785k56xgm9farzxfm67t8yfnq2mmvsl5h8d3agt4wttwpwdn0cl40tw69wgl5l5m9a9ps2zqzuku5797ty5c760dxff97p37w7z9qtx37fm4pe0c4y3al8fd98per705lc7t8dnur3cgs5nyy3yverezyc59esmyyeqe47zprhle8vs66ap7rn4m80uwer8smmkmwqe9neqx942csenpxegr0fg6pjzdyqw77fad50v05y3vv3m2d44shg60f4ngrsq5czygxvsureuj02kufy3dzq2qz25u2qkcycuh7c8rttqhcqs8yqsq8lcvwrxa5k6uazms404uuj9cxnulm5v2fpyqwx679zkmquz6q7um3yfct34qmspqjx5jl2scwkqmvj86rtq9cv3ae9wyu9xrlxkx9027r5xs54frfzu7sxw0xgfq8eteyjfhwwjx63057kw7x9zp48fve5tts7ly5pnfvje9tsqdjgv9trd5ftzlrr7fda5sgq0xck728p85yevramn2shqv2l76lapecw2ymx3frvz8sjsrwdhfyru5pk8hky6q8f3clthzuur423qwz0z4gnp3z3shd3rh6e3g6jkx0e52h4h4sjghu5ww9p7f9z0sjfsq5qkxcnudw3kpn93hzdljd59ja8ehcwnr8ml7rs2m4m7ux8p6a9m39rdquftx2kwlsxc8p85wue807kse87v29yy7tnenkrxnmswfx2j33zsuqa03lchv2s27dpmuahtnah3p3cgyw6ry3fj4clurq4etp5ek6sp7t3lgescpyaee7c0p5xrl9lxvg47s4dc89ztjfkwadlsjpp54fpsmzmkpamx27dgusqk7ph05ksegvpz68xqn3vjsaqvzdffmj5l72qy0j0m49fpal4pl3ah7tmk40ec9jtelk7tpzyje7fzy47qslnc8gammr4y5phcvn9e5qz4v93h36h8vurrhdzwkq83jm4wpjx2wjzjddrjf6hgrmkrr02fugv00c947t78jksxpz4fyxg9vu6d3rqs764c2dhu59s3ljhkwvl6r3njtlmy4s4s8k8pk200255rh268f6lhpdt4gv6qhjmlfhmgrewr50rz3f648a8uqn50j5yuusugy04e22tnxkratr324z5fmu9mapjthl9zkew763uzvp999782gpsqdchu6fsj6m93dqw0ag4jxertzv3cq0syuxpatc2z47unp4cmjfdttzkmqeg3eu4v8kysyrrnupc97eafljjp5pzxpakx2dypt5ymur5g9j8hf92jn5km4kquvvpqta7k0sdxtaehkn36j0qrvyjy6suj7zxvex0qvkensguq0tfex0f9ynfedmzmzdc6nagnw7xzhkkrc87w7322kdda0tvum4swsvhsfarsx0dsjansp339rpvapg4xtfqewkfqvcv0j7vq59p7r"],[1024,"ngam17r8cm3neg6cefqnj9gx5tk5v7hmyd8a4epqhjvtrvy8ev9qpacpa8qleae6gdtetyw5j8d4f8a9vclv03ewtmhxc9q2w495fpadnpprxg9gj9jrz8ucwp6n9r68808ypsnh7nx3zxehg6ea5crqhzfevjacmftlfu9l7rqmnze6p2wsxw7dwklg60fa9vte9g3c5sw42hfj75837w8qdx3wvqewext3d5k3k9e7ttdlecl07sap97g3752u6aewaudgwszh8m7n94cqfx0xg24wknsjka7txdp4fyx4eedrerr23jp5q6pl0wcl64f53y7zyp84zc8ap4nqt74j3pwxvzsfmmmc8z7mfs7ca4gkd45z768cx0lndcac6cn4xqa8dgqv5cdh55arghj7s5989c4pdv2ntzm7r04pka9eg375mnypjmgu52a87qa8ecyxljyldtul3cy7y7rk5e8u2xgsd9z88f97arlexyzfdhmzk7xyk20j6gs62zuns4w2u755lyrlc9pd7r9pa5gcd289l58mze53ggu9mav48qsqndkyf7jwtdw0253jwcw74kphd704ruzerpnwf52kr8hxcfmmg3hxjkd955apurhjqfvacwrrh676ucy77kcl09gqk5gpknmadd30c8m9grg2nja2rtcst0epnz8dkznqdwc4gte0urheqxml7wgrgys4eadeq977nnr3f9ypky0dpgqd8gsyv3ktallq4xddkc23yd06hxc04aslkhcljgvahpgh3pl4rxkxt9ztzh5xx4zr569gkfepvepzpzqjmpn3fdplspd0h3yhjm8qf49p4jzs2jqfzrlhh5fhdrapuyg6szzcmrev69kwg9zp4ede9fs39yfpcsh24vezgkzjj0j8kw5yj5gg9tgcl3sttn5s95rsc8z6r2h60nrrgmc4largs8l7q9vme0tafkuw43jq2wvcrkya6ad3e7xlqtktu2hk932ffyl4lnkumlfma5gsa6j3y4f9lrf80xytf3m8k884q25tykz6a9eqc7z70qamzzp84c2tv4cvckeh5wmk09dk4umys00fmsn6tgx3tsa8542nn7txd855sjwa9x0nfz0wsw8s9nlrvpk2telf37e77ez4uq45cxu57e27gcsp54q2cwnu2nmzwdpxrlf0lj4sw2z6auax9y9p803lx093pcqjvejquvt4ssz0aj0xcnd75kxal30pyllm7agvp0vy4nrpucfetspkns6dkn5fk5fj40ahktl2phdq4w5jpkv0n4sywk2kykxht5lglc5g45afvfl0dyv0h3x0f8gdvnmnxe243r0fqaz96979rrd4zy523swrsptushwuj0rul73ecg6e22mzngymfydxevmd4gpf9wvuyax3xcenuqp7eyyshmplwcxkprpsn0ukz6het7puj2ghcxn2skd8z9yaeaym9k0y9wclarn8s3kkyp5kyr42yqg4txjr7wwlh4qcd04shsnfku0e43kfsqt2lzrej4cv3vaq20zpm6mz53jfxrwu4v9vy03awjcxmu0r82sn2leqdqqgrh9agk0hpg2dvas6qzauuytlx8zkp85q4p0nwh8j6rhauntf8w2r5q0fpkksj8wkpumzwxfhsw4d04gvm0w0738sz77kevw9px2kal2yrstnj4l6qepst83xz47fh7th95wnthtecp7lylp8v6sgnwlhpexke7zdc6l0vfhml75hr29qa5sv6rhnfsjkmpelsn4a3rjvcz5jnf8dzsm6uape772mkz039cwsjgt7a524vzxue09nmzs6a87dn8s8ppx2fsfwes5rn6erg57ws5zqlemrqk7v3tlmxw8p80sqw6g8vh9evryfz6dfayu74wet5lelnxh9tu8h0ht4mkmkeq2wwxsds2pdrcdw0sg75nxxuht9d3ltt624jmc9e5rzzcwynyxj2h3qzfl023nn4zfea453szu49ttlmq8z6ehxacm9cyu26kqmnuauyy33uffnfrgmarjktgcnqe9am3w4fejx89ekjydugvn5284g94ha3tn8chapal39dwn0l985n6ht0kltr73h36cekx7mvxqgapkcax3tnu5xfdcgc6vjk8mtaaktmz929ncslgkpktzqjqmvr0fq0684ytf65c0lxm3qwpqma5gy6q398mq5qytfnlvyzmszjnuq3wu62kxtvgxtfjf5mv5z7sgheg36n2hg55f472yt8w5zyct0xsqftpu2vppk73tzyk28afgwnhqe8x8aad9uw63r25azxj4s7g8r8m3un9lc43kjp66f84jh6ejguzrgffksy57a06duzcm89nfngze05xlra50eqsctltgl7vpec9t5kcptf4yl0hqdr698rlwaudhgk8gc3yr2ra4sv7x4gnrn8pjw79lv2qvfhlwe6fn7e240ta8t0hmsl3908ql73xqhlp0ed69u67yyzzn4skqkushg2gp5k9rlnx62pk7n96fq23lsgn8e2r0u8mjdt26glfgwqk0hvas6adnkh4yqhw5carn9c8lem4g56fupq0pp68tlhk2wcltdc4zyxtfceasem7fepn8kkschqrqxjn8hlyvlhfllxg0lqfnutk6ecn44xn8staye6pcnpfpeze8khnmmph2hpxd56kh3g2w87qa9nv2ys2s4myu04l7fz8cwjfsn8ql4v3g4m774wrvg2ygrmvhrdjxpr2sf9g53tklpyqauy435vwqzyrhaxmx82dwe3fkzap2ka5cwcrkapglsjafgvehecdxjf7ac3s29lvyp9pkcqj5rq020vpwhz4t54lyu7ycw4ysgfcdplf9kvf4n8cpytyf9umdwpvltv35qdu6gfsjhwtws2e7xrlqqk2sy34wj5mx3527laqqkx0xsqdfp9hucdw7zjapdvhwpfjay9qjrducys5tmpa6sq3eg4zuedzvfc85e5jfjfwu5n09e7m0yhcp2jtjm96vqwfkz2f5fp35avr5067kpn4ct7huzsd9wcshx499h9cwpvdskwh4pjp6vxq26x3s9tt7a5ezszem6dccen6gadmz93xyhq0xk292hwpgte45s7py25k6mqmd6fgdyfl3sacs5x9x88z6kydpranzhesrs93dy8nqga6lm2wpwyltdecp2hvn89a9cpj2v443vnhfgpvyjd8g7mryqwn00kl8aysg55z8996wpvxwmnpf54pq20rq4d79g2tt4edskkcxuk9h5yznz58y5gwp9x3qgtdxw87ymkgdup8rqn6ee6qnfhk2qkkafqtgagu75zckxzakfms484xz8smjg636t5ksa0w60t00zjw6pm37jn2k4h3rvnxr96ltxfr0uwvz4q4sgttlfw5us5kdpj05uaddc3hy93lq6arm8mx7ggzla"],[2048,"ngam1dudqupafm7ec0lz3fvv8sgt3wl20qy98h6pv0awjkcut69h4spmewvg6dnp6wp7up67leqnpj2eyke0mzrq2uqcj3ha38dkx8j2yw3628zst768sq5vds25lzvc8fcdqq0xxmk74kg0f3rnjcrevlwa3aagr5gf8vc5w0qqtx4e75tkyn739wwxqyrfuzxydea0et44gxar0tfllfjdyyj0wrv0uw0may90kx9nn6zhvhmmqsf4x62ja2355xx44lmhksyy20dd4tsw2fplsdsmsg7y89qagkzhv375daswwgy7q455dhtcftmtln9xhk9t6ra04un6ac8j2v9d8755pt8wmv5pj5kn65dlqtrytymrksdfwkqcsv6utk0rw98939n92qx09qs9gv76uryvfy9mepp4p6sztzjurpktgqtmxqgwh03p6duuxx2v9le868pkw33w0nv62gad0pkenl9nn9vh8ft7n86fkq8rcl6m687k6m25tfe2srtkllyg76u3jv0zyve7h07mhjxlry6jxm843zeaqzxdncxqmzunq8y4ledrhtcnmfnxzj50vdfmzhuht3p95vjmyrwnvppqyz28m4xxngt7vy6eyh6ws5863faa3s9c8dm63pkp658ad3vl9awn3evk6yp85jd9gcnaz792d2qv9mja4v90dxzh2nmw5nxkakgnyz8l0wx50llpvkpggdnvqykj36dh839n7ltf9z9nq3atfz7we95a2sejg45vw35c5jdkafulhd8dpm3qpwt3xa8cc6e9vjg7zarltntvruwndpvlels5gzpu6t7dxfjv9c2muhrn6xu6th765dd0m40n0hm3q84r30fu9al7925rjrujw0sjjs62nc2572r6xxruvpym5ruy5j3zw9wawl328zk8smktvpfecj6mauy0fwsyckjdzwkwwrd4xgx2hwy7x2rq2c0jyunqsqluysxs0hww4xq99rys28a48qg6h69ykf4jth9mte27cfsfw6hm325ekasakha4zakr7lqhmqktwlgwgnuqhpkn9l843xsj5sx7aacm2fcs3f5ukr6rj59nnsj982a93y9e9hcvtgq77zd7w2l6lxgn0s9vnat99xyjyq8ww8ey5a75wy6rttcytdd7us6qvytha6q7d3ccd4rxgduhuzyjuzte3mhm9qed0pqn3ctch5ul6h2g6ftslujn3dl07m5swjn6ru2tck4d832dnxencqwgv82h6gmnxz3ftldvfkqs34ganj2pqy2pfjepntxafddjg2kxkrqtmfzvhxr4dag0anfnale52aejtfzuqmyatwedlhepg6ea27kxvygflqf7t06rmljvmamlmewk0rd9luykdrp755v7dvdy599gh4zqml89qz3e0hm7xw9uxwkk2qunsmgptfdkqlxth6c3v8422cw6zg6hl9hejhlc6cgnfhm63fjn5kkhejyhcznsjc6p8qdnj2vpejm8du9p2kes9xkegn78akp4zyflp9nmcuztesw39gqfeuq3xtrna30gmuhpeka09kuk8v64dvmrqkhr0k6ar03qx5ezldtga5sjfpnzmuexsr3zk6k6vu2ergn800jyjetan3uycdrwjngjsnd4hha3p73zz90up79yhmz34gfarel6rkyl7td7gxh9u2v39tsumdgv4n4r3yf4tjpj76ux3qjfdrmzecj8hpm3j53lvaj92ng8kgk3dqq9atqwdfkwpw74k5z0s05z7ccd29ete5hudy9w0e9vfcy40g0gjdtwkqfdhxrw6vekha7cjms5yla2qjwz0umrh5efggwydlh08cfc3pms4t5f93ydznp97p95mmw0j2vxdce9sxr08rzjacr2h7s6k6zc32sr34pmj28vkt03k8uh28m8jlr7px9ltu5xrlupqjcsmu575wrt28dh3m62vz9mrt0rukm8pcxagyhmslqv6a9d4mlg7z6he0grhqkjj25jk2dv0rpwljper0yzc8m5ffw8a3f8y8g25v0ryqepzasqjct2mq9c8fnzgdq7h5gplv4p9nezneespwa8z8k7ut90mcgsck5assr6tp8fuhwd6t79mlqurzlmcckr2f4lsdhhj7dr9knf8zm07zwg304lakca8e89r7uc8sragnu79ccj2cn8fyfvwmndjsrdch8q6te6n9kmw5frkhu046kjsm06mq6et5wp09zyxcx0ue36ukf3s3xn3d8km698fg5gcxzdz8ztft8snhtav8psrd7fpvskpee4lydhmpe42f90rvlecverrd3eaan9mljh3gc5mpw0gqmntpqdxuk6w70nfllymc4xw8pzvx0nrljyv48vxx82s4337gtqx7jkrv3x7k0uq52l566kxf0a0u4eugrwd4t04dqdsapehr255gdm7u7cyaer5jvylwvrqshgyck3hj74wuzt5eczmmq9ycqlnrez53nzxsvf5q0k7dyrxeuy0k8gkhcnhy42780z0nqre4g6qawwjrk8p48m32ef0kwyfcu00qeutzvggu62w6wzyrdwp9tduzyg4fw5vues9jelvw5mrtprvx04dxegq4hyakznm6q3uk5jd5qz2fkpt5sc825t7zgx70u4cuyhwwgr8tw4fxwl5uqhwau4k22h9ath7mjgjku5v5jhfvddu9uaj0elfkp5laxsgnn4m4k24da5yk3tfr4xa98t4xcmgdjqsskhcvdcec7jl8sl8q9rjpg4leju4z3qqjfuuz08h4lrgfycv5mt2rjyqyyr4m3cgvdda67z4jlugwd8mhy3d30am3k6xpyvpp55vwp40jtyykl75dgzecjtvpug9al59sylls803qvtxqml8egwnvxkks4tpe6f6wptccmcvyqqc8es88f3sauwjlv8szv3nmkauhyau4sa377pzu2vy5klc7fd3u27qktrut0jhq8avvu4g6glgm70dzrat78n987l9kxeu8ty96zhqkzk493dt4l007yezalxvkltc9m0rq8qz66sv8tuhy5szwrvzfpzlx5z876jxee5pjx5n46er53pylg4mrx8unfnpqrp35dd2f6jmq5tvh9hp6fnclqekfyhwtep9urc2e8flz4d2dtvlc3p3qxtx6plz7hc3uksac8sr9u04t2qjl0ayg3he3xan4ara68296yf79gzykhrvm393n4jvvmugrdj7dnfz375mjfleg68fzwvjxnzm5sfv43v7vl8jvlw6dxusn3ke8j33jpy7hqh80sd0l0a80u2zjvcx8u06u8f4d3qv0ta94qdymv98kxcfu6pdndza92yw8qy8vsppdw5vg35xm62qnn6pspwfhkc2nuz0slv9fpnzl2vzyut90j432vy3y2zpgjfl4yjjxk2ueszh3xcjw7jph8cs0cnkj57ulps"],[4096,"ngam1mhzsndlsj7p2lkkpz2zccutxxcql6lpc59ksd4f45twk7xm4md9hc0lcacs9rznhqg77c04qwhqm2ufq5r7hnsw2psrge72fl7ahxtugyp4eqza2640vse5n8d5agtvcz7pqm2mhsy74yrepmtjl8qnyvu67387u3gvthvw57r4f9aeapqz8wmr5a30jugwez3xgw0g69l4syqwaxqfvnlr66xxp0yf0dav2gtpej85pnrye3m3j8cvc9z7v7mxfjfalk9r6z3qpndc8jszulk3zh47t7gaxj7kaz4qk5jnh6qxeuzcucd5cz44pe4uytzrumgvj20u88maal9lw7p3emcz9wmxq7duhyzhy8apuhwkdy8ark4z9ucryr0ezp5jdclrc3cr66va3lz734dyct7ystvg53glt6n34pznd7shzsz087erdyw9v0m58tkw3gtr53qqk5fmwde5daphw67n9gaen8v5w2wdm8cwumtlhrnz6jv6t5mdlhgqe63urjn6a7f53kaun8s9hvvssuu47es6ed2c79dh9vvwsrv8vqrxxaccktzsearvpllk09qm9v27wn4tvwzjmn3hte295a9xds7elqgl5vweurhs6hsd82xde8jpnq8rag4es7v6h6yyvhtx2etye0776xxz8rehj7gtg04g9gtvw7zx5zxn9glrp2dcwj2w4esw2p9t6ucu8qm40srtcgnl530yrc94u3gnpulckdgynv69drwwclsmgavg5tjxf5wghnzy855rt7efs8p5nc4kuey2vf9f24h6lhc06dwjghnqeq0nj2sdx7vcftlesqmnhcxdvdz2nekeamuxchxgwzqt2hcaj5h7yme70jsjwrpmkjdfrmmwl6hx28ksaw6z7cmx4c4u7asn3mqhcnaaerad58sps8r7j6mafr5c4s559mwwy28nxxjfxn6v5uu62ts722rkldnvhghkl9fuh2g2e8k24reh9d37yhdmxhnf2vgeuf4afjqts7daqck76hthc0uusv9urcsx7e9gfyf7nrmezr4qvr2agjgg55drjqsl5e8afj3r5vsvumc7e2xd6n7e8l6whujlltte408zfwcmm62d8ezczlzljw9vkx5306t05a926xx9kq20d7q7u6pytjl3620tcnu37308vsnr5hpxd9uwmrqmxdnt2amwehjd72n7prlwp269jke60hyv3kkqpgqgpl083k2kq52qyqsee75d7l4kmcgws3zu2f2l5ckjtcdl4t62sna8lnmfrpgrteqgq4ylf9exmx25rl668p24xwaa8069h0s3uetkj8rzqlaumpmer5n5xg8prtttesfkadfcwq3gdp8n9yqtcualad5lvhevv5kvt9jv7flfhtzwqnjwepz4l3zksrt3z08aq8ahnu84rge9v7ee8eh9lpu0qvez5s49qvv8d7elmt4t72s3ydlems4mjf7zzrwz8ua90ygfpmq0y9usnsys20nlzre3q7rqzde4yg8jyq8pjrm97f9y8ljtvt9c3qku3nf47p4p5l9zyhxwqut6r2msekdjy94g0zezl4ydy79hgwuza27r7krrjrduvcm5hljtur9v98wql4td00wzvrjjlz7n920sewqw5yfrhkdcdzhll3k3lz7r0c7zlpt2rp9klg7fjp0vhmceys6p3h46fk39pqrhy78ydtrm05lsc5lv0p7hdan59vqqtynx90fsmgzk0acqrjrjs2fdnmzerul23ynk2zekragsq7rl9tklnntkfd44dm2czvp7y6ccqptnyy5wlcf92u8juyw742nwet9un7gtz48swcvpp92yvqyg2msfeyp8v5rx6uzce9g39nqtalgwhzay4azhmmya3z3t660ctkeyklcnz9saylmt9ul3xx2km8hk57v2v6xdwp6ha905hq298y6ug9lyc08vnxp54fc2k9hrptchu8w87gqxxr7w56zqtt3euz39dex5mrdjv755r9atsev8gsmkxqefyjvran749ldqe9k7gaqcjg9997f44la3g9wp34zlzcs7fnz5geze9qxnl9e4lhpdl5sqqwr7da4p6f4hp7cmdrmagrgwftasgxjpa0esq8c4rexx3udqppw8xt8dklgpktpnxp3tjqrg3ngzlu9lj0qsd999zdd0f0ef3jyuxx7pkegdls5snl2sh3qkajepffjy3zlwalpalcmw8k0g80w96d2kqxv3kkfq67furzhkwtdszn4nu8kgwzd794jrhahkmg6mlvaprrwa60ldadrvg9rgeknttd5ftdqvfuhc8pdfuruujn422rqm5s3mcecf9d8n0mjs6e3puexwf5vd7pcr7h4m5sna9h3tmw4e02ru77j0qywtvurggpevrr7dkpq9563ukut8m02smfzgqh3y0mdalzl8gxuu87ja3a786zenqcadrpc90g8vqqmxact4cpqh9v3lnnrsg8a2277pc0e438mfeva8y99pwpg794267a22jj5xd3egygxdaxw78gam9235tuj65u4fa5gvvdugsg6lnkpwxfdgkd36q3nwrggwexrhu8t7xrt408dm5xys77fe3gyeyuvv6w7jgcvwkznmvdsu77lxvjw5kq4hqhvf5yf2wjpttc4mzknw9lzq69yjhu4fz4c9fcxw7fpufle5udefhw04s9qq7n6fkmj7g5r3smwgg0rp508lz924qfqz2nkhszwshgy5z3qajltz89vunwhreu8hcjpy9hyazzwe4r7fd3jxtywkqvjn63rutnh5gxqqysap5faq35k99mezp72g5qwayjv36qnccangc05ugaychh3vkfzrv0edfpjl40egpuux88gtw6ssj8nny9jv4cqraah5ah3qyyy8qdxdlytx50r8nvsx4mwsyy9558zp497vzj4s5dpcufs7ys07njcvzeeckxe7acwcu4vqyu6e3ts7np9trel8taf08q9efyw93c5w32kt6r9du4ml7cpy2cxskzc5lz4gh87vn2hvlx296p5yavxyg0vhruuhwynw5rd2tk5sy0jmcveysafx9ysqpucwdu7vxa7ddptxa76c57l9z83e08smq95ky6h3vd8jhfnknp6qq6qudpf5j7gkfhlstzvsj88ju2zk8vjwrsrc94eh6ye45lw0wzweqltcaaducs4vnc8cylen79jhc4fel6wqtgp5uajq22f3fq966hdwjtyxts27apx35c45xuyw0zvjudgygqak3snr4nkvnxtat2yguvqx3e42k8dhn2ap6evr9eqjmre6sn4gwhd8nxcvxudkjg44pkufx05hh9hevfrlfcng06gjh6demg0z47aaspjfncds33n9uqwk5jk9jegppj4c64vccew8fhlxcd368s866pkgcs99ag2zdvjn45j9nhx8"],[32767,"ngam12fp5zup2m927an7mknjzx7mu5hwznndv7nq2jylt4ktfhfwq7ttfxyhamd9v7xaqgze2clxmyhlupw9hsw533vet2a5hwhs9d5nru2z2rj33d8cs0eqrgdzclk9f9wfxwz94md0a9qj3tv83a42hdljct7uk45x7lqccwp4wexr59jnfwra93wfls3gsvnnu8xtj708acnwrrlzv7v4jfettum6l094atd7emsxftjkyxtz4v9ymet42r5auscu37d632u4rjsm00g8vayspjuz933laya3mgeg3cvmaudme5z2ufqgmf0u0ymuqtejcfck2jkq0955lcwgfkn7f228xt8dm9vz0hcq6al50ksuswds7y86mynm2h6dqn5hppm47tkeu6zy2nauuh9u2ql64y5lstet8pv4x2jkws9956kh7x22dtuecvv6y6fxh3u5ru6vyk42gwhdm5j7kjy2xxefklw9l38hj27qlykn2y8aj58egfc8dqf72fdjnnp4hrsqflsje7pwjrmwmsk65z4h6nceajf2z4nmuft9ttk7mquxlnr04l0tqzhpwnzn4k5a750z0r7t94tjfajxt64f9un9v6xm5gzkegv3gvmclexgzt7u8s07vl07gcv4c7v2rv3g5h2xqxt55cqau5smshf7cevex0egv0vp3z9zavf8rve6pq2sugaavzc8qxn0vvtpry3dteh77sslh4nkzsrdec6wgfrx8frjj5g75xv8efvq95a3nufkk233225jfw4549mev4uceyn80fs0wm9qgjh2uxd5rvmymzkum93gpjav497sg4uche8jks5cn0cj3j6q4rej40ulrq8mn6sye538ke4stpk92a4k0zu6g4hytc88dtmmqy0pls87ayhtedlyc4n5gz8f5vs2pflnqlnlu9jyv6fw3a4v8mznycwck7s3d0s2cskvttlclvlrlmghfjzzmc8zgg2t935jkt9fweequlm0za4kdv44nsh84hxuxtfv692c9sswxwdx57puf28nff2uapxmymwprs5l369u3y8s6v0wsh48rfh7nrzplr74j38vz0cy82pvgq5ewn08hqn7d3c88fww9p8pjcl6p60ufc60yw9vap7w5awl5nx5fru27p5e8qxdeyl44t3y90evhfffx9njtgn26vsyldjdw2dchs3qevqcsgx0nmpt4y3xdw7vldzz73x74ddm7e6d44v2dwczwkdztthxa7857pjjycl6502y3jfx5l4vyznp9kq030n33nzzsf0ygj4h2n9du44zqaku88g95ndkandj24k3d23dpgv4fx3qc2m5nfr0fz9l6jup7dpe0llhfr34jr9tj9waveke34wwhld7z9czpx7tljry50rjtvmq2h4haeklpxnafsmu8a6d69qnjqfdajptffs63j332lnlmu48zvp5tf4tc4nxdk8m9ex23n23suga6mf4afslp6d0a6cpmztnp9udh9jemfztjya6g2nvzfx3zs76u5du3wnqw793v2kque02xk8hnzmng5qmh4syfpjpy0r2kvcunzusx5upm79wweqm67xx95frqvkh2f7dke8a226na66ljpx0stlyya3vlntzyl6wvhl5eqnzml398807jt4pxf3tjqe0amjy5yclh7wwtgnlt8ffmm9kwshjh0ccf6eavlvn8wkykenxnpf2zxgr0z2met2n89parnzhj3zww5xxalm27em5scxeydak4xmh6tf5eqha87s3mgff74cwmn0cr9fdaahy4w37nuk74snn3xxldqq9m9afg5eqa8mfeuqyqg029asjxrz4pv9xgc6wg793m5l3qxlcq53tdghf33nff6wq72dw83td45qsj70k6syky5tcq405a75kvtgsvmhm6tg9ghlw7rquy8jtac7qazmpppp8vwdgztz5pgk28ekazg6lnvv3kkdhp9m6qz37w2nzlz84lgkfsyg5pzd37su4xyte9lqu630gvvmpkq3wuta0hrcmzgegkr4uglulhsmpmad93vsdp66a4vsy3l3d24w5k9secxpnfytrxmduwlkyngnja6t67rj2cqaw66f6hyvlpwa2fjfyhlchcdyvq9eunrkc8tswma5rh2s53xc9gav2dutptv6yjadngt36eamxvxe9mpg4w5rphg0hql4akvlm0dateyhf0mt6agj2476e7gffld2t0jx8uurynw627uj5lzpwesp64jqmtw7ql9hx8jr2fwfzn6p3s55hcwtskvx9azfk83j84rxl2qnxk85pla03wyastmxsxpuncsqkj5fqhuamh0azy4sfxny263hw7tlx3eea9q0fk039m7l0s029yesa09mfyrxwgvtreh5hafyjslsm3t5xwn0tuqrp02mqppwd46twx4zzk3hygtwld2kfvjf38g7jycejlhv80cka0njpuk4djq6xehgmtw6469fnpkmkajnma9plu72rpkh2whhxfla4gtpqygsmaym9lym6lf8h6tg8radlg02wm3mqw6jwp6re5x46z0wp9nwgj46mr5u7tr3cr3klwc9wauuagnfcxjeumxd6hg2hc847sf0c27vtjj0md0a3qxs3ltr749pxkzxjs5q34x59m88z8wx8vgpmw0kjzk34esn57a3c7yz4k4ducdkvphj0whnq0nlplculcjcnk0jpcp79fz70rs5sg46fedwy0ff4jth3zngd3egcneek2h5uvjfrtvr3a6mguwp9qftdmq62xcs5me63h98dl28206wfpy4qyfgu6yspxap0ca38yfp0uxmnc362ygp5yk7ygmz0x4n2r9ld96y7y9gcxzvunmn3h2rvjeh8t8ndte42egrreccyct3ufcj2wzc2w3fteu3w9heekm4lrqcummwt8khz95rk2hcs35aer2lwceqeq6j9vzdvwavyjparnz7wsjn4uh2mel6780f4lj8hzzhkzrlq84skr4cv8vjn2c2uy0ung6g2gl72gv38xet69p2gjtl8ahkw5gxvxcy4ssg2ky3r3p03zl60lk4y8pn57ta3g46xkyjqrazv9dnz6j5mtas2nzyrasm2ksdnxudk5seny8jhzrgzpv7jfnkpvxzskkc8wqynaqmldfwt6hwcm4rsjm0d7fyt5u7uhlz0zczkjwystcqqehkt9cf0sd65stxhy6f9a6t2yq5kq9ch97s5dghytg284nelwaem8lvwa6n9wwkdgznfygll5csdqzppf28g8x6zmr62x5relyflpa5xh2sq2jd6ejvh4z3p4vfl54xhm0yx4jtjl2gvmf8n0eqkh697hc8guvzytyc0y55j8dyy87sss9qhzu6rkw60pv6u5h6urg5njgnqerw726ay2sghq6zl58zej47gmyqg73e85gdpq7rd3ayj"],[65535,"ngam1kzxf88hc6fz9z9t29q4mqau07jgvhay46ksumld5rpdjevyjlq9yqwy0v2nrure6j90g7h5s6gkpzmkmk37qhd328kx82vpcqxu2lwjsx36e4hs2szqy23ftydl84na44qc2t7u74mde8w2cpnk4ykpjdrwrqd6kfd5v444rkl7auf84fvnwyh7yaanukpphn9psa703lsukd0t5gdandp2kym0s54emwg79hhahw8mhsktus64fjfz90jhs4k98w4yvgk4f7qanw6epg6xyx8e7gmjrus3rje5gac037g2w0fh053qysgjnhv268v0qt2a72t8ntm83yyutmh7z87supmerlv5cju82rj306ek2qsp3n59phn8hq349sy90vjkl0cxg2ngec22tzzm36zqyfm2p5dwgmjljcevktsngw3rctx9e2ass9vjg9nx0wxd2v5xatqt8gaggsqxkhuzcj2t9gag2wzg8j29la32eguypfv5jx2myfmesp25lxyfh3tdr57s9akf5xg0vxnnu0nunkatjsraut6ccm04fe4fuv6mm8ya39ccy54fu2wxcvmz9tgmgytwct3rlvkypu7w0lczea5cnjt9kv50478lc9838t7sf83chur3ygw8gz3reacjemlcjwdn7x4sz487mq2plm59e9wwzw8dclqs64x7sj3377ap9slw6tv4a2gh0s4jcgvpgj4vnxnh4l6cfwgrm5mpkj8hexrqrsjyfthgnsshh77fwvngdzae8m9fm6lf5jdga720sqlqwp3uj2mkjqawdkuezycrnhrac5hvu67vy9myk6p4fp6lj7mspz2zxvcm5wwjnnvhmx2wl83jkmdwkn5mvhat24hfpm0zys26qy0wzqwpzvsdz8ud37f4xt3dywt92acrsh9fm2w20cv6lg6fjwpesy45ztc9sx3wrcu8qpg0mw68vw3dd5kfrz58urx9q79efnkg2wu530jgjj0yajc3urzcr785eq7k579yf4fmv4prs9ckrx90ktr78vdnul6nddzzq9p7glh6s3hs5yp3p2u767ne0dfxqw055l7uzt3ad8wa3mlzdws5p7qk32gtefluxuvknhd78hfzk28rtk60m3jjrynaadwnykkxmd8mqdsu7x6gq3n3tc7rg9ethm30uqdudav92frpmm9trnfd6ltt4wh45gymswrcqk9xz8hm56uz2ncsmy3m66j2hyge4s0ytch9ghfjm069gyf527cdulnyursnruys3s7rfax6tp4lmpfctu8n5u8l75vg050cdghc2a9fe849983d059j5p8ulr4wvhhq30eactfn3dhsp9ju0p4ngkdrm6ugt7r470ld8vs0w09mjr5ppanjav0tpu5x0he0h44w25fjnquuu3pjd9smcwsauge3ym58glf57htvmzra248jefgj3teg4mvgf2w8ehg2nqkulcjkpwscqd4qh9y4xcs5gdkt3p702uq8gd227p7snj5w8ll750nua6ph2vw486awlzl84wmp2gxtz98zaal8pvgypaewm76fl7j0fse7w2vjdtt8xax4yhc98ve0ds05hezuu0jt65nqhfgsuutd3uurks0xl7mmv2xrm8ms89xs3yttvv5wm0ralnjfn70snsrcjw7frrua3fy5st2q985cdru2rws5nvvtsdtakvwwwm3kdlfvd7pmqel7pcsu9787tkdzpaa079ns8gxrtpp7ewsgm2n0y4sz99ukrqmmjhug7q4zwk94hff7azq5l2ru48etu7qa9cv28sg2kw6mkaxxg6kx640u4ns4xg5dllzyl6j0a6ushxfylh6pz4u68vquzx59wm36a5hm66ur3ld6tntq9qmv6rukejuusu8ct70706lnd7s5ct6jwnszcsnxvu7gxg50zju7kmqy8mh6q2tv7ezvyqheem00ps670s7j4p5wmkgp2m0unlenlvpc5x2ka825j5u5cpk5hgmtyeqjhuek8n4ugmrdpk2hwvc6cr7n9mrnwj2k484m622gh6uwqkkewvy726rcujuecls7esekknmql85dfq76k9nwlwrsqy7qvl5q0nrf5cz53pqnz08tfw7jjp722p73fhdekp6ehgur6h2ttvpw3z3nmvlzkaq65wcd05cpmgkgpd7us2ymy2jacuwhl0mwptgkq24757s53v9gj9csylxx5tvzr8n44knyef905k9cu6zcj2vncyjfw9ukvej5xlxf6mzx4aw8570qdz4ww0sjpz2m8nyjf4wf6mt3vh90pqs3pyqzfsx42hwcwmgnj9sz20qmlrm96p9utlpsxm9jvlmn96lzrhatq0l3qw2l84j4sur9rlywufrzc0chhf2qnc3r4axwne0tsg7rm9zq45kw5qx3kj68cx6klmap0s0mndlauuzywp0q8g5y0n6l80s5zxm4ja28hugsdyvx322gmnve04pkrlh5x688qm5za6583hlu5hrw65jg4r2js2f4wk4ypf4qsu7sqkphrdu65v6gks78nmqfwnd0npww47sjfkda6kgv0jvktzul457njjlcvm9htdukqust5dv9v9mstq0hkkgtt7eypc26faunydv6l8735equ25qy4wvp7t9y0zz8kulh7qsww2u28hwmhm56yp8qnkv6qdesfl47ltm30g62wl664l2644mqk6gvjcpuegjkpd97sf55sfg25hdl77x6tgfhwegamte6uq46q9sjx9vvy0sk48gy0wgw9t2ghhj7wanyj33uecr6xs48ktdv4n33hufg58mmelmlchcwl02aslla2zde8le7acs09tuqv7tktacky8skskjt0nnnr2jw0lnlhchw32q3ng73ee38rr8uqf5wtfjj49nzgfa206le266ssckn0eqwqr49pdnl0ezswtx3ud6erhmk33ztewpkc6c76m4u6yuc4nc9wgaeqksumm9y852pjdxlft90zkr9nemnt4krnsfl2tz95uljpmggp8q57jexmjz9gerkgxz4zp0ntzypr8hwktw3e8ulnh63l2dvmk7z3cy97txm28vwj8dlj62exdnzy8e4gk4xvznycy8m08y82a5r72nrfsptxj53gyhldvdxnkez29nymkwkhxxfnlg08esx2l044m248s0sdvh43phgqhlpccw3cpu2mdthtspeg24h95lyprp6hs55s2epw5ct5jra64vs2vkq8ndtc3a9knkc3whcd0v2chjlzu28xncskrd5mlqnxdjf3r8fru9vffdlg0hjt0mdyyvj7rfytcmdf8fappuuptwq9rkq2m308j324g4jlsln0mnhyw46a900a325zadharagtz8l7tzjanjy6eqx7dguhygw4fcu2avt4mv2jehh6g4whdguwyhdyt5h5422x0ptag3gfsvc"]]
"#
            }
            

            // returns a vec of hard-coded keys that were generated from alphanet branch.
            pub fn known_keys() -> Vec<(u16, generation_address::SpendingKey)> {
                serde_json::from_str(json_serialized_known_keys()).unwrap()
            }

            // returns a json-serialized string of generation spending keys generated from alphanet branch.
            pub fn json_serialized_known_keys() -> &'static str {
                r#"
[[0,{"receiver_identifier":10576993799895858553,"decryption_key":{"key":[50,84,61,14,252,219,1,201,95,28,182,16,206,196,169,103,70,60,1,202,207,221,156,220,152,146,73,82,143,32,20,89],"seed":[211,163,114,203,180,37,192,71,42,253,26,208,200,116,68,30,122,12,71,163,48,249,213,191,32,231,109,231,235,127,86,175]},"privacy_preimage":[16795418181461047688,2042300718102878220,2358965452025637505,11067020587686366118,966566326869813794],"unlock_key":[5319407098438986504,10434853369100656863,12828564501489937167,10242609535688029295,467399092569670925],"seed":[18245100099979309961,5513579555997432734,810208476808634309,14319363662701114526,14996260779308684742]}],[1,{"receiver_identifier":16267587508061839327,"decryption_key":{"key":[221,42,95,47,28,140,22,155,198,105,49,250,141,216,55,63,121,98,74,89,203,198,239,214,23,159,243,56,20,141,110,28],"seed":[84,189,175,173,119,56,23,176,144,93,104,177,132,181,99,17,202,123,209,188,166,116,41,65,216,240,30,223,8,70,217,180]},"privacy_preimage":[12012400913257883951,10548310109664908911,2963314380582273919,16633145483206294495,6797528064765341185],"unlock_key":[8612364370396931335,14085781343128185969,663197062531780382,7451413459312806834,6771585555068972636],"seed":[15126687239383492287,8019146490536485036,8223351759230227081,8725444215773842436,10526851446909770211]}],[2,{"receiver_identifier":7833112903642552597,"decryption_key":{"key":[205,177,149,49,198,164,240,111,188,100,162,7,14,53,212,171,88,70,92,208,19,173,223,200,143,4,150,24,115,181,0,52],"seed":[37,229,216,233,187,155,103,186,154,165,43,66,93,73,221,169,214,253,108,144,211,166,9,74,232,194,227,103,190,62,86,248]},"privacy_preimage":[12636266354395813952,6795459629652061821,11951971530784802368,16761359162059540098,2093822759577978597],"unlock_key":[13822839371167458216,17545086086042197446,7943302321688915439,11837258559337631163,17262494671434431978],"seed":[17881852939879229136,2707890201164669829,1904350420031677290,14995036319809399009,15471985421484316330]}],[3,{"receiver_identifier":15776432904464356255,"decryption_key":{"key":[146,155,38,165,197,141,16,111,115,121,102,123,107,83,194,244,213,185,141,117,31,169,248,156,212,9,30,164,230,156,56,1],"seed":[118,79,230,30,76,135,58,54,45,184,200,8,193,155,229,59,173,103,189,205,42,166,138,145,48,183,199,168,93,172,195,144]},"privacy_preimage":[7142370373175902299,10478558198407284074,453149336085382928,15069265578532892518,6538626804545590646],"unlock_key":[2565226146705963760,739785114577857590,8191843855821576984,10220076441036491327,11951283057753763573],"seed":[16365141421571154358,16739523083863846774,14519628374603285428,2633200027327371259,6338082107576141573]}],[8,{"receiver_identifier":13799357822171571776,"decryption_key":{"key":[113,164,178,21,15,138,78,94,21,155,67,184,109,182,187,0,248,52,157,27,160,49,25,57,227,84,184,191,18,45,100,103],"seed":[134,126,177,24,210,228,93,242,49,43,50,142,70,181,180,147,9,95,67,47,80,62,173,142,103,142,60,16,218,217,136,179]},"privacy_preimage":[1211189101788949831,14022139824036773145,14588843039554285691,11737738447579755474,12051850702479454512],"unlock_key":[13962909192869898153,6154664764355016643,5111230136029544360,3100394728782510680,5670437138942626147],"seed":[4900202021826691917,6430296459617804614,18112253639217185544,14605183411743439294,13362417657446608230]}],[16,{"receiver_identifier":8901877516113149416,"decryption_key":{"key":[249,13,57,162,219,179,53,224,78,31,151,88,215,196,202,239,15,245,123,193,2,198,253,142,17,140,140,164,156,75,103,231],"seed":[248,139,43,136,157,148,43,193,54,248,130,17,177,30,158,158,147,25,53,125,141,252,210,52,201,31,0,234,117,170,93,149]},"privacy_preimage":[4410469100546677501,181986858756898395,313349172280412832,14407506431337293818,7289955184802339281],"unlock_key":[657795657830544825,8726506016622999355,10663849937586502137,2899042586860121411,15323767660781612722],"seed":[12408986393586040173,2262136108628180099,14648512199123485643,6390239231076555541,6107701980857071779]}],[256,{"receiver_identifier":2854736736991044552,"decryption_key":{"key":[106,112,200,104,248,88,2,42,230,234,167,61,176,74,208,237,31,197,64,246,87,24,116,53,249,83,205,177,185,180,224,151],"seed":[100,208,1,13,87,102,7,225,226,38,138,252,119,25,229,248,57,37,22,115,6,7,9,20,105,10,45,106,196,129,54,111]},"privacy_preimage":[15525367749930777534,1611630157349764180,18299006058837903546,10236742480471074295,6479967956090294316],"unlock_key":[398311634495695003,11646770901963319949,1690519225691010400,18362809574155191419,9812496023110371113],"seed":[17328256301400162901,17454239965910013971,5229731850412362318,10778380358977004205,13933306870795378736]}],[512,{"receiver_identifier":11866994639017834346,"decryption_key":{"key":[210,28,238,8,115,22,67,197,143,164,74,211,1,89,187,211,113,55,110,224,246,170,202,13,73,131,58,105,32,31,155,107],"seed":[246,111,179,242,202,39,111,167,238,59,225,207,112,204,152,205,194,17,69,135,71,242,95,46,210,99,87,162,86,109,26,247]},"privacy_preimage":[1921906233219744435,2022996711385058371,6049802618873634135,18031319823291940717,3751769971045975951],"unlock_key":[15379964702280686255,17130902097341956627,9194945071806795896,9209245193534184429,6146501360572624023],"seed":[5411949849571388503,3933627778202969831,1677874679712150628,4527096618432776838,9248341545621860898]}],[1024,{"receiver_identifier":10714422477327290352,"decryption_key":{"key":[164,137,112,124,19,167,147,154,233,205,13,92,36,228,68,223,103,130,5,224,81,91,249,26,240,34,136,206,228,140,184,203],"seed":[130,114,42,13,69,218,140,245,246,70,159,181,200,65,121,49,99,97,15,150,20,1,238,3,211,131,249,238,116,134,175,43]},"privacy_preimage":[18189402096902941599,71992625835842794,17757084404008821620,7360885489820787407,9789878880186355935],"unlock_key":[7761717159124621319,10450451047469115766,5439744463440127330,11603782470063549651,11449303707392090862],"seed":[2365345052295347648,11603532765052176484,12017388687019582218,7396594250725652905,12472000517732774903]}],[2048,{"receiver_identifier":9778405133012310639,"decryption_key":{"key":[185,216,219,89,245,23,34,12,109,45,245,61,218,143,59,194,11,206,195,18,243,197,217,82,237,142,128,39,12,121,240,210],"seed":[252,81,75,24,120,33,113,119,212,240,16,167,190,130,199,245,210,182,56,189,22,245,128,119,151,49,26,108,195,167,7,220]},"privacy_preimage":[4507137114898943697,6894865929521777954,13623915892458480730,2088200250760272806,18094849808921970387],"unlock_key":[17568846720529969795,3149017798966663108,12947958625577379238,16475072688526441511,10919155714744419963],"seed":[5616784980898013400,727402852798064337,13218659095231836505,5884708954424272806,12825087792086011600]}],[4096,{"receiver_identifier":12646837763728590301,"decryption_key":{"key":[128,235,244,86,68,135,164,205,45,122,184,140,96,98,123,122,136,234,2,14,218,248,118,128,44,71,182,241,192,199,102,198],"seed":[218,193,18,133,140,113,102,54,1,253,124,56,161,109,6,213,53,162,221,111,27,117,219,75,124,63,248,238,32,81,138,119]},"privacy_preimage":[1628255660603322229,234658259861046870,17371460607231334642,4136818626735410950,12254185450524252601],"unlock_key":[14580403393172134085,14474886613845245105,14010859594126589443,8851060269544255422,9149345050368262409],"seed":[18043819257415475138,9817725016321726136,17086808148734636559,3586079176466245497,8098838825687683246]}],[32767,{"receiver_identifier":17173871530342433618,"decryption_key":{"key":[183,45,8,173,176,253,179,90,151,218,31,121,26,121,49,186,248,82,173,119,141,38,155,53,147,45,206,139,170,72,217,31],"seed":[207,219,180,228,35,123,124,165,220,41,205,172,244,192,169,19,235,173,150,155,165,192,242,214,147,18,253,219,74,207,27,160]},"privacy_preimage":[15444404314180609189,8527172248563520527,10097158032980327554,16667986912870196698,12246683181719442872],"unlock_key":[13040881573072405703,8995936729882139039,13645864635353917427,2266901363176610713,8938526604847354894],"seed":[15856601167853116399,812460632502078442,1821027256123673005,8199846743934765184,13440833780556670412]}],[65535,{"receiver_identifier":5856037380742679728,"decryption_key":{"key":[30,141,219,175,213,131,223,249,157,149,162,118,94,111,240,242,67,36,52,212,118,181,53,227,149,141,79,104,6,121,89,202],"seed":[21,106,40,43,176,119,143,244,144,203,244,149,213,161,205,253,180,24,91,44,176,146,248,10,64,56,143,98,166,62,15,58]},"privacy_preimage":[5114748902587198487,8049387925379178554,1807490043555896444,4081459128049551418,14505292235323317359],"unlock_key":[13563943080511864995,11974021274019981663,4721435379242271972,5988094665144874713,5621350591738873911],"seed":[1890741670832029888,7834038028355318189,13710121957536755320,9558335319520715221,21432049612029273]}]]
"#
            }
        }
    }
}
