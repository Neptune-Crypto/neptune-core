pub mod wallet_block_utxos;
pub mod wallet_state;
pub mod wallet_status;

use anyhow::{bail, Context, Result};
use num_traits::{One, Zero};
use secp256k1::{ecdsa, Secp256k1};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use twenty_first::shared_math::other::random_elements_array;
use twenty_first::shared_math::rescue_prime_digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::rescue_prime_regular::DIGEST_LENGTH;

use crate::models::blockchain::digest::{
    DEVNET_MSG_DIGEST_SIZE_IN_BYTES, DEVNET_SECRET_KEY_SIZE_IN_BYTES,
};
use crate::Hash;

pub const WALLET_FILE_NAME: &str = "wallet.dat";
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
pub struct Wallet {
    name: String,

    // For now we use `Digest` as secret key as it's consistent with STARK
    // proofs that we're transitioning to after DevNet.
    secret_seed: Digest,
    version: u8,
}

impl Wallet {
    /// Create new `Wallet` given a `secret` key.
    pub fn new(secret_seed: Digest) -> Self {
        Self {
            name: STANDARD_WALLET_NAME.to_string(),
            secret_seed,
            version: STANDARD_WALLET_VERSION,
        }
    }

    /// Create a `Wallet` for signing merged `Transaction`s on devnet
    ///
    /// This is a placeholder for STARK proofs
    pub fn devnet_authority_wallet() -> Self {
        let secret_seed = Digest::new([
            BFieldElement::new(12063201067205522823),
            BFieldElement::new(1529663126377206632),
            BFieldElement::new(2090171368883726200),
            BFieldElement::new(12975872837767296928),
            BFieldElement::new(11492877804687889759),
        ]);

        Wallet::new(secret_seed)
    }

    /// Read wallet from `wallet_file` if the file exists, or, if none exists, create new wallet
    /// and save it to `wallet_file`.
    pub fn read_from_file_or_create(wallet_file_path: &Path) -> Result<Self> {
        let wallet = if wallet_file_path.exists() {
            Self::read_from_file(wallet_file_path)?
        } else {
            let new_secret: Digest = generate_secret_key();
            let new_wallet: Wallet = Wallet::new(new_secret);
            new_wallet.create_wallet_file(wallet_file_path)?;
            new_wallet
        };

        // Sanity check that wallet file was stored on disk.
        if !wallet_file_path.exists() {
            bail!(
                "Wallet file '{}' must exist on disk after reading/creating it.",
                wallet_file_path.to_string_lossy()
            );
        }

        Ok(wallet)
    }

    /// Read Wallet from file as JSON
    fn read_from_file(wallet_file: &Path) -> Result<Self> {
        let wallet_file_content: String = fs::read_to_string(wallet_file).with_context(|| {
            format!(
                "Failed to read wallet from {}",
                wallet_file.to_string_lossy(),
            )
        })?;

        serde_json::from_str::<Wallet>(&wallet_file_content).with_context(|| {
            format!(
                "Failed to decode wallet from {}",
                wallet_file.to_string_lossy(),
            )
        })
    }

    /// Create wallet file with restrictive permissions and save this wallet to disk
    fn create_wallet_file(&self, wallet_file: &Path) -> Result<()> {
        let wallet_as_json: String = serde_json::to_string(self).unwrap();

        if cfg!(windows) {
            Self::create_wallet_file_windows(&wallet_file.to_path_buf(), wallet_as_json)
        } else {
            Self::create_wallet_file_unix(&wallet_file.to_path_buf(), wallet_as_json)
        }
    }

    #[cfg(target_family = "unix")]
    /// Create a wallet file, and set restrictive permissions
    fn create_wallet_file_unix(path: &PathBuf, wallet_as_json: String) -> Result<()> {
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
        fs::write(path.clone(), wallet_as_json).context("Failed to write wallet file to disk")
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

    // **Note:** `Message::from_slice()` has to take a slice that is a cryptographically
    // secure hash of the actual message that's going to be signed. Otherwise the result
    // of signing isn't a secure signature. Since `msg_digest` is expected to come from
    // Rescue-Prime.
    pub fn sign_digest(&self, msg_digest: Digest) -> ecdsa::Signature {
        let sk = self.get_ecdsa_signing_secret_key();
        let msg_bytes: [u8; Digest::BYTES] = msg_digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes[..DEVNET_MSG_DIGEST_SIZE_IN_BYTES])
            .expect("a byte slice that is DEVNET_MSG_DIGEST_SIZE_IN_BYTES long");
        sk.sign_ecdsa(msg)
    }

    pub fn get_public_key(&self) -> secp256k1::PublicKey {
        let secp = Secp256k1::new();
        let ecdsa_secret_key: secp256k1::SecretKey = self.get_ecdsa_signing_secret_key();
        secp256k1::PublicKey::from_secret_key(&secp, &ecdsa_secret_key)
    }

    // This is a temporary workaround until our own cryptography is ready.
    // At that point we can return `Digest` as is. Note that `Digest::BYTES`
    // is 5 * 8 = 40 bytes, while SecretKey expects 32 bytes.
    fn get_ecdsa_signing_secret_key(&self) -> secp256k1::SecretKey {
        let signing_key: Digest = self.get_signing_key();
        let bytes: [u8; Digest::BYTES] = signing_key.into();
        secp256k1::SecretKey::from_slice(&bytes[..DEVNET_SECRET_KEY_SIZE_IN_BYTES])
            .expect("a byte slice that is DEVNET_SECRET_KEY_SIZE_IN_BYTES long")
    }

    /// Return the secret key that is used for signatures
    fn get_signing_key(&self) -> Digest {
        let secret_seed = self.secret_seed;
        Hash::hash_pair(&secret_seed, &Self::signature_secret_key_marker())
    }

    /// Return the secret key that is used to deterministically generate commitment pseudo-randomness
    /// for the mutator set.
    fn get_commitment_randomness_seed(&self) -> Digest {
        let secret_seed = self.secret_seed;
        Hash::hash_pair(&secret_seed, &Self::commitment_marker())
    }

    fn signature_secret_key_marker() -> Digest {
        Digest::new([BFieldElement::zero(); DIGEST_LENGTH])
    }

    fn commitment_marker() -> Digest {
        Digest::new([
            BFieldElement::one(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
            BFieldElement::zero(),
        ])
    }
}

#[cfg(test)]
mod wallet_tests {
    use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
    use num_traits::One;
    use tracing_test::traced_test;

    use crate::config_models::network::Network;
    use crate::models::blockchain::block::block_height::BlockHeight;
    use crate::models::blockchain::block::Block;
    use crate::models::blockchain::digest::DEVNET_MSG_DIGEST_SIZE_IN_BYTES;
    use crate::models::blockchain::shared::Hash;
    use crate::models::blockchain::transaction::utxo::Utxo;
    use crate::models::blockchain::transaction::Amount;
    use crate::models::database::MonitoredUtxo;
    use crate::tests::shared::{
        add_output_to_block, add_unsigned_input_to_block, add_unsigned_input_to_block_ams,
        get_mock_wallet_state, make_mock_block, make_unit_test_archival_state,
    };

    use super::*;

    #[tokio::test]
    async fn output_digest_changes_test() {
        // Verify that output randomness is not repeated
        let wallet_state = get_mock_wallet_state(None).await;
        let mut previous_digest = wallet_state.next_output_randomness().await;
        for _ in 0..12 {
            let next_output_randomness = wallet_state.next_output_randomness().await;
            assert_ne!(
                previous_digest, next_output_randomness,
                "Output randomness must not be repeated"
            );
            previous_digest = next_output_randomness;
        }
    }

    #[tokio::test]
    async fn wallet_state_constructor_with_genesis_block_test() -> Result<()> {
        // This test is designed to verify that the genesis block is applied
        // to the wallet state at initialization.
        let wallet_state_premine_recipient = get_mock_wallet_state(None).await;
        let monitored_utxos_premine_wallet =
            wallet_state_premine_recipient.get_monitored_utxos().await;
        assert_eq!(
            1,
            monitored_utxos_premine_wallet.len(),
            "Monitored UTXO list must contain premined UTXO at init, for premine-wallet"
        );
        assert_eq!(
            monitored_utxos_premine_wallet[0].utxo,
            Block::premine_utxos()[0],
            "Auth wallet's monitored UTXO must match that from genesis block at initialization"
        );

        let random_wallet = Wallet::new(generate_secret_key());
        let wallet_state_other = get_mock_wallet_state(Some(random_wallet)).await;
        let monitored_utxos_other = wallet_state_other.get_monitored_utxos().await;
        assert!(
            monitored_utxos_other.is_empty(),
            "Monitored UTXO list must be empty at init if wallet is not premine-wallet"
        );

        // Add 12 blocks and verify that membership proofs are still valid
        let genesis_block = Block::genesis_block();
        let mut next_block = genesis_block.clone();
        for _ in 0..12 {
            let previous_block = next_block;
            next_block = make_mock_block(
                &previous_block,
                None,
                wallet_state_other.wallet.get_public_key(),
            );
            wallet_state_premine_recipient.update_wallet_state_with_new_block(
                &next_block,
                &mut wallet_state_premine_recipient.wallet_db.lock().await,
            )?;
        }

        let monitored_utxos = wallet_state_premine_recipient.get_monitored_utxos().await;
        assert_eq!(
            1,
            monitored_utxos.len(),
            "monitored UTXOs must be 1 after applying N blocks not mined by wallet"
        );

        let genesis_block_output_utxo = genesis_block.body.transaction.outputs[0].0;
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
        let wallet = Wallet::new(generate_secret_key());
        let wallet_state = get_mock_wallet_state(Some(wallet.clone())).await;
        let other_wallet = Wallet::new(generate_secret_key());

        let mut monitored_utxos = wallet_state.get_monitored_utxos().await;
        assert!(
            monitored_utxos.is_empty(),
            "Monitored UTXO list must be empty at init"
        );

        let genesis_block = Block::genesis_block();
        let mut block_1 = make_mock_block(&genesis_block, None, wallet.get_public_key());
        wallet_state.update_wallet_state_with_new_block(
            &block_1,
            &mut wallet_state.wallet_db.lock().await,
        )?;
        monitored_utxos = wallet_state.get_monitored_utxos().await;
        assert_eq!(
            1,
            monitored_utxos.len(),
            "Monitored UTXO list be one after we mined a block"
        );

        // Ensure that the membership proof is valid
        {
            let block_1_tx_output_utxo = block_1.body.transaction.outputs[0].0;
            let block_1_tx_output_digest = Hash::hash(&block_1_tx_output_utxo);
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
        let block_2 = make_mock_block(&block_1, None, other_wallet.get_public_key());
        let mut block_3 = make_mock_block(&block_2, None, other_wallet.get_public_key());
        monitored_utxos = wallet_state.get_monitored_utxos().await;
        {
            let block_1_tx_output_utxo = block_1.body.transaction.outputs[0].0;
            let block_1_tx_output_digest = Hash::hash(&block_1_tx_output_utxo);
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
        monitored_utxos = wallet_state.get_monitored_utxos().await;

        {
            let block_1_tx_output_utxo = block_1.body.transaction.outputs[0].0;
            let block_1_tx_output_digest = Hash::hash(&block_1_tx_output_utxo);
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
        let own_wallet = Wallet::new(generate_secret_key());
        let own_wallet_state = get_mock_wallet_state(Some(own_wallet)).await;
        let genesis_block = Block::genesis_block();
        let block_1 = make_mock_block(
            &genesis_block,
            None,
            own_wallet_state.wallet.get_public_key(),
        );

        // Add block to wallet state
        own_wallet_state.update_wallet_state_with_new_block(
            &block_1,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        // Verify that the allocater returns a sane amount
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(1.into())
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(99.into())
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            1,
            own_wallet_state
                .allocate_sufficient_input_funds(100.into())
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 100
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(101.into())
            .await
            .is_err());

        // Mine 21 more blocks and verify that 2200 worth of UTXOs can be allocated
        let mut next_block = block_1.clone();
        for _ in 0..21 {
            let previous_block = next_block;
            next_block = make_mock_block(
                &previous_block,
                None,
                own_wallet_state.wallet.get_public_key(),
            );
            own_wallet_state.update_wallet_state_with_new_block(
                &next_block,
                &mut own_wallet_state.wallet_db.lock().await,
            )?;
        }

        assert_eq!(
            5,
            own_wallet_state
                .allocate_sufficient_input_funds(500.into())
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            6,
            own_wallet_state
                .allocate_sufficient_input_funds(501.into())
                .await
                .unwrap()
                .len()
        );
        assert_eq!(
            22,
            own_wallet_state
                .allocate_sufficient_input_funds(2200.into())
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 2200
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(2201.into())
            .await
            .is_err());

        // Make a block that spends an input, then verify that this is reflected by
        // the allocator.
        let two_utxos = own_wallet_state
            .allocate_sufficient_input_funds(200.into())
            .await
            .unwrap();
        assert_eq!(
            2,
            two_utxos.len(),
            "Must use two UTXOs each worth 100 to send 200"
        );

        // This block spends two UTXOs and gives us none, so the new balance
        // becomes 2000
        let other_wallet = Wallet::new(generate_secret_key());
        assert_eq!(Into::<BlockHeight>::into(22u64), next_block.header.height);
        next_block = make_mock_block(&next_block.clone(), None, other_wallet.get_public_key());
        assert_eq!(Into::<BlockHeight>::into(23u64), next_block.header.height);
        for (utxo, ms_mp) in two_utxos {
            add_unsigned_input_to_block(&mut next_block, utxo, ms_mp);
        }

        own_wallet_state.update_wallet_state_with_new_block(
            &next_block,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        assert_eq!(
            20,
            own_wallet_state
                .allocate_sufficient_input_funds(2000.into())
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 2000
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(2001.into())
            .await
            .is_err());

        // Add another block that spends *one* UTXO and gives us none, so the new balance
        // becomes 1900
        next_block = make_mock_block(&next_block, None, other_wallet.get_public_key());
        let one_utxo = own_wallet_state
            .allocate_sufficient_input_funds(98.into())
            .await
            .unwrap();
        assert_eq!(1, one_utxo.len());
        add_unsigned_input_to_block(&mut next_block, one_utxo[0].0, one_utxo[0].1.clone());

        own_wallet_state.update_wallet_state_with_new_block(
            &next_block,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        assert_eq!(
            19,
            own_wallet_state
                .allocate_sufficient_input_funds(1900.into())
                .await
                .unwrap()
                .len()
        );

        // Cannot allocate more than we have: 1900
        assert!(own_wallet_state
            .allocate_sufficient_input_funds(1901.into())
            .await
            .is_err());

        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn wallet_state_maintanence_multiple_inputs_outputs_test() -> Result<()> {
        // an archival state is needed for how we currently add inputs to a transaction.
        // So it's just used to generate test data, not in any of the functions that are
        // actually tested.
        let (archival_state, _peer_databases) = make_unit_test_archival_state(Network::Main).await;
        let own_wallet = Wallet::new(generate_secret_key());
        let own_wallet_state = get_mock_wallet_state(Some(own_wallet)).await;
        let premine_wallet = get_mock_wallet_state(None).await.wallet;
        let genesis_block = Block::genesis_block();

        let mut block_1 = make_mock_block(
            &genesis_block,
            None,
            own_wallet_state.wallet.get_public_key(),
        );

        // Add a valid input to the block transaction
        let consumed_utxo_0 = genesis_block.body.transaction.outputs[0].0;
        let premine_output_randomness = genesis_block.body.transaction.outputs[0].1;
        add_unsigned_input_to_block_ams(
            &mut block_1,
            consumed_utxo_0,
            premine_output_randomness,
            &archival_state.archival_mutator_set,
            0,
        )
        .await;

        // Add one output to the block's transaction
        let output_utxo_0: Utxo =
            Utxo::new(Amount::one(), own_wallet_state.wallet.get_public_key());
        add_output_to_block(&mut block_1, output_utxo_0);

        // Add three more outputs, two of them to self
        let output_utxo_1: Utxo = Utxo::new(
            Amount::one() + Amount::one(),
            own_wallet_state.wallet.get_public_key(),
        );
        add_output_to_block(&mut block_1, output_utxo_1);
        let output_utxo_2: Utxo = Utxo::new(
            Amount::one() + Amount::one() + Amount::one(),
            premine_wallet.get_public_key(),
        );
        add_output_to_block(&mut block_1, output_utxo_2);
        let output_utxo_3: Utxo = Utxo::new(
            Amount::one() + Amount::one() + Amount::one() + Amount::one() + Amount::one(),
            own_wallet_state.wallet.get_public_key(),
        );
        add_output_to_block(&mut block_1, output_utxo_3);

        // Sign the transaction with the premine-wallet (since it owns the single input into
        // the block), and verify its validity.
        block_1.body.transaction.sign(&premine_wallet);
        assert!(block_1.is_valid_for_devnet(&genesis_block));

        // Update wallet state with block_1
        let mut monitored_utxos = own_wallet_state.get_monitored_utxos().await;
        assert!(
            monitored_utxos.is_empty(),
            "List of monitored UTXOs must be empty prior to updating wallet state"
        );
        own_wallet_state.update_wallet_state_with_new_block(
            &block_1,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        // Verify that update added 4 UTXOs to list of monitored transactions:
        // three as regular outputs, and one as coinbase UTXO
        monitored_utxos = own_wallet_state.get_monitored_utxos().await;
        assert_eq!(
            4,
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
            next_block = make_mock_block(
                &previous_block,
                None,
                own_wallet_state.wallet.get_public_key(),
            );
            own_wallet_state.update_wallet_state_with_new_block(
                &next_block,
                &mut own_wallet_state.wallet_db.lock().await,
            )?;
        }

        let mut block_18 = next_block;
        monitored_utxos = own_wallet_state.get_monitored_utxos().await;
        assert_eq!(
            4 + 17,
            monitored_utxos.len(),
            "List of monitored UTXOs have length 21 after updating wallet state and mining 17 blocks"
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
        let wallet_status = own_wallet_state.get_wallet_status().await;
        assert_eq!(
            21,
            wallet_status.synced_unspent.len(),
            "Wallet must have 20 synced, unspent UTXOs"
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
        let mut block_2_b =
            make_mock_block(&block_1, Some(100.into()), premine_wallet.get_public_key());
        own_wallet_state.update_wallet_state_with_new_block(
            &block_2_b,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        let monitored_utxos_at_2b: Vec<_> = own_wallet_state
            .get_monitored_utxos()
            .await
            .into_iter()
            .filter(|x| x.has_synced_membership_proof)
            .collect();
        assert_eq!(
            4,
            monitored_utxos_at_2b.len(),
            "List of monitored UTXOs have length 4 after updating wallet state"
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
        let mut block_19 =
            make_mock_block(&block_18, Some(100.into()), premine_wallet.get_public_key());
        own_wallet_state.update_wallet_state_with_new_block(
            &block_19,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;
        let monitored_utxos_block_19: Vec<_> = own_wallet_state
            .get_monitored_utxos()
            .await
            .into_iter()
            .filter(|monitored_utxo| monitored_utxo.has_synced_membership_proof)
            .collect();
        assert_eq!(
            4 + 17,
            monitored_utxos_block_19.len(),
            "List of monitored UTXOs have length 21 after returning to good fork"
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
        let mut block_3_b = make_mock_block(
            &block_2_b,
            Some(100.into()),
            own_wallet_state.wallet.get_public_key(),
        );

        let consumed_utxo_1 = monitored_utxos_at_2b[0].utxo;
        let consumed_utxo_1_mp = monitored_utxos_at_2b[0]
            .get_membership_proof_for_block(&block_2_b.hash)
            .unwrap();
        add_unsigned_input_to_block(&mut block_3_b, consumed_utxo_1, consumed_utxo_1_mp);
        let forked_utxo: Utxo =
            Utxo::new(Amount::from(6u32), own_wallet_state.wallet.get_public_key());
        add_output_to_block(&mut block_3_b, forked_utxo);
        block_3_b.body.transaction.sign(&own_wallet_state.wallet);
        assert!(block_3_b.is_valid_for_devnet(&block_2_b));
        own_wallet_state.update_wallet_state_with_new_block(
            &block_3_b,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        let monitored_utxos_3b: Vec<_> = own_wallet_state
            .get_monitored_utxos()
            .await
            .into_iter()
            .filter(|x| x.has_synced_membership_proof)
            .collect();
        assert_eq!(
            4 + 2,
            monitored_utxos_3b.len(),
            "List of monitored and unspent UTXOs have length 6 after receiving two"
        );
        assert_eq!(
            1,
            monitored_utxos_3b
                .iter()
                .filter(|x| x.spent_in_block.is_some())
                .count(),
            "One monitored UTXO must be marked as spent"
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

        // Then fork back to A-chain which contains the same output to `own_wallet`
        let mut block_20 = make_mock_block(
            &block_19,
            Some(100.into()),
            own_wallet_state.wallet.get_public_key(),
        );
        let consumed_utxo_2 = monitored_utxos_block_19[0].utxo;
        let consumed_utxo_2_mp = monitored_utxos_block_19[0]
            .get_membership_proof_for_block(&block_19.hash)
            .unwrap();
        add_unsigned_input_to_block(&mut block_20, consumed_utxo_2, consumed_utxo_2_mp);
        add_output_to_block(&mut block_20, forked_utxo);
        block_20.body.transaction.sign(&own_wallet_state.wallet);
        own_wallet_state.update_wallet_state_with_new_block(
            &block_20,
            &mut own_wallet_state.wallet_db.lock().await,
        )?;

        // Verify that we have two membership proofs of `forked_utxo`: one matching block20 and one matching block_3b
        let monitored_utxos_20: Vec<_> = own_wallet_state
            .get_monitored_utxos()
            .await
            .into_iter()
            .filter(|x| x.has_synced_membership_proof)
            .collect();
        assert_eq!(
            4 + 17 + 2, // Two more than after block19
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

        // Verify that we only have *one* entry for `forked_utxo`
        assert_eq!(
            1,
            monitored_utxos_20
                .iter()
                .filter(|x| Hash::hash(&x.utxo) == Hash::hash(&forked_utxo))
                .count()
        );

        // Verify that we have two membership proofs for forked UTXO
        let forked_utxo_digest = Hash::hash(&forked_utxo);
        let forked_utxo_info: MonitoredUtxo = monitored_utxos_20
            .into_iter()
            .find(|monitored_utxo| Hash::hash(&monitored_utxo.utxo) == forked_utxo_digest)
            .unwrap();
        assert!(
            forked_utxo_info
                .get_membership_proof_for_block(&block_20.hash)
                .is_some(),
            "Wallet state must contain membership proof for current block"
        );
        assert!(
            forked_utxo_info
                .get_membership_proof_for_block(&block_3_b.hash)
                .is_some(),
            "Wallet state must contain mebership proof for abandoned block"
        );
        println!("forked_utxo_info\n {:?}", forked_utxo_info);
        assert_eq!(
            2,
            forked_utxo_info.blockhash_to_membership_proof.len(),
            "Two membership proofs must be stored for forked UTXO"
        );

        Ok(())
    }

    #[tokio::test]
    async fn new_random_wallet_base_test() {
        let random_wallet = Wallet::new(generate_secret_key());
        let wallet_state = get_mock_wallet_state(Some(random_wallet)).await;
        let pk = wallet_state.wallet.get_public_key();
        let msg_vec: Vec<BFieldElement> = wallet_state.wallet.secret_seed.values().to_vec();
        let digest: Digest = Hash::hash_slice(&msg_vec);
        let signature = wallet_state.wallet.sign_digest(digest);
        let msg_bytes: [u8; Digest::BYTES] = digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes[..DEVNET_MSG_DIGEST_SIZE_IN_BYTES])
            .expect("a byte slice that is DEVNET_MSG_DIGEST_SIZE_IN_BYTES long");
        assert!(
            signature.verify(&msg, &pk).is_ok(),
            "DEVNET signature must verify"
        );

        let signature_alt = wallet_state.wallet.sign_digest(digest);
        assert!(
            signature_alt.verify(&msg, &pk).is_ok(),
            "DEVNET signature must verify"
        );
    }

    #[test]
    fn signature_secret_and_commitment_p_randomness_secret_are_different() {
        let secret = generate_secret_key();
        let wallet = Wallet::new(secret);
        assert_ne!(
            wallet.get_commitment_randomness_seed(),
            wallet.get_signing_key()
        );
    }

    #[test]
    fn get_authority_spending_public_key() {
        // Helper function/test to print the public key associated with the authority signatures
        let authority_wallet = Wallet::devnet_authority_wallet();
        println!(
            "authority_wallet pub key: {}",
            authority_wallet.get_public_key()
        );
    }
}
