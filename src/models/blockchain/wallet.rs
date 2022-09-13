use super::block::Block;
use super::digest::{
    Digest, DEVNET_MSG_DIGEST_SIZE_IN_BYTES, DEVNET_SECRET_KEY_SIZE_IN_BYTES,
    RESCUE_PRIME_OUTPUT_SIZE_IN_BFES,
};
use super::transaction::devnet_input::DevNetInput;
use super::transaction::utxo::Utxo;
use super::transaction::{Amount, Transaction};
use crate::config_models::data_directory::get_data_directory;
use crate::config_models::network::Network;
use crate::database::leveldb::LevelDB;
use crate::database::rusty::RustyLevelDB;
use crate::Hash;
use anyhow::Result;
use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use num_traits::Zero;
use rand::thread_rng;
use secp256k1::{ecdsa, Secp256k1};
use serde::{Deserialize, Serialize};
use std::fs;
use std::ops::Add;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use twenty_first::shared_math::{b_field_element::BFieldElement, traits::GetRandomElements};
use twenty_first::util_types::simple_hasher::Hasher;

const WALLET_FILE_NAME: &str = "wallet.dat";
const STANDARD_WALLET_NAME: &str = "standard_wallet";
const STANDARD_WALLET_VERSION: u8 = 0;
const WALLET_BLOCK_DB_NAME: &str = "wallet_block_db";
const WALLET_OUTPUT_COUNT_DB_NAME: &str = "wallout_output_count_db";

type BlockHash = Digest;
/// The parts of a block that this wallet wants to keep track of,
/// ie. the input and output UTXOs that share this wallet's public key.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct WalletBlockUtxos {
    pub input_utxos: Vec<Utxo>,
    pub output_utxos: Vec<(Utxo, Digest)>,
}

struct WalletBlockIOSums {
    pub input_sum: Amount,
    pub output_sum: Amount,
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
    fn new(input_utxos: Vec<Utxo>, output_utxos: Vec<(Utxo, Digest)>) -> Self {
        Self {
            input_utxos,
            output_utxos,
        }
    }

    fn get_io_sums(&self) -> WalletBlockIOSums {
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

/// Gets a new secret.
pub fn generate_secret_key() -> Digest {
    let mut rng = thread_rng();
    BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut rng).into()
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
            BFieldElement::new(14683724377595469133),
            BFieldElement::new(4905634007273628284),
            BFieldElement::new(2544353828551980854),
            BFieldElement::new(9457203229242732950),
            BFieldElement::new(5097796649750941488),
            BFieldElement::new(12701344140082211424),
        ]);

        Wallet::new(secret_seed)
    }

    /// Read wallet from `wallet_file` if the file exists, or, if none exists, create new wallet
    /// and save it to `wallet_file`.
    pub fn read_from_file_or_create(wallet_file: &Path) -> Self {
        let ret = if wallet_file.exists() {
            Self::read_from_file(wallet_file)
        } else {
            let new_secret: Digest = generate_secret_key();
            let new_wallet: Wallet = Wallet::new(new_secret);
            new_wallet.create_wallet_file(wallet_file);
            new_wallet
        };

        // Sanity check that wallet file was stored on disk.
        assert!(
            wallet_file.exists(),
            "wallet file must exist on disk after creation or opening."
        );

        ret
    }

    /// Read Wallet from file as JSON
    fn read_from_file(wallet_file: &Path) -> Self {
        let wallet_file_content: String = fs::read_to_string(wallet_file).unwrap_or_else(|err| {
            panic!(
                "Failed to read wallet from {}: {}",
                wallet_file.to_string_lossy(),
                err
            )
        });

        serde_json::from_str::<Wallet>(&wallet_file_content).unwrap_or_else(|err| {
            panic!(
                "Failed to decode wallet from {}: {}",
                wallet_file.to_string_lossy(),
                err
            )
        })
    }

    /// Create wallet file with restrictive permissions and save this wallet to disk
    fn create_wallet_file(&self, wallet_file: &Path) {
        let wallet_as_json: String = serde_json::to_string(self).unwrap();

        if cfg!(windows) {
            Self::create_wallet_file_windows(&wallet_file.to_path_buf(), wallet_as_json);
        } else {
            Self::create_wallet_file_unix(&wallet_file.to_path_buf(), wallet_as_json);
        }
    }

    /// Derive the filesystem path for Wallet within data directory
    pub fn wallet_path(root_data_dir_path: &Path) -> PathBuf {
        let mut pb = root_data_dir_path.to_path_buf();
        pb.push(WALLET_FILE_NAME);
        pb
    }

    #[cfg(target_family = "unix")]
    /// Create a wallet file, and set restrictive permissions
    fn create_wallet_file_unix(path: &PathBuf, wallet_as_json: String) {
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
        fs::write(path.clone(), wallet_as_json).expect("Failed to write wallet file to disk");
    }

    /// Create a wallet file, without setting restrictive UNIX permissions
    fn create_wallet_file_windows(path: &PathBuf, wallet_as_json: String) {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .unwrap();
        fs::write(path.clone(), wallet_as_json).expect("Failed to write wallet file to disk");
    }

    pub fn sign_digest(&self, msg_digest: Digest) -> ecdsa::Signature {
        let sk = self.get_ecdsa_signing_secret_key();
        let msg_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = msg_digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes).unwrap();
        sk.sign_ecdsa(msg)
    }

    pub fn get_public_key(&self) -> secp256k1::PublicKey {
        let secp = Secp256k1::new();
        let ecdsa_secret_key: secp256k1::SecretKey = self.get_ecdsa_signing_secret_key();
        secp256k1::PublicKey::from_secret_key(&secp, &ecdsa_secret_key)
    }

    // This is a temporary workaround until our own cryptography is ready.
    // At that point we can return `Digest` as is.
    fn get_ecdsa_signing_secret_key(&self) -> secp256k1::SecretKey {
        let signing_key = self.get_signing_key();
        let bytes: [u8; DEVNET_SECRET_KEY_SIZE_IN_BYTES] = signing_key.into();
        secp256k1::SecretKey::from_slice(&bytes).unwrap()
    }

    /// Return the secret key that is used for signatures
    fn get_signing_key(&self) -> Digest {
        let secret_seed = self.secret_seed;
        let signature_secret_key_marker = Digest::default();
        let hasher = Hash::new();
        hasher
            .hash_pair(&secret_seed.into(), &signature_secret_key_marker.into())
            .into()
    }

    /// Return the secret key that is used to deterministically generate commitment pseudo-randomness
    /// for the mutator set.
    fn get_commitment_randomness_seed(&self) -> Digest {
        let secret_seed = self.secret_seed;
        let mut commitment_pr_marker: Vec<BFieldElement> =
            vec![BFieldElement::ring_zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES];
        commitment_pr_marker[0] = BFieldElement::ring_one();
        let hasher = Hash::new();
        hasher
            .hash_pair(&secret_seed.into(), &commitment_pr_marker)
            .into()
    }
}

/// A wallet indexes its input and output UTXOs after blockhashes
/// so that one can easily roll-back. We don't want to serialize the
/// database handle, wherefore this struct exists.
#[derive(Debug, Clone)]
pub struct WalletState {
    // This value must be increased by one for each output.
    // Output counter counts number of outputs generated by this wallet. It does not matter
    // if these outputs are confirmed in a block or not. It adds one per output regardless.
    // The purpose of this value is to generate unique and deterministic entropy for each
    // new output.
    pub outgoing_utxo_counter_db: Arc<TokioMutex<RustyLevelDB<(), u128>>>,

    pub wallet_block_db: Arc<TokioMutex<RustyLevelDB<BlockHash, WalletBlockUtxos>>>,
    pub wallet: Wallet,
    // This `secret_key` corresponds to a `master_private_key` for Bitcoin wallet.
    // From this master key several individual UTXO private keys can be derived using this [scheme][scheme]
    // [scheme]: https://learnmeabitcoin.com/technical/derivation-paths
}

impl WalletState {
    pub fn new_from_wallet(wallet: Wallet, network: Network) -> Self {
        // Create or connect to wallet block DB
        let wallet_block_db: RustyLevelDB<BlockHash, WalletBlockUtxos> =
            RustyLevelDB::<BlockHash, WalletBlockUtxos>::new(
                get_data_directory(network).unwrap(),
                WALLET_BLOCK_DB_NAME,
                rusty_leveldb::Options::default(),
            )
            .unwrap();
        let wallet_block_db = Arc::new(TokioMutex::new(wallet_block_db));

        // Create or connect to DB for output count
        let outgoing_utxo_count_db: RustyLevelDB<(), u128> = RustyLevelDB::<(), u128>::new(
            get_data_directory(network).unwrap(),
            WALLET_OUTPUT_COUNT_DB_NAME,
            rusty_leveldb::Options::default(),
        )
        .unwrap();
        let outgoing_utxo_counter_db = Arc::new(TokioMutex::new(outgoing_utxo_count_db));

        Self {
            outgoing_utxo_counter_db,
            wallet_block_db,
            wallet,
        }
    }
}

impl WalletState {
    pub fn update_wallet_state_with_new_block(
        &self,
        block: &Block,
        wallet_db_lock: &mut tokio::sync::MutexGuard<RustyLevelDB<Digest, WalletBlockUtxos>>,
    ) -> Result<()> {
        // A wallet contains a set of input and output UTXOs,
        // each of which contains an address (public key),
        // which inform the balance of the wallet.

        //TODO: In mainloop, actually call forget_block when you remove it.

        let transaction: Transaction = block.body.transaction.clone();

        let my_pub_key = self.wallet.get_public_key();

        let input_utxos: Vec<Utxo> = transaction.get_input_utxos_with_pub_key(my_pub_key);

        let output_utxos: Vec<(Utxo, Digest)> =
            transaction.get_output_utxos_with_pub_key(my_pub_key);

        // Let's not store the UTXOs of blocks that don't affect our balance
        if input_utxos.is_empty() && output_utxos.is_empty() {
            return Ok(());
        }

        let next_block_of_relevant_utxos = WalletBlockUtxos::new(input_utxos, output_utxos);

        wallet_db_lock.put(block.hash, next_block_of_relevant_utxos);

        Ok(())
    }

    pub async fn get_balance(&self) -> Amount {
        let sums: WalletBlockIOSums = self
            .wallet_block_db
            .lock()
            .await
            .new_iter()
            .map(|(_block_hash, wallet_block)| wallet_block.get_io_sums())
            .reduce(|a, b| a + b)
            .unwrap();
        sums.output_sum - sums.input_sum
    }

    #[allow(dead_code)]
    async fn forget_block(&self, block_hash: Digest) {
        self.wallet_block_db.lock().await.delete(block_hash);
    }

    /// Fetch the output counter from the database and increase the counter by one
    async fn next_output_counter(&self) -> u128 {
        let mut outgoing_utxo_counter_lock = self.outgoing_utxo_counter_db.lock().await;
        let current_counter: u128 = outgoing_utxo_counter_lock.get(()).unwrap_or_default();
        outgoing_utxo_counter_lock.put((), current_counter + 1);

        current_counter
    }

    /// Get the randomness for the next output UTXO and increment the output counter by one
    async fn next_output_randomness(&self) -> Digest {
        let counter = self.next_output_counter().await;

        // TODO: Ugly hack used to generate a `Digest` from a `u128` here.
        // Once we've updated to twenty-first 0.2.0 or later use its `to_sequence` instead.
        let mut counter_as_digest: Vec<BFieldElement> =
            vec![BFieldElement::ring_zero(); RESCUE_PRIME_OUTPUT_SIZE_IN_BFES];
        counter_as_digest[0] = BFieldElement::new(counter as u64);
        let counter_as_digest: Digest = counter_as_digest.into();
        let commitment_pseudo_randomness_seed = self.wallet.get_commitment_randomness_seed();
        let hasher = Hash::new();

        hasher
            .hash_pair(
                &counter_as_digest.into(),
                &commitment_pseudo_randomness_seed.into(),
            )
            .into()
    }

    pub async fn create_transaction(
        &self,
        amount: Amount,
        recipient_public_key: secp256k1::PublicKey,
    ) -> Result<Transaction> {
        let _spendable_utxos: Vec<(Utxo, Digest)> = self.allocate_sufficient_input_funds(amount)?;
        let _membership_proofs: Vec<MsMembershipProof<Hash>> = vec![];

        // TODO: Fetch `MembershipProof`s, generate `RemovalRecord`s, and sign.
        //
        // See `allow_consumption_of_genesis_output_test` in archival_state.
        let inputs: Vec<DevNetInput> = vec![];

        let output_utxo = Utxo {
            amount,
            public_key: recipient_public_key,
        };
        let output_randomness = self.next_output_randomness().await;

        let outputs = vec![(output_utxo, output_randomness)];

        let transaction = Transaction {
            inputs,
            outputs,
            public_scripts: vec![],
            fee: Amount::zero(),
            timestamp: BFieldElement::new(1655916990),
            authority_proof: None,
        };

        Ok(transaction)
    }

    // We apply the strategy of using all UTXOs for the wallet as input and transfer any surplus back to our wallet.
    //
    // TODO: Assert that balance is sufficient! (There is similar logic in block-validation elsewhere.)
    fn allocate_sufficient_input_funds(&self, _amount: Amount) -> Result<Vec<(Utxo, Digest)>> {
        let _allocated_amount = Amount::zero();
        // while allocated_amount < amount {
        // TODO: Allocate enough.
        //
        // TODO: Depends on wallet database of owned UTXOs being available.
        //
        // TODO: Eventually sort by optimal granularity.
        // }
        Ok(vec![])
    }
}

#[cfg(test)]
mod wallet_tests {
    use super::*;
    use crate::{
        models::blockchain::{digest::DEVNET_MSG_DIGEST_SIZE_IN_BYTES, shared::Hash},
        tests::shared::get_mock_wallet_state,
    };
    use twenty_first::{
        shared_math::rescue_prime_xlix::RP_DEFAULT_OUTPUT_SIZE, util_types::simple_hasher::Hasher,
    };

    #[tokio::test]
    async fn increase_output_counter_test() {
        // Verify that output counter is incremented when the counter value is fetched
        let wallet_state = get_mock_wallet_state();
        for i in 0..12 {
            assert_eq!(
                i,
                wallet_state.next_output_counter().await,
                "Output counter must match number of calls"
            );
        }
    }

    #[tokio::test]
    async fn output_digest_changes_test() {
        // Verify that output randomness is not repeated
        let wallet_state = get_mock_wallet_state();
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

    #[test]
    fn new_random_wallet_base_test() {
        let network = Network::Testnet;
        let secret = generate_secret_key();
        let wallet_state = WalletState::new_from_wallet(Wallet::new(secret), network);
        let pk = wallet_state.wallet.get_public_key();
        let msg_vec: Vec<BFieldElement> = wallet_state.wallet.secret_seed.values().to_vec();
        let digest_vec: Vec<BFieldElement> = Hash::new().hash(&msg_vec, RP_DEFAULT_OUTPUT_SIZE);
        let digest: Digest = digest_vec.into();
        let signature = wallet_state.wallet.sign_digest(digest);
        let msg_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes).unwrap();
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
