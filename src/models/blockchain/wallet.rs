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
use futures::executor::block_on;
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
use tracing::info;
use twenty_first::shared_math::{b_field_element::BFieldElement, traits::GetRandomElements};

pub const WALLET_FILE_NAME: &str = "wallet.dat";
pub const STANDARD_WALLET_NAME: &str = "standard_wallet";
pub const STANDARD_WALLET_VERSION: u8 = 0;
pub const STANDARD_WALLET_DB_NAME: &str = "wallet_db.dat";

type BlockHash = Digest;
/// The parts of a block that this wallet wants to keep track of,
/// ie. the input and output UTXOs that share this wallets public key.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct WalletBlock {
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

impl WalletBlock {
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
/// FIXME: This should be reimplemented in a more reasonable way.
fn generate_secret_key() -> Digest {
    let mut rng = thread_rng();

    BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut rng).into()
}

/// Wallet contains the wallet-related data we want to store in a JSON file,
/// and that is not updated during regular program execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    pub name: String,
    pub secret: Digest,
    pub version: u8,
}

impl Wallet {
    fn new(secret: Digest) -> Self {
        Self {
            name: STANDARD_WALLET_NAME.to_string(),
            secret,
            version: STANDARD_WALLET_VERSION,
        }
    }

    /// Read the wallet from disk. Create one if none exists.
    pub fn new_from_file_or_default(wallet_file: &Path) -> Wallet {
        // Check if file exists
        let wallet: Wallet = if wallet_file.exists() {
            info!("Found wallet file: {}", wallet_file.to_string_lossy());

            // Read wallet from disk
            let file_content: String = match fs::read_to_string(wallet_file) {
                Ok(fc) => fc,
                Err(err) => panic!(
                    "Failed to read file {}. Got error: {}",
                    wallet_file.to_string_lossy(),
                    err
                ),
            };

            // Parse wallet as JSON and return result
            match serde_json::from_str(&file_content) {
                Ok(stored_wallet) => stored_wallet,
                Err(err) => {
                    panic!(
                    "Failed to parse {} as Wallet in JSON format. Is the wallet file corrupted? Error: {}",
                    wallet_file.to_string_lossy(),
                    err
                )
                }
            }
        } else {
            info!(
                "Creating new wallet file: {}",
                wallet_file.to_string_lossy()
            );

            // New wallet must be made and stored to disk
            let new_wallet: Wallet = Wallet::new(generate_secret_key());
            let wallet_as_json: String =
                serde_json::to_string(&new_wallet).expect("wallet serialization must succeed");

            // Store to disk, with the right permissions
            if cfg!(target_family = "unix") {
                Self::create_wallet_file_unix(&wallet_file.to_path_buf(), wallet_as_json);
            } else {
                Self::create_wallet_file_windows(&wallet_file.to_path_buf(), wallet_as_json);
            }

            new_wallet
        };

        // Sanity check that wallet file was stored on disk.
        assert!(
            wallet_file.exists(),
            "wallet file must exist on disk after creation."
        );

        wallet
    }

    pub fn wallet_path(root_data_dir_path: &Path) -> PathBuf {
        let mut pb = root_data_dir_path.to_path_buf();
        pb.push(WALLET_FILE_NAME);
        pb
    }

    /// Create a wallet file, and set restrictive permissions
    #[cfg(target_family = "unix")]
    fn create_wallet_file_unix(path: &PathBuf, wallet_as_json: String) {
        // On Unix/Linux we set the file permissions to 600, to disallow
        // other users on the same machine to access the secrets.
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
    // #[cfg(not(target_family = "unix"))]
    fn create_wallet_file_windows(path: &PathBuf, wallet_as_json: String) {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .unwrap();
        fs::write(path.clone(), wallet_as_json).expect("Failed to write wallet file to disk");
    }
}

/// A wallet indexes its input and output UTXOs after blockhashes
/// so that one can easily roll-back. We don't want to serialize the
/// database handle, wherefore this struct exists.
#[derive(Debug, Clone)]
pub struct WalletState {
    pub db: Arc<TokioMutex<RustyLevelDB<BlockHash, WalletBlock>>>,
    pub wallet: Wallet,
    // MAYBE: maintain balance here?
    // TODO: How do we know if the Wallet has seen a given block?

    // This `secret_key` corresponds to a `master_private_key` for Bitcoin wallet.
    // From this master key several individual UTXO private keys can be derived using this [scheme][scheme]
    // [scheme]: https://learnmeabitcoin.com/technical/derivation-paths
}

impl WalletState {
    pub fn new_from_wallet(wallet: Wallet, network: Network) -> Self {
        let _db: RustyLevelDB<BlockHash, WalletBlock> =
            RustyLevelDB::<BlockHash, WalletBlock>::new(
                get_data_directory(network).unwrap(),
                STANDARD_WALLET_DB_NAME,
                rusty_leveldb::Options::default(),
            )
            .unwrap();
        let db = Arc::new(TokioMutex::new(_db));
        Self { wallet, db }
    }
}

impl WalletState {
    pub fn update_wallet_state_with_new_block(&self, block: &Block) {
        // A wallet contains a set of input and output UTXOs,
        // each of which contains an address (public key),
        // which inform the balance of the wallet.

        //TODO: In mainloop, actually call forget_block when you remove it.

        let transaction: Transaction = block.body.transaction.clone();

        let my_pub_key = self.get_public_key();

        let input_utxos: Vec<Utxo> = transaction.get_input_utxos_with_pub_key(my_pub_key);

        let output_utxos: Vec<(Utxo, Digest)> =
            transaction.get_output_utxos_with_pub_key(my_pub_key);

        // if we remove this
        if input_utxos.is_empty() && output_utxos.is_empty() {
            return;
        }

        let next_block_of_relevant_utxos = WalletBlock::new(input_utxos, output_utxos);

        block_on(async {
            self.db
                .lock()
                .await
                .put(block.hash, next_block_of_relevant_utxos)
        })
    }

    pub fn get_balance(&self) -> Amount {
        block_on(async {
            let sums: WalletBlockIOSums = self
                .db
                .lock()
                .await
                .new_iter()
                .map(|(_block_hash, wallet_block)| wallet_block.get_io_sums())
                .reduce(|a, b| a + b)
                .unwrap();
            sums.output_sum - sums.input_sum
        })
    }

    #[allow(dead_code)]
    fn forget_block(&self, block_hash: Digest) {
        block_on(async { self.db.lock().await.delete(block_hash) });
    }

    pub fn create_transaction(
        &self,
        amount: Amount,
        _recipient_public_key: secp256k1::PublicKey,
    ) -> Result<Transaction> {
        let _spendable_utxos: Vec<(Utxo, Digest)> = self.allocate_sufficient_input_funds(amount)?;
        let _membership_proofs: Vec<MsMembershipProof<Hash>> = vec![];

        // TODO: Fetch `MembershipProof`s, generate `RemovalRecord`s, and sign.
        //
        // See `allow_consumption_of_genesis_output_test` in archival_state.
        let inputs: Vec<DevNetInput> = vec![];
        let outputs = vec![];

        let transaction = Transaction {
            inputs,
            outputs,
            public_scripts: vec![],
            fee: Amount::zero(),
            timestamp: BFieldElement::new(1655916990),
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

    fn _get_ecdsa_sk(&self) -> secp256k1::SecretKey {
        let bytes: [u8; DEVNET_SECRET_KEY_SIZE_IN_BYTES] = self.wallet.secret.into();
        secp256k1::SecretKey::from_slice(&bytes).unwrap()
    }

    fn _sign(&self, msg_hash: secp256k1::Message) -> ecdsa::Signature {
        let sk = self._get_ecdsa_sk();
        sk.sign_ecdsa(msg_hash)
    }

    pub fn sign_digest(&self, msg_digest: Digest) -> ecdsa::Signature {
        let sk = self._get_ecdsa_sk();
        let msg_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = msg_digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes).unwrap();
        sk.sign_ecdsa(msg)
    }

    pub fn get_public_key(&self) -> secp256k1::PublicKey {
        let secp = Secp256k1::new();
        let bytes: [u8; DEVNET_SECRET_KEY_SIZE_IN_BYTES] = self.wallet.secret.into();
        let ecdsa_secret_key: secp256k1::SecretKey =
            secp256k1::SecretKey::from_slice(&bytes).unwrap();

        secp256k1::PublicKey::from_secret_key(&secp, &ecdsa_secret_key)
    }
}

#[cfg(test)]
mod ordered_digest_tests {
    use twenty_first::{
        shared_math::rescue_prime_xlix::RP_DEFAULT_OUTPUT_SIZE, util_types::simple_hasher::Hasher,
    };

    use crate::models::blockchain::{digest::DEVNET_MSG_DIGEST_SIZE_IN_BYTES, shared::Hash};

    use super::*;

    #[test]
    fn new_random_wallet_base_test() {
        let network = Network::Testnet;
        let secret = generate_secret_key();
        let wallet_state = WalletState::new_from_wallet(Wallet::new(secret), network);
        let pk = wallet_state.get_public_key();
        let msg_vec: Vec<BFieldElement> = wallet_state.wallet.secret.values().to_vec();
        let digest_vec: Vec<BFieldElement> = Hash::new().hash(&msg_vec, RP_DEFAULT_OUTPUT_SIZE);
        let digest: Digest = digest_vec.into();
        let msg_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = digest.into();
        let msg = secp256k1::Message::from_slice(&msg_bytes).unwrap();
        let signature = wallet_state._sign(msg);
        assert!(
            signature.verify(&msg, &pk).is_ok(),
            "DEVNET signature must verify"
        );

        let signature_alt = wallet_state.sign_digest(digest);
        assert!(
            signature_alt.verify(&msg, &pk).is_ok(),
            "DEVNET signature must verify"
        );
    }
}
