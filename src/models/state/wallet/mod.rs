pub mod wallet_block_utxos;
pub mod wallet_status;

use anyhow::{bail, Result};
use itertools::Itertools;
use num_traits::{One, Zero};
use secp256k1::{ecdsa, Secp256k1};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, info, warn};
use twenty_first::shared_math::other::random_elements_array;

use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use mutator_set_tf::util_types::mutator_set::removal_record::RemovalRecord;

use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::rescue_prime_regular::DIGEST_LENGTH;
use twenty_first::util_types::simple_hasher::Hasher;

use crate::config_models::data_directory::get_data_directory;
use crate::config_models::network::Network;
use crate::database::leveldb::LevelDB;
use crate::database::rusty::RustyLevelDB;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::digest::{
    Digest, Hashable2, DEVNET_MSG_DIGEST_SIZE_IN_BYTES, DEVNET_SECRET_KEY_SIZE_IN_BYTES,
};
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::{Amount, Transaction};
use crate::models::database::{MonitoredUtxo, WalletDbKey, WalletDbValue};
use crate::models::state::wallet::wallet_block_utxos::WalletBlockUtxos;
use crate::Hash;

use self::wallet_block_utxos::WalletBlockIOSums;
use self::wallet_status::{WalletStatus, WalletStatusElement};

const WALLET_FILE_NAME: &str = "wallet.dat";
const STANDARD_WALLET_NAME: &str = "standard_wallet";
const STANDARD_WALLET_VERSION: u8 = 0;
const WALLET_DB_NAME: &str = "wallet_block_db";
const WALLET_OUTPUT_COUNT_DB_NAME: &str = "wallout_output_count_db";

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
        let signature_secret_key_marker = Digest::default().values();
        Digest::new(Hash::new().hash_pair(&secret_seed.values(), &signature_secret_key_marker))
    }

    /// Return the secret key that is used to deterministically generate commitment pseudo-randomness
    /// for the mutator set.
    fn get_commitment_randomness_seed(&self) -> Digest {
        let secret_seed = self.secret_seed;
        let mut commitment_marker = Digest::default().values();
        commitment_marker[0] = BFieldElement::one();
        Digest::new(Hash::new().hash_pair(&secret_seed.values(), &commitment_marker))
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

    pub wallet_db: Arc<TokioMutex<RustyLevelDB<WalletDbKey, WalletDbValue>>>,
    pub wallet: Wallet,
}

impl WalletState {
    pub async fn new_from_wallet(wallet: Wallet, network: Network) -> Self {
        // Create or connect to wallet block DB
        let wallet_db: RustyLevelDB<WalletDbKey, WalletDbValue> =
            RustyLevelDB::<WalletDbKey, WalletDbValue>::new(
                get_data_directory(network).unwrap(),
                WALLET_DB_NAME,
                rusty_leveldb::Options::default(),
            )
            .unwrap();
        let wallet_db = Arc::new(TokioMutex::new(wallet_db));

        // Create or connect to DB for output count
        let outgoing_utxo_count_db: RustyLevelDB<(), u128> = RustyLevelDB::<(), u128>::new(
            get_data_directory(network).unwrap(),
            WALLET_OUTPUT_COUNT_DB_NAME,
            rusty_leveldb::Options::default(),
        )
        .unwrap();
        let outgoing_utxo_counter_db = Arc::new(TokioMutex::new(outgoing_utxo_count_db));

        let ret = Self {
            outgoing_utxo_counter_db,
            wallet_db: wallet_db.clone(),
            wallet,
        };

        // Wallet state has to be initialized with the genesis block, otherwise the outputs
        // from it would be unspendable. This should only be done *once* though
        let mut wallet_db_lock = wallet_db.lock().await;
        if wallet_db_lock.get(WalletDbKey::SyncDigest).is_none() {
            ret.update_wallet_state_with_new_block(&Block::genesis_block(), &mut wallet_db_lock)
                .expect("Updating wallet state with genesis block must succeed");
        }

        ret
    }
}

impl WalletState {
    pub fn update_wallet_state_with_new_block(
        &self,
        block: &Block,
        wallet_db_lock: &mut tokio::sync::MutexGuard<RustyLevelDB<WalletDbKey, WalletDbValue>>,
    ) -> Result<()> {
        // A transaction contains a set of input and output UTXOs,
        // each of which contains an address (public key),

        let transaction: Transaction = block.body.transaction.clone();

        let my_pub_key = self.wallet.get_public_key();

        let input_utxos: Vec<Utxo> = transaction.get_own_input_utxos(my_pub_key);

        let output_utxos_commitment_randomness: Vec<(Utxo, Digest)> =
            transaction.get_own_output_utxos_and_comrands(my_pub_key);

        // Derive the membership proofs for new input UTXOs, *and* in the process update existing membership
        // proofs with updates from this block
        let mut monitored_utxos: Vec<MonitoredUtxo> = wallet_db_lock
            .get(WalletDbKey::MonitoredUtxos)
            .map(|x| x.as_monitored_utxos())
            .unwrap_or_default();

        // Let's not store the UTXOs of blocks that don't affect our balance
        if input_utxos.is_empty()
            && output_utxos_commitment_randomness.is_empty()
            && monitored_utxos.is_empty()
        {
            return Ok(());
        }

        let next_block_of_relevant_utxos =
            WalletBlockUtxos::new(input_utxos, output_utxos_commitment_randomness);

        let mut new_wallet_db_values: Vec<(WalletDbKey, WalletDbValue)> = vec![(
            WalletDbKey::WalletBlockUtxos(block.hash),
            WalletDbValue::WalletBlockUtxos(next_block_of_relevant_utxos),
        )];

        // Find the versions of the membership proofs that are from the latest block
        let mut own_membership_proofs: Vec<MsMembershipProof<Hash>> = vec![];
        let mut own_items_as_digests: Vec<Digest> = vec![];
        for mut monitored_utxo in monitored_utxos.iter_mut() {
            let relevant_membership_proof: Option<MsMembershipProof<Hash>> =
                monitored_utxo.get_membership_proof_for_block(&block.header.prev_block_digest);
            match relevant_membership_proof {
                Some(ms_mp) => {
                    debug!("Found valid mp for UTXO");
                    own_membership_proofs.push(ms_mp.to_owned());
                    own_items_as_digests.push(monitored_utxo.utxo.neptune_hash());
                    monitored_utxo.has_synced_membership_proof = true;
                }
                None => {
                    warn!(
                        "Unable to find membership proof for UTXO with digest {}",
                        monitored_utxo.utxo.neptune_hash()
                    );
                    monitored_utxo.has_synced_membership_proof = false;
                }
            }
        }

        // Loop over all input UTXOs, applying all addition records
        let mut changed_mps = vec![];
        let mut msa_state: MutatorSetAccumulator<Hash> =
            block.body.previous_mutator_set_accumulator.to_owned();
        let mut removal_records = block.body.mutator_set_update.removals.clone();
        removal_records.reverse();
        let mut removal_records: Vec<&mut RemovalRecord<Hash>> =
            removal_records.iter_mut().collect::<Vec<_>>();
        for (mut addition_record, (utxo, commitment_randomness)) in block
            .body
            .mutator_set_update
            .additions
            .clone()
            .into_iter()
            .zip_eq(block.body.transaction.outputs.clone().into_iter())
        {
            let res: Result<Vec<usize>, Box<dyn Error>> =
                MsMembershipProof::batch_update_from_addition(
                    &mut own_membership_proofs.iter_mut().collect::<Vec<_>>(),
                    &own_items_as_digests
                        .iter()
                        .map(|digest| digest.values())
                        .collect::<Vec<_>>(),
                    &mut msa_state.set_commitment,
                    &addition_record,
                );
            match res {
                Ok(mut indices_of_mutated_mps) => changed_mps.append(&mut indices_of_mutated_mps),
                Err(_) => bail!("Failed to update membership proofs with addition record"),
            };

            // Batch update removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(
                &mut removal_records,
                &mut msa_state.set_commitment,
            )
            .expect("MS removal record update from add must succeed in wallet handler");

            // If output UTXO belongs to us, add it to the list of monitored UTXOs and
            // add its membership proof to the list of managed membership proofs.
            if utxo.matches_pubkey(self.wallet.get_public_key()) {
                // TODO: Change this logging to use `Display` for `Amount` once functionality is merged from t-f
                info!(
                    "Received UTXO in block {}, height {}: value = {:?}",
                    block.hash, block.header.height, utxo.amount
                );
                let new_own_membership_proof = msa_state.prove(
                    &utxo.neptune_hash().values(),
                    &commitment_randomness.values(),
                    true,
                );

                own_membership_proofs.push(new_own_membership_proof);
                own_items_as_digests.push(utxo.neptune_hash());

                // In case of forks, it can happen that a UTXO is dropped from the abandoned chain
                // but exists in the new chain. If that's the case, then the membership proof was marked
                // as invalid above, but the membership proof in scope here is actually its real
                // membership proof. We fix this problem by deleting the old entry for monitored UTXO
                // (if it exists) and then just add the new one.
                let mut new_monitored_utxo = MonitoredUtxo::new(utxo);
                let forked_utxo_match = monitored_utxos
                    .iter()
                    .find_position(|x| !x.has_synced_membership_proof && x.utxo == utxo);
                if let Some((index_of_forked_utxo, forked_utxo)) = forked_utxo_match {
                    // If this is a forked UTXO (removed in abandoned chain, added in this)
                    // then we make sure to both remove the old entry from the `monitored_utxos`
                    // list *but* preserve the membership proofs associated with this old entry
                    // since we might have to fork back to this chain that is being abandoned.
                    // We remove the old entry since we are adding a new entry immediately
                    // below this if-block and we don't want to include this monitored UTXO twice.
                    info!(
                        "Own UTXO {} repeated in forked chain, recovering.",
                        forked_utxo.utxo.neptune_hash()
                    );
                    new_monitored_utxo = monitored_utxos.remove(index_of_forked_utxo);
                    new_monitored_utxo.has_synced_membership_proof = true;
                }

                monitored_utxos.push(new_monitored_utxo);
            }

            // Update mutator set to bring it to the correct state for the next call to batch-update
            msa_state.add(&mut addition_record);
        }

        // sanity checks
        assert_eq!(
            monitored_utxos
                .iter()
                .filter(|x| x.has_synced_membership_proof)
                .count(),
            own_membership_proofs.len(),
            "Monitored UTXO count must match number of managed membership proofs"
        );
        assert_eq!(
            own_membership_proofs.len(),
            own_items_as_digests.len(),
            "Number of managed membership proofs must match number of own items"
        );

        // Loop over all output UTXOs, applying all removal records
        debug!("Block has {} removal records", removal_records.len());
        debug!(
            "Transaction has {} inputs",
            block.body.transaction.inputs.len()
        );
        let mut i = 0;
        while let Some(removal_record) = removal_records.pop() {
            let res = MsMembershipProof::batch_update_from_remove(
                &mut own_membership_proofs.iter_mut().collect::<Vec<_>>(),
                removal_record,
            );
            match res {
                Ok(mut indices_of_mutated_mps) => changed_mps.append(&mut indices_of_mutated_mps),
                Err(_) => bail!("Failed to update membership proofs with removal record"),
            };

            // Batch update removal records to keep them valid after next removal
            RemovalRecord::batch_update_from_remove(&mut removal_records, removal_record)
                .expect("MS removal record update from remove must succeed in wallet handler");

            // TODO: We mark membership proofs as spent, so they can be deleted. But
            // how do we ensure that we can recover them in case of a fork? For now we maintain
            // them even if the are spent, and then, later, we can add logic to remove these
            // membership proofs of spent UTXOs once they have been spent for M blocks.
            let input_utxo = block.body.transaction.inputs[i].utxo;
            if input_utxo.matches_pubkey(my_pub_key) {
                debug!(
                    "Discovered own input at input {}, marking UTXO as spent.",
                    i
                );

                let mut matching_utxos: Vec<&mut MonitoredUtxo> = monitored_utxos
                    .iter_mut()
                    .filter(|x| x.utxo.neptune_hash() == input_utxo.neptune_hash())
                    .collect();
                match matching_utxos.len() {
                    0 => panic!(
                        "Discovered own input UTXO in block that did not match a monitored UTXO"
                    ),
                    1 => {
                        matching_utxos[0].spent_in_block =
                            Some((block.hash, block.header.height, block.header.timestamp));
                    }
                    _n => {
                        // If we are monitoring multiple UTXOs with the same hash, we need another
                        // method to mark the correct UTXO as spent. In DevNet we use the membership
                        // proof from the block for this. In MainNet, where the input membership
                        // proofs are not included in the blocks, we can probably just check which
                        // of our own membership proofs that have become invalid with this block.
                        let matching_match = matching_utxos
                            .iter_mut()
                            .find(|x| {
                                x.get_membership_proof_for_block(&block.header.prev_block_digest)
                                    .unwrap()
                                    .auth_path_aocl
                                    .data_index
                                    == block.body.transaction.inputs[i]
                                        .membership_proof
                                        .auth_path_aocl
                                        .data_index
                            })
                            .unwrap();
                        matching_match.spent_in_block =
                            Some((block.hash, block.header.height, block.header.timestamp));
                    }
                }
            }

            msa_state.remove(removal_record);
            i += 1;
        }

        // Sanity check that `msa_state` agrees with the mutator set from the applied block
        assert_eq!(
            block
                .body
                .next_mutator_set_accumulator
                .clone()
                .get_commitment(),
            msa_state.get_commitment(),
            "Mutator set in wallet-handler must agree with that from applied block"
        );

        changed_mps.sort();
        changed_mps.dedup();
        debug!("Number of mutated membership proofs: {}", changed_mps.len());
        debug!(
            "Number of unspent membership proofs: {}",
            monitored_utxos
                .iter()
                .filter(|x| x.spent_in_block.is_none())
                .count()
        );

        for (monitored_utxo, updated_mp) in monitored_utxos
            .iter_mut()
            .filter(|x| x.has_synced_membership_proof)
            .zip_eq(own_membership_proofs)
        {
            // Sanity check that all membership proofs are valid for the next mutator set defined
            // by this block
            assert!(
                monitored_utxo.spent_in_block.is_some()
                    || msa_state.verify(&monitored_utxo.utxo.neptune_hash().values(), &updated_mp),
                "{}",
                format!(
                    "Updated membership proof for unspent UTXO must be valid. Invalid: {:?}",
                    monitored_utxo
                )
            );

            // Add the new membership proof to the list of membership proofs for this UTXO
            monitored_utxo.add_membership_proof_for_tip(block.hash, updated_mp);
        }

        new_wallet_db_values.push((
            WalletDbKey::MonitoredUtxos,
            WalletDbValue::MonitoredUtxos(monitored_utxos),
        ));

        // Push block hash for which wallet has been updated
        new_wallet_db_values.push((
            WalletDbKey::SyncDigest,
            WalletDbValue::SyncDigest(block.hash),
        ));

        wallet_db_lock.batch_write(&new_wallet_db_values);

        Ok(())
    }

    fn get_monitored_utxos_with_lock(
        &self,
        lock: &mut RustyLevelDB<WalletDbKey, WalletDbValue>,
    ) -> Vec<MonitoredUtxo> {
        lock.get(WalletDbKey::MonitoredUtxos)
            .map(|x| x.as_monitored_utxos())
            .unwrap_or_default()
    }

    // Blocking call to get the monitored UTXOs.
    pub async fn get_monitored_utxos(&self) -> Vec<MonitoredUtxo> {
        let mut lock = self.wallet_db.lock().await;
        self.get_monitored_utxos_with_lock(&mut lock)
    }

    pub async fn get_balance(&self) -> Amount {
        let sums: WalletBlockIOSums = self
            .wallet_db
            .lock()
            .await
            .new_iter()
            .filter(|(_key, value)| value.is_wallet_block_utxos())
            .map(|(_key, value)| value.as_wallet_block_utxos())
            .map(|wallet_block| wallet_block.get_io_sums())
            .reduce(|a, b| a + b)
            .unwrap_or_default();
        sums.output_sum - sums.input_sum
    }

    fn get_wallet_status_with_lock(
        &self,
        lock: &mut RustyLevelDB<WalletDbKey, WalletDbValue>,
    ) -> WalletStatus {
        let m_utxos = self.get_monitored_utxos_with_lock(lock);
        let synced_unspent: Vec<(WalletStatusElement, MsMembershipProof<Hash>)> = m_utxos
            .iter()
            .filter(|x| x.spent_in_block.is_none() && x.has_synced_membership_proof)
            .map(|x| {
                let ms_mp = x.get_latest_membership_proof();
                (
                    WalletStatusElement(ms_mp.auth_path_aocl.data_index, x.utxo),
                    ms_mp,
                )
            })
            .collect();
        let unsynced_unspent: Vec<WalletStatusElement> = m_utxos
            .iter()
            .filter(|x| x.spent_in_block.is_none() && !x.has_synced_membership_proof)
            .map(|x| {
                WalletStatusElement(
                    x.get_latest_membership_proof().auth_path_aocl.data_index,
                    x.utxo,
                )
            })
            .collect();
        let synced_spent: Vec<WalletStatusElement> = m_utxos
            .iter()
            .filter(|x| x.spent_in_block.is_some() && x.has_synced_membership_proof)
            .map(|x| {
                WalletStatusElement(
                    x.get_latest_membership_proof().auth_path_aocl.data_index,
                    x.utxo,
                )
            })
            .collect();
        let unsynced_spent: Vec<WalletStatusElement> = m_utxos
            .iter()
            .filter(|x| x.spent_in_block.is_some() && !x.has_synced_membership_proof)
            .map(|x| {
                WalletStatusElement(
                    x.get_latest_membership_proof().auth_path_aocl.data_index,
                    x.utxo,
                )
            })
            .collect();
        WalletStatus {
            synced_unspent_amount: synced_unspent.iter().map(|x| x.0 .1.amount).sum(),
            synced_unspent,
            unsynced_unspent_amount: unsynced_unspent.iter().map(|x| x.1.amount).sum(),
            unsynced_unspent,
            synced_spent_amount: synced_spent.iter().map(|x| x.1.amount).sum(),
            synced_spent,
            unsynced_spent_amount: unsynced_spent.iter().map(|x| x.1.amount).sum(),
            unsynced_spent,
        }
    }

    pub async fn get_wallet_status(&self) -> WalletStatus {
        let mut lock = self.wallet_db.lock().await;
        self.get_wallet_status_with_lock(&mut lock)
    }

    #[allow(dead_code)]
    async fn forget_block(&self, block_hash: Digest) {
        self.wallet_db
            .lock()
            .await
            .delete(WalletDbKey::WalletBlockUtxos(block_hash));
    }

    /// Fetch the output counter from the database and increase the counter by one
    async fn next_output_counter(&self) -> u128 {
        let mut outgoing_utxo_counter_lock = self.outgoing_utxo_counter_db.lock().await;
        let current_counter: u128 = outgoing_utxo_counter_lock.get(()).unwrap_or_default();
        outgoing_utxo_counter_lock.put((), current_counter + 1);

        current_counter
    }

    /// Get the randomness for the next output UTXO and increment the output counter by one
    pub async fn next_output_randomness(&self) -> Digest {
        let counter = self.next_output_counter().await;

        // TODO: Ugly hack used to generate a `Digest` from a `u128` here.
        // Once we've updated to twenty-first 0.2.0 or later use its `to_sequence` instead.
        let mut counter_as_digest: Vec<BFieldElement> = vec![BFieldElement::zero(); DIGEST_LENGTH];
        counter_as_digest[0] = BFieldElement::new(counter as u64);
        let counter_as_digest: Digest = counter_as_digest.try_into().unwrap();
        let commitment_pseudo_randomness_seed = self.wallet.get_commitment_randomness_seed();

        Digest::new(Hash::new().hash_pair(
            &counter_as_digest.values(),
            &commitment_pseudo_randomness_seed.values(),
        ))
    }

    pub fn allocate_sufficient_input_funds_with_lock(
        &self,
        lock: &mut RustyLevelDB<WalletDbKey, WalletDbValue>,
        requested_amount: Amount,
    ) -> Result<Vec<(Utxo, MsMembershipProof<Hash>)>> {
        // We only attempt to generate a transaction using those UTXOs that have up-to-date
        // membership proofs.
        let wallet_status: WalletStatus = self.get_wallet_status_with_lock(lock);

        // First check that we have enough. Otherwise return an error.
        if wallet_status.synced_unspent_amount < requested_amount {
            // TODO: Change this to `Display` print once available.
            bail!("Insufficient synced amount to create transaction. Requested: {:?}, synced available amount: {:?}", requested_amount, wallet_status.synced_unspent_amount);
        }

        let mut ret: Vec<(Utxo, MsMembershipProof<Hash>)> = vec![];
        let mut allocated_amount = Amount::zero();
        while allocated_amount < requested_amount {
            let next_elem = wallet_status.synced_unspent[ret.len()].clone();
            allocated_amount = allocated_amount + next_elem.0 .1.amount;
            ret.push((next_elem.0 .1, next_elem.1));
        }

        Ok(ret)
    }

    // Allocate sufficient UTXOs to generate a transaction. `amount` must include fees that are
    // paid in the transaction.
    pub async fn allocate_sufficient_input_funds(
        &self,
        requested_amount: Amount,
    ) -> Result<Vec<(Utxo, MsMembershipProof<Hash>)>> {
        let mut lock = self.wallet_db.lock().await;
        self.allocate_sufficient_input_funds_with_lock(&mut lock, requested_amount)
    }
}

#[cfg(test)]
mod wallet_tests {
    use super::*;
    use crate::{
        models::{
            blockchain::{
                block::block_height::BlockHeight, digest::DEVNET_MSG_DIGEST_SIZE_IN_BYTES,
                shared::Hash,
            },
            state::archival_state::ArchivalState,
        },
        tests::shared::{
            add_output_to_block, add_unsigned_input_to_block, add_unsigned_input_to_block_ams,
            get_mock_wallet_state, make_mock_block, make_unit_test_archival_state,
        },
    };
    use num_traits::One;
    use tracing_test::traced_test;
    use twenty_first::util_types::simple_hasher::Hasher;

    #[tokio::test]
    async fn increase_output_counter_test() {
        // Verify that output counter is incremented when the counter value is fetched
        let wallet_state = get_mock_wallet_state(None).await;
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
        assert!(
            next_block.body.next_mutator_set_accumulator.verify(
                &genesis_block.body.transaction.outputs[0]
                    .0
                    .neptune_hash()
                    .values(),
                &monitored_utxos[0]
                    .get_membership_proof_for_block(&next_block.hash)
                    .unwrap()
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
        assert!(block_1.body.next_mutator_set_accumulator.verify(
            &block_1.body.transaction.outputs[0]
                .0
                .neptune_hash()
                .values(),
            &monitored_utxos[0]
                .get_membership_proof_for_block(&block_1.hash)
                .unwrap()
        ));

        // Create new blocks, verify that the membership proofs are *not* valid
        // under this block as tip
        let block_2 = make_mock_block(&block_1, None, other_wallet.get_public_key());
        let mut block_3 = make_mock_block(&block_2, None, other_wallet.get_public_key());
        monitored_utxos = wallet_state.get_monitored_utxos().await;
        assert!(
            !block_3.body.next_mutator_set_accumulator.verify(
                &block_1.body.transaction.outputs[0]
                    .0
                    .neptune_hash()
                    .values(),
                &monitored_utxos[0]
                    .get_membership_proof_for_block(&block_1.hash)
                    .unwrap()
            ),
            "membership proof must be invalid before updating wallet state"
        );

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
        assert!(
            block_3.body.next_mutator_set_accumulator.verify(
                &block_1.body.transaction.outputs[0]
                    .0
                    .neptune_hash()
                    .values(),
                &monitored_utxos[0]
                    .get_membership_proof_for_block(&block_3.hash)
                    .unwrap()
            ),
            "Membership proof must be valid after updating wallet state with generated blocks"
        );

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
        let archival_state: ArchivalState = make_unit_test_archival_state().await;
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
        assert!(block_1.devnet_is_valid(&genesis_block));

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
                    &monitored_utxo.utxo.neptune_hash().values(),
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
                    &monitored_utxo.utxo.neptune_hash().values(),
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
                    &monitored_utxo.utxo.neptune_hash().values(),
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
            .filter(|x| x.has_synced_membership_proof)
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
                    &monitored_utxo.utxo.neptune_hash().values(),
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
        let forked_utxo: Utxo = Utxo::new(
            Amount::one()
                + Amount::one()
                + Amount::one()
                + Amount::one()
                + Amount::one()
                + Amount::one(),
            own_wallet_state.wallet.get_public_key(),
        );
        add_output_to_block(&mut block_3_b, forked_utxo);
        block_3_b.body.transaction.sign(&own_wallet_state.wallet);
        assert!(block_3_b.devnet_is_valid(&block_2_b));
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
                        &monitored_utxo.utxo.neptune_hash().values(),
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
                        &monitored_utxo.utxo.neptune_hash().values(),
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
                .filter(|x| x.utxo.neptune_hash() == forked_utxo.neptune_hash())
                .count()
        );

        // Verify that we have two membership proofs for forked UTXO
        let forked_utxo_info: MonitoredUtxo = monitored_utxos_20
            .into_iter()
            .find(|x| x.utxo.neptune_hash() == forked_utxo.neptune_hash())
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
        let digest: Digest = Digest::new(Hash::new().hash_sequence(&msg_vec));
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
