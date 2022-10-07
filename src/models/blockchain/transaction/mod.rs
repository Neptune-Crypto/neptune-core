pub mod devnet_input;
pub mod transaction_kernel;
pub mod utxo;

use anyhow::{bail, Result};
use get_size::GetSize;
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::{
    addition_record::AdditionRecord, ms_membership_proof::MsMembershipProof,
    mutator_set_accumulator::MutatorSetAccumulator, mutator_set_trait::MutatorSet,
    removal_record::RemovalRecord,
};
use num_bigint::{BigInt, BigUint};
use num_rational::BigRational;
use num_traits::Zero;
use secp256k1::{ecdsa, Message, PublicKey};
use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn};
use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::simple_hasher::Hashable;
use twenty_first::util_types::simple_hasher::Hasher;

use self::{devnet_input::DevNetInput, transaction_kernel::TransactionKernel, utxo::Utxo};
use super::block::Block;
use super::digest::{Digest, Hashable2, DEVNET_MSG_DIGEST_SIZE_IN_BYTES};
use super::shared::Hash;
use crate::models::state::wallet::Wallet;

pub const AMOUNT_SIZE_FOR_U32: usize = 4;
pub type Amount = U32s<AMOUNT_SIZE_FOR_U32>;
pub type TransactionDigest = Digest;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub inputs: Vec<DevNetInput>,

    // In `outputs`, element 0 is the UTXO, element 1 is the randomness that goes into the mutator set
    pub outputs: Vec<(Utxo, Digest)>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: Amount,
    pub timestamp: BFieldElement,
    pub authority_proof: Option<ecdsa::Signature>,
}

impl GetSize for Transaction {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        // TODO:  This is wrong and `GetSize` needs to be implemeted recursively.
        42
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl Hashable2 for Transaction {
    fn neptune_hash(&self) -> Digest {
        let hasher = Hash::new();

        // Hash outputs
        let outputs_preimage: Vec<BFieldElement> = self
            .outputs
            .iter()
            .flat_map(|(output_utxo, _)| Utxo::neptune_hash(output_utxo).values())
            .collect();

        // Hash inputs
        let inputs_preimage: Vec<BFieldElement> = self
            .inputs
            .iter()
            .flat_map(|input| input.utxo.neptune_hash().values())
            .collect();

        // Hash fee
        let fee_preimage: Vec<BFieldElement> = self.fee.to_sequence();

        // Hash timestamp
        let timestamp_preimage = vec![self.timestamp];

        // Hash public_scripts
        // If public scripts are not padded or end with a specific instruction, then it might
        // be possible to find a collission for this digest. If that's the case, each public script
        // can be padded with a B field element that's not a valid VM instruction.
        let public_scripts_preimage: Vec<BFieldElement> = self.public_scripts.concat();

        let all_digests = vec![
            inputs_preimage,
            outputs_preimage,
            fee_preimage,
            timestamp_preimage,
            public_scripts_preimage,
        ]
        .concat();

        Digest::new(hasher.hash_sequence(&all_digests))
    }
}

/// Make `Transaction` hashable with `StdHash` for using it in `HashMap`.
#[allow(clippy::derive_hash_xor_eq)]
impl StdHash for Transaction {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let our_hash = Transaction::neptune_hash(self);
        <Digest as StdHash>::hash(&our_hash, state);
    }
}

impl Transaction {
    pub fn get_input_utxos(&self) -> Vec<Utxo> {
        self.inputs.iter().map(|dni| dni.utxo).collect()
    }

    pub fn get_own_input_utxos(&self, pub_key: PublicKey) -> Vec<Utxo> {
        self.inputs
            .iter()
            .map(|dni| dni.utxo)
            .filter(|utxo| utxo.public_key == pub_key)
            .collect()
    }

    pub fn get_own_output_utxos_and_comrands(&self, pub_key: PublicKey) -> Vec<(Utxo, Digest)> {
        self.outputs
            .iter()
            .filter(|(utxo, _randomness)| utxo.public_key == pub_key)
            .copied()
            .collect::<Vec<(Utxo, Digest)>>()
    }

    /// Update mutator set data for a transaction to update its validity for a new block
    /// Note that this will invalidate the signature, meaning that the authority signatures
    /// have to be updated. This is true as long as the membership proofs and removal records
    /// are part of the transaction signature preimage
    pub fn update_ms_data(&mut self, block: &Block) -> Result<()> {
        let mut transaction_membership_proofs: Vec<MsMembershipProof<Hash>> = self
            .inputs
            .iter()
            .map(|x| x.membership_proof.clone().into())
            .collect();
        let mut transaction_membership_proofs: Vec<&mut MsMembershipProof<Hash>> =
            transaction_membership_proofs.iter_mut().collect();
        let transaction_items: Vec<Digest> =
            self.inputs.iter().map(|x| x.utxo.neptune_hash()).collect();

        let mut msa_state: MutatorSetAccumulator<Hash> =
            block.body.previous_mutator_set_accumulator.to_owned();
        let block_addition_records: Vec<AdditionRecord<Hash>> =
            block.body.mutator_set_update.additions.clone();
        let mut transaction_removal_records: Vec<RemovalRecord<Hash>> = self
            .inputs
            .iter()
            .map(|x| x.removal_record.clone())
            .collect();
        let mut transaction_removal_records: Vec<&mut RemovalRecord<Hash>> =
            transaction_removal_records.iter_mut().collect();
        let mut block_removal_records = block.body.mutator_set_update.removals.clone();
        block_removal_records.reverse();
        let mut block_removal_records: Vec<&mut RemovalRecord<Hash>> =
            block_removal_records.iter_mut().collect::<Vec<_>>();

        // Apply all addition records in the block
        for mut block_addition_record in block_addition_records {
            // Update all transaction's membership proofs with addition records from block
            let res = MsMembershipProof::batch_update_from_addition(
                &mut transaction_membership_proofs,
                &transaction_items,
                &mut msa_state.set_commitment,
                &block_addition_record,
            );
            if let Err(err) = res {
                error!("{}", err);
                bail!("Failed to update membership proof with addition record");
            };

            // Batch update block's removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(&mut block_removal_records, &mut msa_state)
                .expect("MS removal record update from add must succeed in wallet handler");

            // Batch update transaction's removal records
            RemovalRecord::batch_update_from_addition(
                &mut transaction_removal_records,
                &mut msa_state.set_commitment,
            )
            .expect("MS removal record update from add must succeed in wallet handler");

            msa_state.add(&mut block_addition_record);
        }

        while let Some(removal_record) = block_removal_records.pop() {
            let res = MsMembershipProof::batch_update_from_remove(
                &mut transaction_membership_proofs,
                removal_record,
            );
            if let Err(err) = res {
                error!("{}", err);
                bail!("Failed to update transaction membership proof with removal record");
            };

            // Batch update block's removal records to keep them valid after next removal
            RemovalRecord::batch_update_from_remove(&mut block_removal_records, removal_record)
                .expect("MS removal record update from remove must succeed in wallet handler");

            // batch update transaction's removal records
            // Batch update block's removal records to keep them valid after next removal
            RemovalRecord::batch_update_from_remove(
                &mut transaction_removal_records,
                removal_record,
            )
            .expect("MS removal record update from remove must succeed in wallet handler");

            msa_state.remove(removal_record);
        }

        // Sanity check of block validity
        assert_eq!(
            msa_state.get_commitment(),
            block
                .body
                .next_mutator_set_accumulator
                .clone()
                .get_commitment(),
            "Internal MSA state must match that from block"
        );

        // Write all transaction's membership proofs and removal records back
        for ((tx_input, new_mp), new_rr) in self
            .inputs
            .iter_mut()
            .zip_eq(transaction_membership_proofs.into_iter())
            .zip_eq(transaction_removal_records.into_iter())
        {
            tx_input.membership_proof = new_mp.to_owned().into();
            tx_input.removal_record = new_rr.to_owned();
        }

        Ok(())
    }

    fn get_kernel(&self) -> TransactionKernel {
        TransactionKernel {
            fee: self.fee,
            input_utxos: self.inputs.iter().map(|inp| inp.utxo.to_owned()).collect(),
            output_utxos: self
                .outputs
                .clone()
                .into_iter()
                .map(|(utxo, _)| utxo)
                .collect(),
            public_scripts: self.public_scripts.clone(),
            timestamp: self.timestamp,
        }
    }

    /// Sign all transaction inputs with the same signature
    pub fn sign(&mut self, wallet: &Wallet) {
        let kernel: TransactionKernel = self.get_kernel();
        let kernel_digest: Digest = kernel.neptune_hash();
        let signature = wallet.sign_digest(kernel_digest);
        for input in self.inputs.iter_mut() {
            input.signature = Some(signature);
        }
    }

    /// Perform a devnet authority signature on a `Transaction`
    ///
    /// This is a placeholder for STARK proofs, since merged
    /// transactions will have invalid input signatures with the
    /// current signature scheme.
    pub fn devnet_authority_sign(&mut self) {
        let kernel: TransactionKernel = self.get_kernel();
        let kernel_digest: Digest = kernel.neptune_hash();
        let authority_wallet = Wallet::devnet_authority_wallet();
        let signature = authority_wallet.sign_digest(kernel_digest);

        self.authority_proof = Some(signature)
    }

    /// Validate Transaction according to Devnet definitions.
    ///
    /// When a transaction occurs in a mined block, `coinbase_amount` is
    /// derived from that block. When a transaction is received from a peer,
    /// and is not yet mined, the coinbase amount is None.
    pub fn devnet_is_valid(&self, coinbase_amount: Option<Amount>) -> bool {
        // What belongs here are the things that would otherwise
        // be verified by the transaction validity proof.

        // Membership proofs and removal records are checked by caller, don't check here.

        // 1. Check that Transaction spends at most its input and coinbase
        let sum_inputs: Amount = self.inputs.iter().map(|input| input.utxo.amount).sum();
        let sum_outputs: Amount = self.outputs.iter().map(|(utxo, _)| utxo.amount).sum();
        let spendable_amount = sum_inputs + coinbase_amount.unwrap_or_else(Amount::zero);
        let spent_amount = sum_outputs + self.fee;
        if spent_amount > spendable_amount {
            warn!(
                "Invalid amount: Spent: {:?}, spendable: {:?}",
                spent_amount, spendable_amount
            );
            return false;
        }

        // 2. signatures: either
        //  - the presence of a devnet authority proof validates the transaction
        //  - for all inputs
        //    -- signature is valid: on kernel (= (input utxos, output utxos, public scripts, fee, timestamp)); under public key
        let kernel: TransactionKernel = self.get_kernel();
        let kernel_digest: Digest = kernel.neptune_hash();
        let kernel_digest_as_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = kernel_digest.into();
        let msg: Message = Message::from_slice(&kernel_digest_as_bytes).unwrap();

        if let Some(signature) = self.authority_proof {
            let authority_public_key = Wallet::devnet_authority_wallet().get_public_key();
            let valid: bool = signature.verify(&msg, &authority_public_key).is_ok();
            if !valid {
                warn!("Invalid authority-merge-signature for transaction");
            }

            return valid;
        }

        for input in self.inputs.iter() {
            if input.signature.is_some()
                && input
                    .signature
                    .unwrap()
                    .verify(&msg, &input.utxo.public_key)
                    .is_err()
            {
                warn!("Invalid input-signature for transaction");
                return false;
            }
        }

        true
    }

    pub fn merge_with(self, other: Transaction) -> Transaction {
        let timestamp = BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Timestamping failed")
                .as_secs(),
        );

        // Add this `Transaction`
        let authority_proof = None;

        let mut merged_transaction = Transaction {
            inputs: vec![self.inputs, other.inputs].concat(),
            outputs: vec![self.outputs, other.outputs].concat(),
            public_scripts: vec![self.public_scripts, other.public_scripts].concat(),
            fee: self.fee + other.fee,
            timestamp,
            authority_proof,
        };

        merged_transaction.devnet_authority_sign();
        merged_transaction
    }

    /// Calculates a fraction representing the fee-density, defined as:
    /// `transaction_fee/transaction_size`.
    pub fn fee_density(&self) -> BigRational {
        let transaction_as_bytes = bincode::serialize(&self).unwrap();
        let transaction_size = BigInt::from(transaction_as_bytes.get_size());
        let transaction_fee = BigInt::from(BigUint::from(self.fee));
        BigRational::new_raw(transaction_fee, transaction_size)
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use crate::{
        config_models::network::Network,
        models::state::wallet,
        tests::shared::{
            get_mock_global_state, make_mock_block, make_mock_transaction,
            make_mock_unsigned_devnet_input, new_random_wallet,
        },
    };
    use tracing_test::traced_test;
    use twenty_first::shared_math::other::random_elements_array;

    #[traced_test]
    #[test]
    fn merged_transaction_is_devnet_valid_test() {
        let wallet_1 = new_random_wallet();
        let output_amount_1: Amount = 42.into();
        let output_1 = Utxo {
            amount: output_amount_1,
            public_key: wallet_1.get_public_key(),
        };
        let randomness: Digest = Digest::new(random_elements_array());

        let coinbase_transaction = make_mock_transaction(vec![], vec![(output_1, randomness)]);
        let coinbase_amount = Some(output_amount_1);

        assert!(coinbase_transaction.devnet_is_valid(coinbase_amount));

        let input_1 = make_mock_unsigned_devnet_input(42.into(), &wallet_1);
        let mut transaction_1 = make_mock_transaction(vec![input_1], vec![(output_1, randomness)]);

        assert!(!transaction_1.devnet_is_valid(None));
        transaction_1.sign(&wallet_1);
        assert!(transaction_1.devnet_is_valid(None));

        let input_2 = make_mock_unsigned_devnet_input(42.into(), &wallet_1);
        let mut transaction_2 = make_mock_transaction(vec![input_2], vec![(output_1, randomness)]);

        assert!(!transaction_2.devnet_is_valid(None));
        transaction_2.sign(&wallet_1);
        assert!(transaction_2.devnet_is_valid(None));

        let mut merged_transaction = transaction_1.merge_with(transaction_2);
        assert!(
            merged_transaction.devnet_is_valid(coinbase_amount),
            "Merged transaction must be valid because of authority proof"
        );

        merged_transaction.authority_proof = None;
        assert!(
            !merged_transaction.devnet_is_valid(coinbase_amount),
            "Merged transaction must not be valid without authority proof"
        );

        // Make an authority sign with a wrong secret key and verify failure
        let kernel: TransactionKernel = merged_transaction.get_kernel();
        let kernel_digest: Digest = kernel.neptune_hash();
        let bad_authority_signature = wallet_1.sign_digest(kernel_digest);
        merged_transaction.authority_proof = Some(bad_authority_signature);
        assert!(
            !merged_transaction.devnet_is_valid(coinbase_amount),
            "Merged transaction must not be valid with wrong authority proof"
        );

        // Restore valid proof
        merged_transaction.devnet_authority_sign();
        assert!(
            merged_transaction.devnet_is_valid(coinbase_amount),
            "Merged transaction must be valid because of authority proof, 2"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn transaction_is_valid_after_update_test() -> Result<()> {
        // We need the global state to construct a transaction. This global state
        // has a wallet which receives a premine-UTXO.
        let global_state = get_mock_global_state(Network::Main, 2).await;
        let other_wallet = wallet::Wallet::new(wallet::generate_secret_key());

        // Create a transaction that's valid after the Genesis block
        let new_utxo = Utxo {
            amount: 5.into(),
            public_key: other_wallet.get_public_key(),
        };
        let mut updated_tx = global_state
            .create_transaction(vec![new_utxo])
            .await
            .unwrap();

        let genesis_block = Block::genesis_block();
        let block_1 = make_mock_block(&genesis_block, None, other_wallet.get_public_key());
        assert!(
            block_1.devnet_is_valid(&genesis_block),
            "Block 1 must be valid with only coinbase output"
        );

        updated_tx.update_ms_data(&block_1)?;

        // Insert the updated transaction into block 2 and verify that this block is valid
        let mut block_2 = make_mock_block(&block_1, None, other_wallet.get_public_key());
        block_2.authority_merge_transaction(updated_tx.clone());
        assert!(block_2.devnet_is_valid(&block_1));

        // Mine 26 blocks, keep the transaction updated, and verify that it is valid after
        // all blocks
        let mut next_block = block_1.clone();
        let mut _previous_block = next_block.clone();
        for _ in 0..26 {
            _previous_block = next_block;
            next_block = make_mock_block(&_previous_block, None, other_wallet.get_public_key());
            updated_tx.update_ms_data(&next_block)?;
        }

        _previous_block = next_block.clone();
        next_block = make_mock_block(&next_block, None, other_wallet.get_public_key());
        next_block.authority_merge_transaction(updated_tx.clone());
        assert!(next_block.devnet_is_valid(&_previous_block));

        Ok(())
    }
}
