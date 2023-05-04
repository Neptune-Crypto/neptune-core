pub mod amount;
pub mod native_coin;
pub mod transaction_kernel;
pub mod utxo;

use anyhow::Result;
use get_size::GetSize;
use itertools::Itertools;
use mutator_set_tf::util_types::mutator_set::mutator_set_kernel::get_swbf_indices;
use num_bigint::{BigInt, BigUint};
use num_rational::BigRational;
use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use std::time::{SystemTime, UNIX_EPOCH};
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};

use mutator_set_tf::util_types::mutator_set::addition_record::AdditionRecord;
use mutator_set_tf::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use mutator_set_tf::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use mutator_set_tf::util_types::mutator_set::mutator_set_trait::MutatorSet;
use mutator_set_tf::util_types::mutator_set::removal_record::RemovalRecord;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::rescue_prime_digest::Digest;

use self::amount::Amount;
use self::native_coin::native_coin_typescript;
use self::transaction_kernel::TransactionKernel;
use self::utxo::Utxo;
use super::address::generation_address;
use super::block::Block;
use super::shared::Hash;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof(pub Vec<BFieldElement>);

impl Hashable for Proof {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        self.0.clone()
    }
}

/// The raw witness is the most primitive type of transaction witness.
/// It exposes secret data and is therefore not for broadcasting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrimitiveWitness {
    pub input_utxos: Vec<Utxo>,
    pub lock_script_witnesses: Vec<Vec<BFieldElement>>,
    pub input_membership_proofs: Vec<MsMembershipProof<Hash>>,
    pub output_utxos: Vec<Utxo>,
    pub pubscripts: Vec<Vec<BFieldElement>>,
}

/// Linked proofs are one abstraction level above raw witness. They
/// hide secrets and can therefore be broadcast securely. Some
/// information is still leaked though, such as the number of inputs
/// and outputs, and number of type scripts, but this information
/// cannot be used to spend someone else's coins.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkedProofs {
    lock_script_proofs: Vec<Proof>,
    lock_script_hashes: Vec<Digest>,
    index_proofs: Vec<Proof>,
    type_script_proofs: Vec<Proof>,
    type_script_hashes: Vec<Digest>,
    lock_script_extraction_proof: Proof,
    type_script_extraction_proof: Proof,
    pubscript_proofs: Vec<Proof>,
}

/// Single proofs are the final abstaction layer for transaction
/// witnesses. It represents the merger of a set of linked proofs
/// into one. It hides information that linked proofs expose, but
/// the downside is that it requires multiple runs of the recursive
/// prover to produce.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleProof(pub Proof);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Witness {
    Primitive(PrimitiveWitness),
    LinkedProofs(LinkedProofs),
    SingleProof(SingleProof),
    Faith,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub kernel: TransactionKernel,

    pub witness: Witness,
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

impl Hashable for Transaction {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        let inputs_preimage = self
            .kernel
            .inputs
            .iter()
            .flat_map(|input| input.to_sequence());

        let outputs_preimage = self
            .kernel
            .outputs
            .iter()
            .flat_map(|output| output.to_sequence());

        // If public scripts are not padded or end with a specific instruction, then it might
        // be possible to find a collission for this digest. If that's the case, each public script
        // can be padded with a B field element that's not a valid VM instruction.
        let public_scripts_preimage = self
            .kernel
            .pubscript_hashes_and_inputs
            .iter()
            .flat_map(|(psh, psi)| [psh.to_sequence(), psi.to_vec()].concat());
        let fee_preimage = self.kernel.fee.to_sequence().into_iter();
        let timestamp_preimage = vec![self.kernel.timestamp].into_iter();

        inputs_preimage
            .chain(outputs_preimage)
            .chain(public_scripts_preimage)
            .chain(fee_preimage)
            .chain(timestamp_preimage)
            .collect_vec()
    }
}

/// Make `Transaction` hashable with `StdHash` for using it in `HashMap`.
///
/// The Clippy warning is safe to suppress, because we do not violate the invariant: k1 == k2 => hash(k1) == hash(k2).
#[allow(clippy::derived_hash_with_manual_eq)]
impl StdHash for Transaction {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let neptune_hash = Hash::hash(self);
        StdHash::hash(&neptune_hash, state);
    }
}

impl Transaction {
    // pub fn get_own_input_utxos(&self, pub_key: PublicKey) -> Vec<Utxo> {
    //     self.inputs
    //         .iter()
    //         .map(|dni| dni.utxo)
    //         .filter(|utxo| utxo.public_key == pub_key)
    //         .collect()
    // }

    /// Update mutator set data in a transaction to update its
    /// compatibility with a new block. Note that this will
    /// invalidate the proof, requiring an update.
    pub fn update_mutator_set_data(&mut self, block: &Block) -> Result<()> {
        let mut msa_state: MutatorSetAccumulator<Hash> =
            block.body.previous_mutator_set_accumulator.to_owned();
        let block_addition_records: Vec<AdditionRecord> =
            block.body.transaction.kernel.outputs.clone();
        let mut transaction_removal_records: Vec<RemovalRecord<Hash>> = self.kernel.inputs.clone();
        let mut transaction_removal_records: Vec<&mut RemovalRecord<Hash>> =
            transaction_removal_records.iter_mut().collect();
        let mut block_removal_records = block.body.transaction.kernel.inputs.clone();
        block_removal_records.reverse();
        let mut block_removal_records: Vec<&mut RemovalRecord<Hash>> =
            block_removal_records.iter_mut().collect::<Vec<_>>();

        // Apply all addition records in the block
        for block_addition_record in block_addition_records {
            // Batch update block's removal records to keep them valid after next addition
            RemovalRecord::batch_update_from_addition(
                &mut block_removal_records,
                &mut msa_state.kernel,
            )
            .expect("MS removal record update from add must succeed in wallet handler");

            // Batch update transaction's removal records
            RemovalRecord::batch_update_from_addition(
                &mut transaction_removal_records,
                &mut msa_state.kernel,
            )
            .expect("MS removal record update from add must succeed in wallet handler");

            msa_state.add(&block_addition_record);
        }

        while let Some(removal_record) = block_removal_records.pop() {
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
            msa_state.hash(),
            block.body.next_mutator_set_accumulator.clone().hash(),
            "Internal MSA state must match that from block"
        );

        // Write all transaction's membership proofs and removal records back
        for (tx_input, new_rr) in self
            .kernel
            .inputs
            .iter_mut()
            .zip_eq(transaction_removal_records.into_iter())
        {
            *tx_input = new_rr.to_owned();
        }

        Ok(())
    }

    /// Validate Transaction
    ///
    /// This method tests the transaction's internal consistency in
    /// isolation, without the context of the canonical chain.
    ///
    /// When a transaction occurs in a mined block, `coinbase_amount` is
    /// derived from that block. When a transaction is received from a peer,
    /// and is not yet mined, the coinbase amount is None.
    pub fn is_valid(&self, coinbase_amount: Option<Amount>) -> bool {
        match &self.witness {
            Witness::Primitive(primitive_witness) => {
                // verify lock scripts
                for (input_utxo, secret_input) in primitive_witness
                    .input_utxos
                    .iter()
                    .zip(primitive_witness.lock_script_witnesses.iter())
                {
                    let program = input_utxo.lock_script.clone();
                    let std_input = Hash::hash(&self.kernel).to_sequence();
                    let std_output: Vec<BFieldElement> = vec![];
                    // verify (program, std_input, secret_input, std_output)
                }

                // verify removal records
                for ((input_utxo, msmp), removal_record) in primitive_witness
                    .input_utxos
                    .iter()
                    .zip(primitive_witness.input_membership_proofs.iter())
                    .zip(self.kernel.inputs.iter())
                {
                    let item = Hash::hash(input_utxo);
                    let indices = get_swbf_indices::<Hash>(
                        &item,
                        &msmp.sender_randomness,
                        &msmp.receiver_preimage,
                        msmp.auth_path_aocl.leaf_index,
                    );

                    if removal_record.absolute_indices.to_array() != indices {
                        return false;
                    }
                }

                // verify type scripts
                for output_utxo in primitive_witness.output_utxos.iter() {
                    for (type_script_hash, _state) in output_utxo.coins.iter() {
                        let type_script = native_coin_typescript();

                        // verify H(type_script) == type_script_hash

                        let program = type_script;
                        let input = Hash::hash(&self.kernel);
                        let output: Vec<BFieldElement> = vec![];
                        let secret_input = output_utxo
                            .coins
                            .iter()
                            .find(|(d, s)| *d == *type_script_hash)
                            .unwrap()
                            .to_owned();

                        // verify
                        // (program, input, secret_input, output)
                    }
                }

                // verify pubscripts
                for ((pubscript_hash, pubscript_input), pubscript) in self
                    .kernel
                    .pubscript_hashes_and_inputs
                    .iter()
                    .zip(primitive_witness.pubscripts.iter())
                {
                    if *pubscript_hash != Hash::hash_varlen(&pubscript) {
                        return false;
                    }

                    let program = pubscript;
                    let input = pubscript_input;
                    let secret_input: Vec<BFieldElement> = vec![];
                    let output: Vec<BFieldElement> = vec![];
                    // verify claim (program, standard input, secret_input, standard output)
                }

                true
            }
            Witness::LinkedProofs(_) => true,
            Witness::SingleProof(_) => true,
            Witness::Faith => true,
        }
    }

    /// Merge two transactions. Both input transactions must have a
    /// valid SingleProof witness for this operation to work.
    pub fn merge_with(self, other: Transaction) -> Transaction {
        let timestamp = BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Timestamping failed")
                .as_millis() as u64,
        );

        let merged_kernel = TransactionKernel {
            inputs: vec![self.kernel.inputs, other.kernel.inputs].concat(),
            outputs: vec![self.kernel.outputs, other.kernel.outputs].concat(),
            pubscript_hashes_and_inputs: vec![
                self.kernel.pubscript_hashes_and_inputs,
                other.kernel.pubscript_hashes_and_inputs,
            ]
            .concat(),
            fee: self.kernel.fee + other.kernel.fee,
            timestamp,
        };

        let mut merged_transaction = Transaction {
            kernel: merged_kernel,
            witness: Witness::SingleProof(SingleProof(Proof(vec![]))),
        };

        merged_transaction
    }

    /// Calculates a fraction representing the fee-density, defined as:
    /// `transaction_fee/transaction_size`.
    pub fn fee_density(&self) -> BigRational {
        let transaction_as_bytes = bincode::serialize(&self).unwrap();
        let transaction_size = BigInt::from(transaction_as_bytes.get_size());
        let transaction_fee = BigInt::from(BigUint::from(self.kernel.fee.0));
        BigRational::new_raw(transaction_fee, transaction_size)
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use crate::{
        config_models::network::Network,
        models::state::wallet::{self, generate_secret_key},
        tests::shared::{get_mock_global_state, new_random_wallet},
    };
    use tracing_test::traced_test;
    use twenty_first::shared_math::other::random_elements_array;

    // #[traced_test]
    // #[test]
    // fn merged_transaction_is_devnet_valid_test() {
    //     let wallet_1 = new_random_wallet();
    //     let output_amount_1: Amount = 42.into();
    //     let output_1 = Utxo {
    //         amount: output_amount_1,
    //         public_key: wallet_1.get_public_key(),
    //     };
    //     let randomness: Digest = Digest::new(random_elements_array());

    //     let coinbase_transaction = make_mock_transaction(vec![], vec![(output_1, randomness)]);
    //     let coinbase_amount = Some(output_amount_1);

    //     assert!(coinbase_transaction.is_valid_for_devnet(coinbase_amount));

    //     let input_1 = make_mock_unsigned_devnet_input(<i32 as Into<Amount>>::into(42), &wallet_1);
    //     let mut transaction_1 = make_mock_transaction(vec![input_1], vec![(output_1, randomness)]);

    //     assert!(!transaction_1.is_valid_for_devnet(None));
    //     transaction_1.sign(&wallet_1);
    //     assert!(transaction_1.is_valid_for_devnet(None));

    //     let input_2 = make_mock_unsigned_devnet_input(42.into(), &wallet_1);
    //     let mut transaction_2 = make_mock_transaction(vec![input_2], vec![(output_1, randomness)]);

    //     assert!(!transaction_2.is_valid_for_devnet(None));
    //     transaction_2.sign(&wallet_1);
    //     assert!(transaction_2.is_valid_for_devnet(None));

    //     let mut merged_transaction = transaction_1.merge_with(transaction_2);
    //     assert!(
    //         merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must be valid because of authority proof"
    //     );

    //     merged_transaction.authority_proof = None;
    //     assert!(
    //         !merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must not be valid without authority proof"
    //     );

    //     // Make an authority sign with a wrong secret key and verify failure
    //     let kernel: TransactionKernel = merged_transaction.get_kernel();
    //     let kernel_digest: Digest = Hash::hash(&kernel);
    //     let bad_authority_signature = wallet_1.sign_digest(kernel_digest);
    //     merged_transaction.authority_proof = Some(bad_authority_signature);
    //     assert!(
    //         !merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must not be valid with wrong authority proof"
    //     );

    //     // Restore valid proof
    //     merged_transaction.devnet_authority_sign();
    //     assert!(
    //         merged_transaction.is_valid_for_devnet(coinbase_amount),
    //         "Merged transaction must be valid because of authority proof, 2"
    //     );
    // }

    // #[traced_test]
    // #[tokio::test]
    // async fn transaction_is_valid_after_block_update_simple_test() -> Result<()> {
    //     // We need the global state to construct a transaction. This global state
    //     // has a wallet which receives a premine-UTXO.
    //     let global_state = get_mock_global_state(Network::Main, 2, None).await;
    //     let other_wallet = wallet::WalletSecret::new(wallet::generate_secret_key());

    //     // Create a transaction that's valid after the Genesis block
    //     let new_utxo = Utxo {
    //         amount: 5.into(),
    //         public_key: other_wallet.get_public_key(),
    //     };
    //     let mut updated_tx = global_state
    //         .create_transaction(vec![new_utxo], 1.into())
    //         .await
    //         .unwrap();

    //     let genesis_block = Block::genesis_block();
    //     let block_1 = make_mock_block(&genesis_block, None, other_wallet.get_public_key());
    //     assert!(
    //         block_1.is_valid_for_devnet(&genesis_block),
    //         "Block 1 must be valid with only coinbase output"
    //     );

    //     updated_tx.update_ms_data(&block_1).unwrap();

    //     // Insert the updated transaction into block 2 and verify that this block is valid
    //     let mut block_2 = make_mock_block(&block_1, None, other_wallet.get_public_key());
    //     block_2.authority_merge_transaction(updated_tx.clone());
    //     assert!(block_2.is_valid_for_devnet(&block_1));

    //     // Mine 26 blocks, keep the transaction updated, and verify that it is valid after
    //     // all blocks
    //     let mut next_block = block_1.clone();
    //     let mut _previous_block = next_block.clone();
    //     for _ in 0..26 {
    //         _previous_block = next_block;
    //         next_block = make_mock_block(&_previous_block, None, other_wallet.get_public_key());
    //         updated_tx.update_ms_data(&next_block).unwrap();
    //     }

    //     _previous_block = next_block.clone();
    //     next_block = make_mock_block(&next_block, None, other_wallet.get_public_key());
    //     next_block.authority_merge_transaction(updated_tx.clone());
    //     assert!(next_block.is_valid_for_devnet(&_previous_block));

    //     Ok(())
    // }

    // #[traced_test]
    // #[tokio::test]
    // async fn transaction_is_valid_after_block_update_multiple_ios_test() -> Result<()> {
    //     // We need the global state to construct a transaction. This global state
    //     // has a wallet which receives a premine-UTXO.
    //     let own_global_state = get_mock_global_state(Network::Main, 2, None).await;
    //     let own_wallet_secret = &own_global_state.wallet_state.wallet_secret;

    //     // Create a transaction that's valid after the Genesis block
    //     let mut output_utxos: Vec<Utxo> = vec![];
    //     for i in 0..7 {
    //         let new_utxo = Utxo {
    //             amount: i.into(),
    //             public_key: own_wallet_secret.get_public_key(),
    //         };
    //         output_utxos.push(new_utxo);
    //     }

    //     // Create a transaction that's valid after genesis block
    //     let mut tx = own_global_state
    //         .create_transaction(output_utxos, 1.into())
    //         .await
    //         .unwrap();
    //     let original_tx = tx.clone();

    //     // Create next block and verify that transaction is not valid with this block as tip
    //     let genesis_block = Block::genesis_block();
    //     let other_wallet = WalletSecret::new(generate_secret_key());
    //     let block_1 = make_mock_block(&genesis_block, None, own_wallet_secret.get_public_key());
    //     let block_2 = make_mock_block(&block_1, None, other_wallet.get_public_key());
    //     assert!(
    //         block_1.is_valid_for_devnet(&genesis_block),
    //         "Block 1 must be valid with only coinbase output"
    //     );
    //     assert!(
    //         block_2.is_valid_for_devnet(&block_1),
    //         "Block 2 must be valid with only coinbase output"
    //     );

    //     let mut block_2_with_deprecated_tx = block_2.clone();
    //     block_2_with_deprecated_tx.authority_merge_transaction(tx.clone());
    //     assert!(
    //         !block_2_with_deprecated_tx.is_valid_for_devnet(&block_1),
    //         "Block with transaction with deprecated mutator set data must be invalid"
    //     );

    //     // Update the transaction with mutator set data from block 1. Verify that this
    //     // gives rise to a valid block.
    //     tx.update_ms_data(&block_1).unwrap();
    //     let mut block_2_with_updated_tx = block_2.clone();
    //     block_2_with_updated_tx.authority_merge_transaction(tx.clone());
    //     assert!(
    //         block_2_with_updated_tx.is_valid_for_devnet(&block_1),
    //         "Block with transaction with updated mutator set data must be valid"
    //     );

    //     // We would like to use more advanced blocks, that have multiple inputs and outputs.
    //     // Problem: If we start making with my own wallet, we consume the same inputs that are
    //     // consumed in `updated_tx`. Solution: Create another global state object, containing
    //     // another wallet, and use this to generate the transactions that go into these
    //     // blocks. This should keep the `updated_tx` valid as its inputs are not being spent.
    //     let other_global_state =
    //         get_mock_global_state(Network::Main, 2, Some(other_wallet.clone())).await;
    //     other_global_state
    //         .wallet_state
    //         .update_wallet_state_with_new_block(
    //             &block_1,
    //             &mut other_global_state.wallet_state.wallet_db.lock().await,
    //         )
    //         .unwrap();
    //     *other_global_state
    //         .chain
    //         .light_state
    //         .latest_block
    //         .lock()
    //         .await = block_1.clone();
    //     other_global_state
    //         .wallet_state
    //         .update_wallet_state_with_new_block(
    //             &block_2,
    //             &mut other_global_state.wallet_state.wallet_db.lock().await,
    //         )
    //         .unwrap();
    //     *other_global_state
    //         .chain
    //         .light_state
    //         .latest_block
    //         .lock()
    //         .await = block_2.clone();
    //     let mut updated_tx = original_tx;
    //     updated_tx.update_ms_data(&block_1).unwrap();
    //     updated_tx.update_ms_data(&block_2).unwrap();

    //     // Mine 12 blocks with non-trivial transactions, keep the transaction updated,
    //     // and verify that it is valid after all blocks.
    //     let mut next_block = block_2.clone();
    //     let mut _previous_block = next_block.clone();
    //     for i in 0..12 {
    //         _previous_block = next_block.clone();
    //         let utxo_a = Utxo {
    //             amount: (3 * i).into(),
    //             public_key: other_wallet.get_public_key(),
    //         };
    //         let utxo_b = Utxo {
    //             amount: (3 * i + 1).into(),
    //             public_key: other_wallet.get_public_key(),
    //         };
    //         let utxo_c = Utxo {
    //             amount: (3 * i + 2).into(),
    //             public_key: other_wallet.get_public_key(),
    //         };
    //         let other_transaction = other_global_state
    //             .create_transaction(vec![utxo_a, utxo_b, utxo_c], 1.into())
    //             .await
    //             .unwrap();
    //         next_block = make_mock_block(&_previous_block, None, other_wallet.get_public_key());

    //         next_block.authority_merge_transaction(other_transaction);
    //         assert!(
    //             next_block.is_valid_for_devnet(&_previous_block),
    //             "Produced block must be valid after merging new transaction"
    //         );

    //         // Update other's global state with this transaction, such that a new transaction
    //         // can be made in the next iteration of the loop.
    //         {
    //             let mut light_state = other_global_state
    //                 .chain
    //                 .light_state
    //                 .latest_block
    //                 .lock()
    //                 .await;
    //             *light_state = next_block.clone();
    //             other_global_state
    //                 .wallet_state
    //                 .update_wallet_state_with_new_block(
    //                     &next_block,
    //                     &mut other_global_state.wallet_state.wallet_db.lock().await,
    //                 )
    //                 .unwrap();
    //         }

    //         // After each new block, "our" transaction is updated with the information
    //         // from that block such that its mutator set data is kept up-to-date.
    //         updated_tx.update_ms_data(&next_block).unwrap();
    //     }

    //     _previous_block = next_block.clone();
    //     next_block = make_mock_block(&next_block, None, other_wallet.get_public_key());
    //     next_block.authority_merge_transaction(updated_tx.clone());
    //     assert!(
    //         next_block.is_valid_for_devnet(&_previous_block),
    //         "Block is valid when merged transaction is updated"
    //     );

    //     Ok(())
    // }
}
