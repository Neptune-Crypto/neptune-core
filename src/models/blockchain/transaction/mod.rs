pub mod devnet_input;
pub mod transaction_kernel;
pub mod utxo;

use get_size::GetSize;
use num_bigint::{BigInt, BigUint};
use num_rational::BigRational;
use num_traits::Zero;
use secp256k1::{ecdsa, Message, PublicKey};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    hash::{Hash as StdHash, Hasher as StdHasher},
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::warn;
use twenty_first::{
    amount::u32s::U32s, shared_math::b_field_element::BFieldElement,
    util_types::simple_hasher::Hasher,
};

use self::{devnet_input::DevNetInput, transaction_kernel::TransactionKernel, utxo::Utxo};
use super::{
    digest::{Digest, Hashable, DEVNET_MSG_DIGEST_SIZE_IN_BYTES, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    shared::Hash,
    wallet::Wallet,
};

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

impl Hashable for Transaction {
    fn hash(&self) -> Digest {
        // TODO: Consider using a Merkle tree construction here instead
        let hasher = Hash::new();

        // Hash outputs
        let outputs_preimage: Vec<Vec<BFieldElement>> = self
            .outputs
            .iter()
            .map(|(output_utxo, _)| <Utxo as Hashable>::hash(output_utxo).into())
            .collect();
        let outputs_digest = hasher.hash_many(&outputs_preimage);

        // Hash inputs
        let mut inputs_preimage: Vec<Vec<BFieldElement>> = vec![];
        for input in self.inputs.iter() {
            inputs_preimage.push(<Utxo as Hashable>::hash(&input.utxo).into());
            // We don't hash the membership proofs as they aren't part of the main net blocks
            inputs_preimage.push(input.removal_record.hash());
        }
        let inputs_digest = hasher.hash_many(&inputs_preimage);

        // Hash fee
        let fee_bfes: [BFieldElement; AMOUNT_SIZE_FOR_U32] = self.fee.into();
        let fee_digest = hasher.hash(&fee_bfes, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES);

        // Hash timestamp
        let timestamp_digest = hasher.hash(&[self.timestamp], RESCUE_PRIME_OUTPUT_SIZE_IN_BFES);

        // Hash public_scripts
        // If public scripts are not padded or end with a specific instruction, then it might
        // be possible to find a collission for this digest. If that's the case, each public script
        // can be padded with a B field element that's not a valid VM instruction.
        let flatted_public_scripts: Vec<BFieldElement> = self.public_scripts.concat();
        let public_scripts_digest =
            hasher.hash(&flatted_public_scripts, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES);

        let all_digests = vec![
            inputs_digest,
            outputs_digest,
            fee_digest,
            timestamp_digest,
            public_scripts_digest,
        ]
        .concat();

        Digest::new(
            hasher
                .hash(&all_digests, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES)
                .try_into()
                .unwrap(),
        )
    }
}

/// Make `Transaction` hashable with `StdHash` for using it in `HashMap`.
#[allow(clippy::derive_hash_xor_eq)]
impl StdHash for Transaction {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let our_hash = <Transaction as Hashable>::hash(self);
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

    pub fn get_own_output_utxos(&self, pub_key: PublicKey) -> Vec<(Utxo, Digest)> {
        self.outputs
            .iter()
            .filter(|(utxo, _randomness)| utxo.public_key == pub_key)
            .copied()
            .collect::<Vec<(Utxo, Digest)>>()
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
        let kernel_digest: Digest = kernel.hash();
        let signature = wallet.sign_digest(kernel_digest);
        for input in self.inputs.iter_mut() {
            input.signature = signature;
        }
    }

    /// Perform a devnet authority signature on a `Transaction`
    ///
    /// This is a placeholder for STARK proofs, since merged
    /// transactions will have invalid input signatures with the
    /// current signature scheme.
    pub fn devnet_authority_sign(&mut self) {
        let kernel: TransactionKernel = self.get_kernel();
        let kernel_digest: Digest = kernel.hash();
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
        let kernel_digest: Digest = kernel.hash();
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
            if input
                .signature
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
    use crate::tests::shared::{
        make_mock_transaction, make_mock_unsigned_devnet_input, new_random_wallet,
    };
    use rand::thread_rng;
    use tracing_test::traced_test;
    use twenty_first::shared_math::traits::GetRandomElements;

    #[traced_test]
    #[test]
    fn merged_transaction_is_devnet_valid_test() {
        let mut rng = thread_rng();
        let wallet_1 = new_random_wallet();
        let output_amount_1: Amount = 42.into();
        let output_1 = Utxo {
            amount: output_amount_1,
            public_key: wallet_1.get_public_key(),
        };
        let randomness: Digest =
            BFieldElement::random_elements(RESCUE_PRIME_OUTPUT_SIZE_IN_BFES, &mut rng).into();

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
        let kernel_digest: Digest = kernel.hash();
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
}
