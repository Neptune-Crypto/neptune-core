pub mod devnet_input;
pub mod transaction_kernel;
pub mod utxo;

use secp256k1::{Message, PublicKey};
use serde::{Deserialize, Serialize};
use twenty_first::{
    amount::u32s::U32s, shared_math::b_field_element::BFieldElement,
    util_types::simple_hasher::Hasher,
};

use self::{devnet_input::DevNetInput, transaction_kernel::TransactionKernel, utxo::Utxo};
use super::{
    digest::{Digest, Hashable, DEVNET_MSG_DIGEST_SIZE_IN_BYTES, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    shared::Hash,
    wallet::WalletState,
};

pub const AMOUNT_SIZE_FOR_U32: usize = 4;
pub type Amount = U32s<AMOUNT_SIZE_FOR_U32>;
pub type TransactionId = Digest;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub inputs: Vec<DevNetInput>,

    // In `outputs`, element 0 is the UTXO, element 1 is the randomness that goes into the mutator set
    pub outputs: Vec<(Utxo, Digest)>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: Amount,
    pub timestamp: BFieldElement,
}

impl Hashable for Transaction {
    fn hash(&self) -> Digest {
        // TODO: Consider using a Merkle tree construction here instead
        let hasher = Hash::new();

        // Hash outputs
        let outputs_preimage: Vec<Vec<BFieldElement>> = self
            .outputs
            .iter()
            .map(|(output_utxo, _)| output_utxo.hash().into())
            .collect();
        let outputs_digest = hasher.hash_many(&outputs_preimage);

        // Hash inputs
        let mut inputs_preimage: Vec<Vec<BFieldElement>> = vec![];
        for input in self.inputs.iter() {
            inputs_preimage.push(input.utxo.hash().into());
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

impl Transaction {
    pub fn get_input_utxos_with_pub_key(&self, pub_key: PublicKey) -> Vec<Utxo> {
        self.inputs
            .iter()
            .map(|dni| dni.utxo)
            .filter(|utxo| utxo.public_key == pub_key)
            .collect::<Vec<_>>()
    }

    pub fn get_output_utxos_with_pub_key(&self, pub_key: PublicKey) -> Vec<(Utxo, Digest)> {
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
    pub fn sign(&mut self, wallet_state: &WalletState) {
        let kernel: TransactionKernel = self.get_kernel();
        let kernel_digest: Digest = kernel.hash();
        let signature = wallet_state.wallet.sign_digest(kernel_digest);
        for input in self.inputs.iter_mut() {
            input.signature = signature;
        }
    }

    /// Validate Transaction according to Devnet definitions.
    pub fn devnet_is_valid(&self, coinbase_amount: Amount) -> bool {
        // What belongs here are the things that would otherwise
        // be verified by the transaction validity proof.

        // Membership proofs and removal records are checked by caller, don't check here.

        // 1. Check that Transaction spends at most its input and coinbase
        let sum_inputs: Amount = self.inputs.iter().map(|input| input.utxo.amount).sum();
        let sum_outputs: Amount = self.outputs.iter().map(|(utxo, _)| utxo.amount).sum();
        let spendable_amount = sum_inputs + coinbase_amount;
        let spent_amount = sum_outputs + self.fee;
        if spent_amount > spendable_amount {
            return false;
        }

        // 2. signatures
        //  - for all inputs
        //    -- signature is valid: on kernel (= (input utxos, output utxos, public scripts, fee, timestamp)); under public key
        let kernel: TransactionKernel = self.get_kernel();
        let kernel_digest: Digest = kernel.hash();
        let kernel_digest_as_bytes: [u8; DEVNET_MSG_DIGEST_SIZE_IN_BYTES] = kernel_digest.into();
        for input in self.inputs.iter() {
            let msg: Message = Message::from_slice(&kernel_digest_as_bytes).unwrap();
            if input
                .signature
                .verify(&msg, &input.utxo.public_key)
                .is_err()
            {
                return false;
            }
        }

        true
    }

    pub fn merge_transaction(
        _coinbase_transaction: &Transaction,
        _incoming_transactions: &Transaction,
    ) -> Transaction {
        todo!()
    }
}
