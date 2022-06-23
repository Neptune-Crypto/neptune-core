pub mod devnet_input;
pub mod transaction_kernel;
pub mod utxo;

use num_traits::Zero;
use secp256k1::Message;
use serde::{Deserialize, Serialize};
use twenty_first::{
    amount::u32s::U32s, shared_math::b_field_element::BFieldElement,
    util_types::simple_hasher::Hasher,
};

use self::{devnet_input::DevNetInput, transaction_kernel::TransactionKernel, utxo::Utxo};
use super::{
    digest::{Digest, Hashable, DEVNET_SIGNATURE_SIZE_IN_BYTES, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    shared::Hash,
};

pub const AMOUNT_SIZE_FOR_U32: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub inputs: Vec<DevNetInput>,
    pub outputs: Vec<Utxo>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: U32s<AMOUNT_SIZE_FOR_U32>,
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
            .map(|output| output.hash().into())
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
    fn get_kernel(&self) -> TransactionKernel {
        TransactionKernel {
            fee: self.fee,
            input_utxos: self.inputs.iter().map(|inp| inp.utxo.to_owned()).collect(),
            output_utxos: self.outputs.clone(),
            public_scripts: self.public_scripts.clone(),
            timestamp: self.timestamp,
        }
    }

    pub fn devnet_is_valid(&self, coinbase_amount: Option<U32s<AMOUNT_SIZE_FOR_U32>>) -> bool {
        // What belongs here are the things that would otherwise
        // be verified by the transaction validity proof.

        // Membership proofs and removal records are checked by caller, don't check here.

        // 1. UTXO: sum(inputs) + coinbase_amount >= fee + sum(outputs)
        let mut spendable_amount: U32s<AMOUNT_SIZE_FOR_U32> =
            self.inputs.iter().map(|input| input.utxo.amount).sum();
        spendable_amount = spendable_amount
            + match coinbase_amount {
                None => U32s::zero(),
                Some(amount) => amount,
            };

        let output_amount = self.fee + self.outputs.iter().map(|utxo| utxo.amount).sum();

        if output_amount > spendable_amount {
            return false;
        }

        // 2. signatures
        //  - for all inputs
        //    -- signature is valid: on kernel (= (input utxos, output utxos, public scripts, fee, timestamp)); under public key
        let kernel: TransactionKernel = self.get_kernel();
        let kernel_digest: Digest = kernel.hash();
        let kernel_digest_as_bytes: [u8; DEVNET_SIGNATURE_SIZE_IN_BYTES] = kernel_digest.into();
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
}
