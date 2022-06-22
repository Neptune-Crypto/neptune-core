use core::time;
use std::iter;

use secp256k1::ecdsa;
use serde::{Deserialize, Serialize};
use twenty_first::{
    amount::u32s::U32s,
    shared_math::b_field_element::BFieldElement,
    util_types::{
        mutator_set::{
            removal_record::RemovalRecord, transfer_ms_membership_proof::TransferMsMembershipProof,
        },
        simple_hasher::Hasher,
    },
};

use super::{
    digest::{Digest, Hashable, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES},
    shared::Hash,
};

pub const AMOUNT_SIZE_FOR_U32: usize = 4;
pub const PUBLIC_KEY_LENGTH_IN_BYTES: usize = 33;
pub const PUBLIC_KEY_LENGTH_IN_BFES: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    pub amount: U32s<AMOUNT_SIZE_FOR_U32>,
    pub public_key: secp256k1::PublicKey,
}

impl Utxo {
    fn accumulate(&self) -> Vec<BFieldElement> {
        let amount_bfes: [BFieldElement; AMOUNT_SIZE_FOR_U32] = self.amount.into();
        let bytes: [u8; PUBLIC_KEY_LENGTH_IN_BYTES] = self.public_key.serialize();
        let pk_bfes: [BFieldElement; PUBLIC_KEY_LENGTH_IN_BFES] =
            BFieldElement::from_byte_array(bytes).try_into().unwrap();
        vec![amount_bfes.to_vec(), pk_bfes.to_vec()].concat()
    }
}

impl Hashable for Utxo {
    fn hash(&self) -> Digest {
        let hasher = Hash::new();
        Digest::new(
            hasher
                .hash(&self.accumulate(), RESCUE_PRIME_OUTPUT_SIZE_IN_BFES)
                .try_into()
                .unwrap(),
        )
    }
}

pub struct DevNetInput {
    pub utxo: Utxo,
    pub membership_proof: TransferMsMembershipProof<Hash>,
    pub removal_record: RemovalRecord<Hash>,
    pub signature: ecdsa::Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub inputs: Vec<(Utxo, TransferMsMembershipProof<Hash>, RemovalRecord<Hash>)>,
    pub outputs: Vec<Utxo>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: U32s<AMOUNT_SIZE_FOR_U32>,
    pub timestamp: BFieldElement,
}

pub struct TransactionKernel {
    pub input_utxos: Vec<Utxo>,
    pub output_utxos: Vec<Utxo>,
    pub public_scripts: Vec<Vec<BFieldElement>>,
    pub fee: U32s<AMOUNT_SIZE_FOR_U32>,
    pub timestamp: BFieldElement,
}

impl Hashable for TransactionKernel {
    fn hash(&self) -> Digest {
        todo!()
        // let mut leafs: Vec<RescuePrimeDigest> = vec![];
        // leafs.push(MerkleTree::root_from_arbitrary_number_of_digests(
        //     self.input_utxos
        //         .iter()
        //         .map(|i| i.hash())
        //         .collect()
        //         .try_into()
        //         .unwrap(),
        // ));
        // leafs.push(MerkleTree::root_from_arbitrary_number_of_digests(
        //     self.output_utxos
        //         .iter()
        //         .map(|i| i.hash())
        //         .collect()
        //         .try_into()
        //         .unwrap(),
        // ));
        // leafs.push(MerkleTree::root_from_arbitrary_number_of_digests(
        //     self.public_scripts.iter().map(|i| i.hash()).collect(),
        // ));
        // leafs.push(fee.hash());
        // leafs.push(time.hash());

        // MerkleTree::root_from_arbitrary_number_of_digests(&leafs)
    }
}

impl Hashable for Transaction {
    fn hash(&self) -> Digest {
        // TODO: This digest definition should be reworked
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
            inputs_preimage.push(input.0.hash().into());
            // We don't hash the membership proofs as they aren't part of the main net blocks
            inputs_preimage.push(input.2.hash());
        }
        let inputs_digest = hasher.hash_many(&inputs_preimage);

        // Hash fee
        let fee_bfes: [BFieldElement; AMOUNT_SIZE_FOR_U32] = self.fee.into();
        let fee_digest = hasher.hash(&fee_bfes, RESCUE_PRIME_OUTPUT_SIZE_IN_BFES);

        // Hash timestamp
        let timestamp_digest = hasher.hash(&[self.timestamp], RESCUE_PRIME_OUTPUT_SIZE_IN_BFES);

        // Hash public_scripts
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
            input_utxos: self.inputs.iter().map(|inp| inp.0.to_owned()).collect(),
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

        // 2. signatures
        //  - for all inputs
        //    -- signature is valid: on kernel (= (input utxos, output utxos, public scripts, fee, timestamp)); under public key

        todo!()
    }
}
