use anyhow::bail;
use anyhow::Result;
use num_traits::One;
use num_traits::Zero;
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, fips202::shake256, lattice, tip5::Digest},
    util_types::algebraic_hasher::{AlgebraicHasher, Hashable},
};

use crate::models::blockchain::shared::Hash;

pub const GENERATION_FLAG: BFieldElement = BFieldElement::new(79);

pub struct SpendingKey {
    pub receiver_identifier: BFieldElement,
    decryption_key: lattice::kem::SecretKey,
    receiver_preimage: Digest,
}

pub struct ReceivingAddress {
    pub receiver_identifier: BFieldElement,
    encryption_key: lattice::kem::PublicKey,
    receiver_digest: Digest,
}

pub fn public_script_is_marked(public_script: &[BFieldElement]) -> bool {
    const OPCODE_FOR_HALT: BFieldElement = BFieldElement::zero();
    match public_script.get(0) {
        Some(&OPCODE_FOR_HALT) => match public_script.get(1) {
            Some(&GENERATION_FLAG) => true,
            Some(_) => false,
            None => false,
        },
        Some(_) => false,
        None => false,
    }
}

pub fn receiver_identifier_from_public_script(
    public_script: &[BFieldElement],
) -> Result<BFieldElement> {
    match public_script.get(2) {
        Some(id) => Ok(*id),
        None => bail!("Public script does not contain receiver ID"),
    }
}

impl SpendingKey {
    pub fn derive_from_seed(seed: &Digest) -> Self {
        let receiver_preimage =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::zero()]].concat());
        let randomness: [u8; 32] = shake256(&bincode::serialize(seed).unwrap(), 32)
            .try_into()
            .unwrap();
        let (sk, pk) = lattice::kem::keygen(randomness);
        let receiver_identifier =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::one()]].concat()).values()
                [0];

        Self {
            receiver_identifier,
            decryption_key: sk,
            receiver_preimage,
        }
    }
}

impl ReceivingAddress {
    pub fn derive_from_seed(seed: &Digest) -> Self {
        let receiver_preimage =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::zero()]].concat());
        let receiver_digest = Hash::hash(&receiver_preimage);
        let randomness: [u8; 32] = shake256(&bincode::serialize(seed).unwrap(), 32)
            .try_into()
            .unwrap();
        let (sk, pk) = lattice::kem::keygen(randomness);
        let receiver_identifier =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::one()]].concat()).values()
                [0];

        Self {
            receiver_identifier,
            encryption_key: pk,
            receiver_digest,
        }
    }
}
