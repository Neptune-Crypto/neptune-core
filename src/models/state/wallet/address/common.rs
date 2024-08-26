use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::prelude::triton_vm;
use crate::prelude::twenty_first;
use anyhow::bail;
use anyhow::Result;
use itertools::Itertools;
use sha3::digest::ExtendableOutput;
use sha3::digest::Update;
use sha3::Shake256;
use triton_vm::triton_asm;
use triton_vm::triton_instr;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::tip5::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

/// Derive a receiver id from a seed.
pub fn derive_receiver_id(seed: Digest) -> BFieldElement {
    Hash::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(2)]].concat()).values()[0]
}

/// retrieves key-type field from a [PublicAnnouncement]
///
/// returns an error if the field is not present
pub fn key_type_from_public_announcement(
    announcement: &PublicAnnouncement,
) -> Result<BFieldElement> {
    match announcement.message.first() {
        Some(key_type) => Ok(*key_type),
        None => bail!("Public announcement does not contain key type."),
    }
}

/// retrieves ciphertext field from a [PublicAnnouncement]
///
/// returns an error if the input is too short
pub fn ciphertext_from_public_announcement(
    announcement: &PublicAnnouncement,
) -> Result<Vec<BFieldElement>> {
    if announcement.message.len() <= 2 {
        bail!("Public announcement does not contain ciphertext.");
    }
    Ok(announcement.message[2..].to_vec())
}

/// retrieves receiver identifier field from a [PublicAnnouncement]
///
/// returns an error if the input is too short
pub fn receiver_identifier_from_public_announcement(
    announcement: &PublicAnnouncement,
) -> Result<BFieldElement> {
    match announcement.message.get(1) {
        Some(id) => Ok(*id),
        None => bail!("Public announcement does not contain receiver ID"),
    }
}

/// Encodes a slice of bytes to a vec of BFieldElements. This
/// encoding is injective but not uniform-to-uniform.
pub fn bytes_to_bfes(bytes: &[u8]) -> Vec<BFieldElement> {
    let mut padded_bytes = bytes.to_vec();
    while padded_bytes.len() % 8 != 0 {
        padded_bytes.push(0u8);
    }
    let mut bfes = vec![BFieldElement::new(bytes.len() as u64)];
    for chunk in padded_bytes.chunks(8) {
        let ch: [u8; 8] = chunk.try_into().unwrap();
        let int = u64::from_be_bytes(ch);
        if int < BFieldElement::P - 1 {
            bfes.push(BFieldElement::new(int));
        } else {
            let rem = int & 0xffffffff;
            bfes.push(BFieldElement::new(BFieldElement::P - 1));
            bfes.push(BFieldElement::new(rem));
        }
    }
    bfes
}

/// Decodes a slice of BFieldElements to a vec of bytes. This method
/// computes the inverse of `bytes_to_bfes`.
pub fn bfes_to_bytes(bfes: &[BFieldElement]) -> Result<Vec<u8>> {
    if bfes.is_empty() {
        bail!("Cannot decode empty byte stream");
    }

    let length = bfes[0].value() as usize;
    if length > std::mem::size_of_val(bfes) {
        bail!("Cannot decode byte stream shorter than length indicated. BFE slice length: {}, indicated byte stream length: {length}", bfes.len());
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(length);
    let mut skip_top = false;
    for bfe in bfes.iter().skip(1) {
        let bfe_bytes = bfe.value().to_be_bytes();
        if skip_top {
            bytes.append(&mut bfe_bytes[4..8].to_vec());
            skip_top = false;
        } else {
            bytes.append(&mut bfe_bytes[0..4].to_vec());
            if bfe_bytes[0..4] == [0xff, 0xff, 0xff, 0xff] {
                skip_top = true;
            } else {
                bytes.append(&mut bfe_bytes[4..8].to_vec());
            }
        }
    }

    Ok(bytes[0..length].to_vec())
}

// note: copied from twenty_first::math::lattice::kem::shake256()
//       which is not public
pub fn shake256<const NUM_OUT_BYTES: usize>(randomness: impl AsRef<[u8]>) -> [u8; NUM_OUT_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(randomness.as_ref());

    let mut result = [0u8; NUM_OUT_BYTES];
    hasher.finalize_xof_into(&mut result);
    result
}

/// generates a lock script from the spending lock.
///
/// Satisfaction of this lock script establishes the UTXO owner's assent to
/// the transaction.
pub fn lock_script(spending_lock: Digest) -> LockScript {
    let push_spending_lock_digest_to_stack = spending_lock
        .values()
        .iter()
        .rev()
        .map(|elem| triton_instr!(push elem.value()))
        .collect_vec();

    let instructions = triton_asm!(
        divine 5
        hash
        {&push_spending_lock_digest_to_stack}
        assert_vector
        read_io 5
        halt
    );

    instructions.into()
}

/// returns human-readable-prefix for the given network
pub fn network_hrp_char(network: Network) -> char {
    match network {
        Network::Alpha | Network::Beta | Network::Main => 'm',
        Network::Testnet => 't',
        Network::Regtest => 'r',
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;

    use rand::thread_rng;
    use rand::Rng;
    use rand::RngCore;
    use tasm_lib::DIGEST_LENGTH;

    #[test]
    fn test_conversion_fixed_length() {
        let mut rng = thread_rng();
        const N: usize = 23;
        let byte_array: [u8; N] = rng.gen();
        let byte_vec = byte_array.to_vec();
        let bfes = bytes_to_bfes(&byte_vec);
        let bytes_again = bfes_to_bytes(&bfes).unwrap();

        assert_eq!(byte_vec, bytes_again);
    }

    #[test]
    fn test_conversion_variable_length() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let n: usize = rng.gen_range(0..101);
            let mut byte_vec: Vec<u8> = vec![0; n];
            rng.try_fill_bytes(&mut byte_vec).unwrap();
            let bfes = bytes_to_bfes(&byte_vec);
            let bytes_again = bfes_to_bytes(&bfes).unwrap();

            assert_eq!(byte_vec, bytes_again);
        }
    }

    #[test]
    fn test_conversion_cornercases() {
        for test_case in [
            vec![],
            vec![0u8],
            vec![0u8, 0u8],
            vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
            vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
            vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
            vec![1u8],
            0xffffffff00000000u64.to_be_bytes().to_vec(),
            0xffffffff00000001u64.to_be_bytes().to_vec(),
            0xffffffff00000123u64.to_be_bytes().to_vec(),
            0xffffffffffffffffu64.to_be_bytes().to_vec(),
            [
                0xffffffffffffffffu64.to_be_bytes().to_vec(),
                0xffffffffffffffffu64.to_be_bytes().to_vec(),
            ]
            .concat(),
        ] {
            let bfes = bytes_to_bfes(&test_case);
            let bytes_again = bfes_to_bytes(&bfes).unwrap();

            assert_eq!(test_case, bytes_again);
        }
    }

    /// Verify the UTXO owner's assent to the transaction.
    /// This is the rust reference implementation, but the version of
    /// this logic that is proven is `lock_script`.
    ///
    /// This function mocks proof verification.
    pub fn std_lockscript_reference_verify_unlock(
        spending_lock: Digest,
        _bind_to: Digest,
        witness_data: [BFieldElement; DIGEST_LENGTH],
    ) -> bool {
        spending_lock == Digest::new(witness_data).hash::<Hash>()
    }

    /// Unlock the UTXO binding it to some transaction by its kernel hash.
    /// This function mocks proof generation.
    pub fn binding_unlock(unlock_key: Digest, _bind_to: Digest) -> [BFieldElement; DIGEST_LENGTH] {
        let witness_data = unlock_key;
        witness_data.values()
    }
}
