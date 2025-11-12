use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use sha3::digest::ExtendableOutput;
use sha3::digest::Update;
use sha3::Shake256;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

/// returns human-readable-prefix for the given network
pub(crate) fn network_hrp_char(network: Network) -> char {
    match network {
        Network::Main => 'm',
        Network::Testnet(_) => 't',
        Network::TestnetMock => 'z',
        Network::RegTest => 'r',
    }
}

/// Derive a receiver id from a seed.
pub fn derive_receiver_id(seed: Digest) -> BFieldElement {
    Tip5::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(2)]].concat()).values()[0]
}

/// Derive a seed and a nonce deterministically, in order to produce
/// deterministic announcements, since these are needed to be able to
/// reuse proofs for tests. These values are used in the encryption
/// step.
pub fn deterministically_derive_seed_and_nonce(
    payload: &UtxoNotificationPayload,
) -> ([u8; 32], BFieldElement) {
    let combined = Tip5::hash_pair(payload.sender_randomness, payload.utxo.lock_script_hash());
    let [e0, e1, e2, e3, e4] = combined.values();
    let e0: [u8; 8] = e0.into();
    let e1: [u8; 8] = e1.into();
    let e2: [u8; 8] = e2.into();
    let e3: [u8; 8] = e3.into();
    let seed: [u8; 32] = [e0, e1, e2, e3].concat().try_into().unwrap();

    (seed, e4)
}

/// retrieves key-type field from a [Announcement]
///
/// returns an error if the field is not present
pub fn key_type_from_announcement(announcement: &Announcement) -> Result<BFieldElement> {
    match announcement.message.first() {
        Some(key_type) => Ok(*key_type),
        None => bail!("announcement does not contain key type."),
    }
}

/// retrieves ciphertext field from a [Announcement]
///
/// returns an error if the input is too short
pub fn ciphertext_from_announcement(announcement: &Announcement) -> Result<Vec<BFieldElement>> {
    ensure!(
        announcement.message.len() > 2,
        "announcement does not contain ciphertext.",
    );

    Ok(announcement.message[2..].to_vec())
}

/// retrieves receiver identifier field from a [Announcement]
///
/// returns an error if the input is too short
pub fn receiver_identifier_from_announcement(announcement: &Announcement) -> Result<BFieldElement> {
    match announcement.message.get(1) {
        Some(id) => Ok(*id),
        None => bail!("announcement does not contain receiver ID"),
    }
}

/// Encodes a slice of bytes to a vec of BFieldElements. This
/// encoding is injective but not uniform-to-uniform.
pub fn bytes_to_bfes(bytes: &[u8]) -> Vec<BFieldElement> {
    let mut padded_bytes = bytes.to_vec();
    while !padded_bytes.len().is_multiple_of(8) {
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
    ensure!(!bfes.is_empty(), "Cannot decode empty byte stream");

    let length = bfes[0].value() as usize;
    ensure!(
        length <= size_of_val(bfes),
        "Cannot decode byte stream shorter than length indicated. \
        BFE slice length: {}, indicated byte stream length: {length}",
        bfes.len(),
    );

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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use rand::Rng;
    use rand::TryRngCore;

    use super::*;

    #[test]
    fn test_conversion_fixed_length() {
        const N: usize = 23;

        let mut rng = rand::rng();
        let byte_array: [u8; N] = rng.random();
        let byte_vec = byte_array.to_vec();
        let bfes = bytes_to_bfes(&byte_vec);
        let bytes_again = bfes_to_bytes(&bfes).unwrap();

        assert_eq!(byte_vec, bytes_again);
    }

    #[test]
    fn test_conversion_variable_length() {
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let n: usize = rng.random_range(0..101);
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
}
