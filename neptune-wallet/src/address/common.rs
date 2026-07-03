use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use neptune_consensus::network::Network;
use neptune_consensus::transaction::announcement::Announcement;
use sha3::digest::ExtendableOutput;
use sha3::digest::Update;
use sha3::Shake256;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::utxo_notification::UtxoNotificationPayload;

/// returns human-readable-prefix for the given network
pub fn network_hrp_char(network: Network) -> char {
    match network {
        Network::Main => 'm',
        Network::Testnet(_) => 't',
        Network::TestnetMock => 'z',
        Network::RegTest => 'r',
        // `Network` is `#[non_exhaustive]`; this arm is unreachable for all
        // currently defined variants.
        _ => unreachable!("unhandled network variant"),
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
///
/// It's important that the *entire* payload is used here. As repeated
/// nonce/secret keys in two different UTXOs are only acceptable when the
/// plaintext ([UtxoNotificationPayload]) is also repeated. In other words: If
/// this function could give the same result for two different payloads, then
/// the secret key/nonce could be repeated for two different plaintexts, and
/// that would leak the secret key through the so-called "forbidden attack".
pub fn deterministically_derive_seed_and_nonce(
    payload: &UtxoNotificationPayload,
) -> ([u8; 32], BFieldElement) {
    let combined = Tip5::hash_pair(payload.sender_randomness, Tip5::hash(&payload.utxo));
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
///
/// Fails if the number of bytes exceed 8*10^6.
pub fn bfes_to_bytes(bfes: &[BFieldElement]) -> Result<Vec<u8>> {
    const MAX_DECODED_LENGTH: usize = BFieldElement::BYTES * 1_000_000;
    ensure!(!bfes.is_empty(), "Cannot decode empty byte stream");

    let claimed_length = bfes[0].value() as usize;
    ensure!(
        claimed_length <= size_of_val(bfes),
        "Cannot decode byte stream shorter than length indicated. \
        BFE slice length: {}, indicated byte stream length: {claimed_length}",
        bfes.len(),
    );

    ensure!(
        claimed_length <= MAX_DECODED_LENGTH,
        "Claimed length must not exceed {MAX_DECODED_LENGTH}"
    );

    let mut bytes: Vec<u8> = Vec::with_capacity(claimed_length);
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

    ensure!(
        claimed_length <= bytes.len(),
        "Claimed length cannot exceed actual length when decoding bytes"
    );

    Ok(bytes[0..claimed_length].to_vec())
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
    use neptune_consensus::transaction::utxo::Utxo;
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
    fn no_crash_empty_bfes() {
        let _res = bfes_to_bytes(&[]);
    }

    #[test]
    fn no_crash_in_bfes_to_bytes() {
        for claimed_length in 0..20 {
            for payload_length in 0..12 {
                let byte_vec = vec![0; payload_length];
                let mut bfes = bytes_to_bfes(&byte_vec);
                bfes[0] = bfe!(claimed_length);

                // Ensure no crash
                let _res = bfes_to_bytes(&bfes);
            }
        }
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
    fn too_long_msg() {
        let byte_vec: Vec<u8> = vec![0; 10_000_000];
        let bfes = bytes_to_bfes(&byte_vec);
        assert!(
            bfes_to_bytes(&bfes).is_err(),
            "Must fail if trying to decode too many bytes."
        );
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

    #[test]
    fn tripwire_for_deterministic_derivation_fields() {
        // WARNING TO FUTURE DEVELOPERS:
        // If this test fails to compile, it means a field was added to `UtxoNotificationPayload`.
        //
        // You MUST update `deterministically_derive_seed_and_nonce` to include the new field
        // in the Tip5 hash derivation.
        //
        // If a field is added to the payload but omitted from the seed/nonce derivation,
        // two different payloads could generate the exact same AES key and nonce, resulting
        // in a catastrophic failure of the AES-GCM encryption scheme (the "Forbidden Attack").

        // Create a dummy instance. We just need the compiler to see the type.
        let tripwire = UtxoNotificationPayload {
            sender_randomness: Default::default(),
            utxo: Utxo::empty_dummy(),
        };

        // STRICT DESTRUCTURING:
        // Because we do not use `..` at the end of this block, the Rust compiler
        // guarantees that EVERY single field in the struct is explicitly named here.
        // If a 3rd field is added, this will throw a hard compile error:
        // "pattern does not mention field `new_field`"
        let UtxoNotificationPayload {
            sender_randomness: _,
            utxo: _,
        } = tripwire;
    }
}
