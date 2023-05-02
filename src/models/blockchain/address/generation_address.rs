use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::bail;
use anyhow::Result;
use itertools::Itertools;
use num_traits::Zero;
use rand::thread_rng;
use rand::Rng;
use twenty_first::shared_math::lattice::kem::CIPHERTEXT_SIZE_IN_BFES;
use twenty_first::shared_math::tip5::DIGEST_LENGTH;
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, fips202::shake256, lattice, tip5::Digest},
    util_types::algebraic_hasher::{AlgebraicHasher, Hashable},
};

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::Transaction;

pub const GENERATION_FLAG: BFieldElement = BFieldElement::new(79);

pub struct SpendingKey {
    pub receiver_identifier: BFieldElement,
    pub decryption_key: lattice::kem::SecretKey,
    pub privacy_preimage: Digest,
    pub unlock_key: Digest,
    pub seed: Digest,
}

pub struct ReceivingAddress {
    pub receiver_identifier: BFieldElement,
    pub encryption_key: lattice::kem::PublicKey,
    pub privacy_digest: Digest,
    pub spending_lock: Digest,
}

fn pubscript_input_is_marked(pubscript_input: &[BFieldElement]) -> bool {
    const OPCODE_FOR_HALT: BFieldElement = BFieldElement::zero();
    match pubscript_input.get(0) {
        Some(&OPCODE_FOR_HALT) => match pubscript_input.get(1) {
            Some(&GENERATION_FLAG) => true,
            Some(_) => false,
            None => false,
        },
        Some(_) => false,
        None => false,
    }
}

fn receiver_identifier_from_pubscript_input(
    public_script: &[BFieldElement],
) -> Result<BFieldElement> {
    match public_script.get(2) {
        Some(id) => Ok(*id),
        None => bail!("Public script does not contain receiver ID"),
    }
}

fn ciphertext_from_pubscript_input(
    pubscript_input: &[BFieldElement],
) -> Result<Vec<BFieldElement>> {
    if pubscript_input.len() <= 3 {
        bail!("Public script does not contain ciphertext.");
    }
    return Ok(pubscript_input[3..].to_vec());
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
pub fn bfes_to_bytes(bfes: &[BFieldElement]) -> Vec<u8> {
    let length = bfes[0].value() as usize;
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

    bytes[0..length].to_vec()
}

impl SpendingKey {
    pub fn scan_for_received_utxos(
        &self,
        transaction: &Transaction,
    ) -> Vec<(Utxo, Digest, Digest)> {
        let mut received_utxos_with_randomnesses = vec![];

        // for all public scripts that contain a ciphertext for me,
        for matching_script in transaction
            .kernel
            .pubscript_hashes_and_inputs
            .iter()
            .filter(|(psh, psi)| pubscript_input_is_marked(psi))
            .filter(|(psh, psi)| {
                let receiver_id = receiver_identifier_from_pubscript_input(psi);
                match receiver_id {
                    Ok(recid) => recid == self.receiver_identifier,
                    Err(_) => false,
                }
            })
        {
            // decrypt it to obtain the utxo and sender randomness
            let ciphertext = ciphertext_from_pubscript_input(&matching_script.1);
            let decryption_result = match ciphertext {
                Ok(ctxt) => self.decrypt(&ctxt),
                _ => {
                    continue;
                }
            };
            let (utxo, sender_randomness) = match decryption_result {
                Ok(tuple) => tuple,
                _ => {
                    continue;
                }
            };

            // and join those with the receiver digest to get a commitment
            // Note: the commitment is computed in the same way as in the mutator set.
            let receiver_preimage = self.privacy_preimage.clone();
            let receiver_digest = Hash::hash(&receiver_preimage);
            let canonical_commitment = Hash::hash_pair(
                &Hash::hash_pair(&Hash::hash(&utxo), &sender_randomness),
                &receiver_digest,
            );

            // push to list
            received_utxos_with_randomnesses.push((utxo, sender_randomness, receiver_preimage));
        }

        received_utxos_with_randomnesses
    }

    pub fn derive_from_seed(seed: Digest) -> Self {
        let privacy_preimage =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::new(0)]].concat());
        let unlock_key =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::new(1)]].concat());
        let randomness: [u8; 32] = shake256(&bincode::serialize(&seed).unwrap(), 32)
            .try_into()
            .unwrap();
        let (sk, pk) = lattice::kem::keygen(randomness);
        let receiver_identifier =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::new(2)]].concat()).values()
                [0];

        Self {
            receiver_identifier,
            decryption_key: sk,
            privacy_preimage,
            unlock_key,
            seed: seed.to_owned(),
        }
    }

    /// Decrypt a Generation Address ciphertext
    pub fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<(Utxo, Digest)> {
        // parse ciphertext
        if ciphertext.len() <= CIPHERTEXT_SIZE_IN_BFES {
            bail!("Ciphertext does not have nonce.");
        }
        let (kem_ctxt, remainder_ctxt) = ciphertext.split_at(CIPHERTEXT_SIZE_IN_BFES);
        if remainder_ctxt.len() <= 1 {
            bail!("Ciphertext does not have payload.")
        }
        let (nonce_ctxt, dem_ctxt) = remainder_ctxt.split_at(1);
        let kem_ctxt_array: [BFieldElement; CIPHERTEXT_SIZE_IN_BFES] = kem_ctxt.try_into().unwrap();

        // decrypt
        let shared_key = match lattice::kem::dec(self.decryption_key, kem_ctxt_array.into()) {
            Some(sk) => sk,
            None => bail!("Could not establish shared secret key."),
        };
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce = Nonce::from_slice(&nonce_ctxt[0].value().to_be_bytes()); // almost 64 bits; unique per message
        let ciphertext_bytes = bfes_to_bytes(&ciphertext);
        let plaintext = match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
            Ok(ptxt) => ptxt,
            Err(_) => bail!("Failed to decrypt symmetric payload."),
        };

        // convert plaintext to utxo and digest
        Ok(bincode::deserialize(&plaintext)?)
    }

    fn generate_lock_preimages(&self) -> [Digest; 512] {
        let nth_preimage = |n: usize| {
            Hash::hash_varlen(
                &[
                    self.unlock_key.to_sequence(),
                    [BFieldElement::new(n.try_into().unwrap())].to_vec(),
                ]
                .concat(),
            )
        };
        (0..512).map(nth_preimage).collect_vec().try_into().unwrap()
    }

    fn generate_spending_lock(&self) -> Digest {
        let lock_preimages = self.generate_lock_preimages();
        let mut nodes: [Digest; 512] = [Digest::default(); 512];
        for i in 0..256 {
            nodes[256 + i] = lock_preimages[i];
        }
        for i in 0..255 {
            nodes[255 - i] = Hash::hash_pair(&nodes[510 - 2 * i], &nodes[511 - 2 * i]);
        }
        return nodes[1];
    }

    fn binding_unlock(&self, bind_to: &Digest) -> Vec<Digest> {
        let lock_preimages = self.generate_lock_preimages();
        let mut bind_bits = ReceivingAddress::bind_bits(bind_to);

        let witness_data = bind_bits
            .into_iter()
            .zip(lock_preimages.into_iter())
            .map(|(bit, preimage)| match bit {
                0 => preimage,
                1 => Hash::hash_pair(
                    &preimage,
                    &Digest::new([BFieldElement::zero(); DIGEST_LENGTH]),
                ),
            })
            .collect_vec();

        witness_data
    }
}

impl ReceivingAddress {
    pub fn from_spending_key(spending_key: &SpendingKey) -> Self {
        let seed = spending_key.seed;
        let receiver_identifier =
            Hash::hash_varlen(&[seed.to_sequence(), vec![BFieldElement::new(1)]].concat()).values()
                [0];
        let randomness: [u8; 32] = shake256(&bincode::serialize(&seed).unwrap(), 32)
            .try_into()
            .unwrap();
        let (sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = Hash::hash_pair(
            &spending_key.privacy_preimage,
            &Digest::new([BFieldElement::zero(); DIGEST_LENGTH]),
        );
        Self {
            receiver_identifier,
            encryption_key: pk,
            privacy_digest,
            spending_lock: spending_key.generate_spending_lock(),
        }
    }

    pub fn derive_from_seed(seed: Digest) -> Self {
        let spending_key = SpendingKey::derive_from_seed(seed);
        Self::from_spending_key(&spending_key)
    }

    pub fn encrypt(&self, utxo: Utxo, sender_randomness: Digest) -> Result<Vec<BFieldElement>> {
        // derive shared key
        let mut randomness = [0u8; 32];
        let mut rng = thread_rng();
        rng.fill(&mut randomness);
        let (shared_key, kem_ctxt) = lattice::kem::enc(self.encryption_key, randomness);

        // sample nonce
        let nonce_bfe: BFieldElement = rng.gen();

        // convert payload to bytes
        let plaintext = bincode::serialize(&(utxo, sender_randomness))?;

        // generate symmetric ciphertext
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce = Nonce::from_slice(&nonce_bfe.value().to_be_bytes()); // almost 64 bits; unique per message
        let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
            Ok(ctxt) => ctxt,
            Err(_) => bail!("Could not encrypt payload."),
        };
        let ciphertext_bfes = bytes_to_bfes(&ciphertext);

        // concatenate and return
        Ok([
            std::convert::Into::<[BFieldElement; CIPHERTEXT_SIZE_IN_BFES]>::into(kem_ctxt).to_vec(),
            vec![nonce_bfe],
            ciphertext_bfes,
        ]
        .concat())
    }

    /// Generate a pubscript input, which is a ciphertext only the
    /// recipient can decrypt, along with a pubscript that reads
    /// some input of that length.
    pub fn generate_pubscript_and_input(
        &self,
        utxo: Utxo,
        sender_randomness: Digest,
    ) -> Result<(Vec<BFieldElement>, Vec<BFieldElement>)> {
        let ciphertext = self.encrypt(utxo, sender_randomness)?;
        const READ_IO: BFieldElement = BFieldElement::new(128);
        const HALT: BFieldElement = BFieldElement::new(0);

        let mut pubscript = vec![READ_IO; ciphertext.len() + 1];
        *pubscript.last_mut().unwrap() = HALT;

        Ok((pubscript, ciphertext))
    }

    /// Verify the UTXO owner's assent to the transaction.
    /// This is the rust reference implementation, but the version of
    /// this logic that is proven is `lock_script`. This function
    /// crashes if it fails to verify; and returns nothing (but
    /// gracefully) if it succeeds.
    pub fn verify_unlock(&self, bind_to: &Digest, witness_data: &[Digest]) {
        let bind_bits = Self::bind_bits(&bind_to);

        let mut nodes: [Digest; 512] = [Digest::default(); 512];
        for ((i, d), b) in witness_data.iter().enumerate().zip(bind_bits.iter()) {
            nodes[256 + i] = match b {
                0 => Hash::hash_pair(d, &Digest::new([BFieldElement::zero(); 5])),
                1 => *d,
            };
        }
        for i in 0..255 {
            nodes[255 - i] = Hash::hash_pair(&nodes[510 - 2 * i], &nodes[511 - 2 * i]);
        }
        assert_eq!(self.spending_lock, nodes[1]);
    }

    pub fn bind_bits(bind_to: &Digest) -> Vec<usize> {
        let mut bits: Vec<usize> = Vec::with_capacity(256);
        for d in bind_to.values().into_iter().take(4) {
            let value = d.value();
            for j in 0..64 {
                bits.push(((value >> j) & 1) as usize);
            }
        }

        bits
    }

    /// Generate a lock script from the spending lock. Satisfaction
    /// of this lock script establishes the UTXO owner's assent to
    /// the transaction. The logic contained in here should be
    /// identical to `verify_unlock`.
    pub fn lock_script(&self) -> LockScript {
        // currently this script is just a placeholder
        const DIVINE: BFieldElement = BFieldElement::new(8);
        const HASH: BFieldElement = BFieldElement::new(48);
        const POP: BFieldElement = BFieldElement::new(2);
        const PUSH: BFieldElement = BFieldElement::new(1);
        const ASSERT_VECTOR: BFieldElement = BFieldElement::new(64);
        const READ_IO: BFieldElement = BFieldElement::new(128);
        let mut push_digest = vec![];
        for elem in self.spending_lock.values().iter().rev() {
            push_digest.append(&mut vec![PUSH, *elem]);
        }
        let instrs = vec![
            vec![
                DIVINE, DIVINE, DIVINE, DIVINE, DIVINE, HASH, POP, POP, POP, POP, POP,
            ],
            push_digest,
            vec![ASSERT_VECTOR],
            vec![READ_IO, READ_IO, READ_IO, READ_IO, READ_IO],
        ]
        .concat();

        LockScript(instrs)
    }
}

///
/// Claim
///  - (input: Hash(kernel), output: [], program: lock_script)

#[cfg(test)]
mod test_generation_addresses {
    use rand::{thread_rng, Rng, RngCore};
    use twenty_first::shared_math::tip5::Digest;

    use crate::models::blockchain::address::generation_address::{bfes_to_bytes, bytes_to_bfes};

    use super::{ReceivingAddress, SpendingKey};

    #[test]
    fn test_conversion_fixed_length() {
        let mut rng = thread_rng();
        const N: usize = 23;
        let byte_array: [u8; N] = rng.gen();
        let byte_vec = byte_array.to_vec();
        let bfes = bytes_to_bfes(&byte_vec);
        let bytes_again = bfes_to_bytes(&bfes);

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
            let bytes_again = bfes_to_bytes(&bfes);

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
            let bytes_again = bfes_to_bytes(&bfes);

            assert_eq!(test_case, bytes_again);
        }
    }

    #[test]
    fn test_keygen_sign_verify() {
        let mut rng = thread_rng();
        let seed: Digest = rng.gen();
        let spending_key = SpendingKey::derive_from_seed(seed.clone());
        let receiving_address = ReceivingAddress::derive_from_seed(seed);

        let msg: Digest = rng.gen();
        let witness_data = spending_key.binding_unlock(&msg);
        receiving_address.verify_unlock(&msg, &witness_data);
    }
}
