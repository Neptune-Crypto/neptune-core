use crate::prelude::{triton_vm, twenty_first};

use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::bail;
use anyhow::Result;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use rand::thread_rng;
use rand::Rng;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use triton_vm::triton_asm;
use triton_vm::triton_instr;
use twenty_first::shared_math::lattice::kem::CIPHERTEXT_SIZE_IN_BFES;
use twenty_first::shared_math::tip5::DIGEST_LENGTH;
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, fips202::shake256, lattice, tip5::Digest},
    util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::config_models::network::Network;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PubScript;
use crate::models::blockchain::transaction::Transaction;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::mutator_set_trait::commit;

pub const GENERATION_FLAG: BFieldElement = BFieldElement::new(79);

#[derive(Clone, Debug, Copy)]
pub struct SpendingKey {
    pub receiver_identifier: BFieldElement,
    pub decryption_key: lattice::kem::SecretKey,
    pub privacy_preimage: Digest,
    pub unlock_key: Digest,
    pub seed: Digest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceivingAddress {
    pub receiver_identifier: BFieldElement,
    pub encryption_key: lattice::kem::PublicKey,
    pub privacy_digest: Digest,
    pub spending_lock: Digest,
}

fn pubscript_input_is_marked(pubscript_input: &[BFieldElement]) -> bool {
    matches!(pubscript_input.first(), Some(&GENERATION_FLAG))
}

fn derive_receiver_id(seed: Digest) -> BFieldElement {
    Hash::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(2)]].concat()).values()[0]
}

fn receiver_identifier_from_pubscript_input(
    public_script_input: &[BFieldElement],
) -> Result<BFieldElement> {
    match public_script_input.get(1) {
        Some(id) => Ok(*id),
        None => bail!("Public script does not contain receiver ID"),
    }
}

fn ciphertext_from_pubscript_input(
    pubscript_input: &[BFieldElement],
) -> Result<Vec<BFieldElement>> {
    if pubscript_input.len() <= 2 {
        bail!("Public script does not contain ciphertext.");
    }
    Ok(pubscript_input[2..].to_vec())
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

impl SpendingKey {
    pub fn to_address(&self) -> ReceivingAddress {
        let randomness: [u8; 32] = shake256(&bincode::serialize(&self.seed).unwrap(), 32)
            .try_into()
            .unwrap();
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = self.privacy_preimage.hash::<Hash>();
        ReceivingAddress {
            receiver_identifier: self.receiver_identifier,
            encryption_key: pk,
            privacy_digest,
            spending_lock: self.generate_spending_lock(),
        }
    }

    /// Return announces a list of (addition record, utxo, sender randomness, receiver preimage)
    pub fn scan_for_announced_utxos(
        &self,
        transaction: &Transaction,
    ) -> Vec<(AdditionRecord, Utxo, Digest, Digest)> {
        let mut received_utxos_with_randomnesses = vec![];

        // for all public scripts that contain a ciphertext for me,
        for matching_script in transaction
            .kernel
            .pubscript_hashes_and_inputs
            .iter()
            .filter(|psd| pubscript_input_is_marked(&psd.pubscript_input))
            .filter(|psd| {
                let receiver_id = receiver_identifier_from_pubscript_input(&psd.pubscript_input);
                match receiver_id {
                    Ok(recid) => recid == self.receiver_identifier,
                    Err(_) => false,
                }
            })
        {
            // decrypt it to obtain the utxo and sender randomness
            let ciphertext = ciphertext_from_pubscript_input(&matching_script.pubscript_input);
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
            let receiver_preimage = self.privacy_preimage;
            let receiver_digest = receiver_preimage.hash::<Hash>();
            let addition_record =
                commit::<Hash>(Hash::hash(&utxo), sender_randomness, receiver_digest);

            // push to list
            received_utxos_with_randomnesses.push((
                addition_record,
                utxo,
                sender_randomness,
                receiver_preimage,
            ));
        }

        received_utxos_with_randomnesses
    }

    pub fn derive_from_seed(seed: Digest) -> Self {
        let privacy_preimage =
            Hash::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(0)]].concat());
        let unlock_key =
            Hash::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(1)]].concat());
        let randomness: [u8; 32] = shake256(&bincode::serialize(&seed).unwrap(), 32)
            .try_into()
            .unwrap();
        let (sk, _pk) = lattice::kem::keygen(randomness);
        let receiver_identifier = derive_receiver_id(seed);

        let spending_key = Self {
            receiver_identifier,
            decryption_key: sk,
            privacy_preimage,
            unlock_key,
            seed: seed.to_owned(),
        };

        // Sanity check that spending key's receiver address can be encoded to
        // bech32m without loss of information.
        let receiving_address = spending_key.to_address();
        let encoded_address = receiving_address.to_bech32m(Network::Alpha).unwrap();
        let decoded_address =
            ReceivingAddress::from_bech32m(encoded_address, Network::Alpha).unwrap();
        assert_eq!(
            receiving_address, decoded_address,
            "encoding/decoding from bech32m must succeed. Receiving address was: {receiving_address:#?}"
        );

        spending_key
    }

    /// Decrypt a Generation Address ciphertext
    fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<(Utxo, Digest)> {
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
        let nonce_as_bytes = [nonce_ctxt[0].value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext_bytes = bfes_to_bytes(dem_ctxt)?;
        let plaintext = match cipher.decrypt(nonce, ciphertext_bytes.as_ref()) {
            Ok(ptxt) => ptxt,
            Err(_) => bail!("Failed to decrypt symmetric payload."),
        };

        // convert plaintext to utxo and digest
        Ok(bincode::deserialize(&plaintext)?)
    }

    fn generate_spending_lock(&self) -> Digest {
        self.unlock_key.hash::<Hash>()
    }

    /// Unlock the UTXO binding it to some transaction by its kernel hash.
    /// This function mocks proof generation.
    pub fn binding_unlock(&self, _bind_to: Digest) -> [BFieldElement; DIGEST_LENGTH] {
        let witness_data = self.unlock_key;
        witness_data.values()
    }
}

impl ReceivingAddress {
    pub fn from_spending_key(spending_key: &SpendingKey) -> Self {
        let seed = spending_key.seed;
        let receiver_identifier = derive_receiver_id(seed);
        let randomness: [u8; 32] = shake256(&bincode::serialize(&seed).unwrap(), 32)
            .try_into()
            .unwrap();
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = spending_key.privacy_preimage.hash::<Hash>();
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

    pub fn encrypt(&self, utxo: &Utxo, sender_randomness: Digest) -> Result<Vec<BFieldElement>> {
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
        let nonce_as_bytes = [nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
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
        utxo: &Utxo,
        sender_randomness: Digest,
    ) -> Result<(PubScript, Vec<BFieldElement>)> {
        let mut ciphertext = vec![GENERATION_FLAG, self.receiver_identifier];
        ciphertext.append(&mut self.encrypt(utxo, sender_randomness)?);

        let pubscript = triton_asm!(
            {&tasm_lib::io::InputSource::StdIn.read_words(ciphertext.len())}
            halt
        );

        Ok((pubscript.into(), ciphertext))
    }

    /// Generate a lock script from the spending lock. Satisfaction
    /// of this lock script establishes the UTXO owner's assent to
    /// the transaction. The logic contained in here should be
    /// identical to `verify_unlock`.
    pub fn lock_script(&self) -> LockScript {
        // currently this script is just a placeholder
        // const DIVINE: BFieldElement = BFieldElement::new(8);
        // const HASH: BFieldElement = BFieldElement::new(48);
        // const POP: BFieldElement = BFieldElement::new(2);
        // const PUSH: BFieldElement = BFieldElement::new(1);
        // const ASSERT_VECTOR: BFieldElement = BFieldElement::new(64);
        // const READ_IO: BFieldElement = BFieldElement::new(128);
        // let mut push_digest = vec![];
        // for elem in self.spending_lock.values().iter().rev() {
        //     push_digest.append(&mut vec![PUSH, *elem]);
        // }
        // let instrs = vec![
        //     vec![
        //         DIVINE, DIVINE, DIVINE, DIVINE, DIVINE, HASH, POP, POP, POP, POP, POP,
        //     ],
        //     push_digest,
        //     vec![ASSERT_VECTOR],
        //     vec![READ_IO, READ_IO, READ_IO, READ_IO, READ_IO],
        // ]
        // .concat();

        let mut push_spending_lock_digest_to_stack = vec![];
        for elem in self.spending_lock.values().iter().rev() {
            push_spending_lock_digest_to_stack.push(triton_instr!(push elem.value()));
        }

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

    fn get_hrp(network: Network) -> String {
        let mut hrp = "nolga".to_string();
        let network_byte: char = match network {
            Network::Alpha => 'm',
            Network::Testnet => 't',
            Network::RegTest => 'r',
        };
        hrp.push(network_byte);
        hrp
    }

    pub fn to_bech32m(&self, network: Network) -> Result<String> {
        let hrp = Self::get_hrp(network);
        let payload = bincode::serialize(self)?;
        let variant = Variant::Bech32m;
        match bech32::encode(&hrp, payload.to_base32(), variant) {
            Ok(enc) => Ok(enc),
            Err(e) => bail!("Could not encode generation address as bech32m because error: {e}"),
        }
    }

    pub fn from_bech32m(encoded: String, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(&encoded)?;

        if variant != Variant::Bech32m {
            bail!("Can only decode bech32m addresses.");
        }

        if hrp[0..=5] != Self::get_hrp(network) {
            bail!("Could not decode bech32m address because of invalid prefix");
        }

        let payload = Vec::<u8>::from_base32(&data)?;

        match bincode::deserialize(&payload) {
            Ok(ra) => Ok(ra),
            Err(e) => bail!("Could not decode bech32m address because of error: {e}"),
        }
    }

    /// Verify the UTXO owner's assent to the transaction.
    /// This is the rust reference implementation, but the version of
    /// this logic that is proven is `lock_script`.
    ///
    /// This function mocks proof verification.
    fn _reference_verify_unlock(
        &self,
        msg: Digest,
        witness_data: [BFieldElement; DIGEST_LENGTH],
    ) -> bool {
        std_lockscript_reference_verify_unlock(self.spending_lock, msg, witness_data)
    }
}

///
/// Claim
///  - (input: Hash(kernel), output: [], program: lock_script)

#[cfg(test)]
mod test_generation_addresses {
    use rand::{random, thread_rng, Rng, RngCore};
    use twenty_first::{shared_math::tip5::Digest, util_types::algebraic_hasher::AlgebraicHasher};

    use crate::{
        config_models::network::Network,
        models::blockchain::{
            shared::Hash,
            transaction::{amount::Amount, transaction_kernel::PubScriptHashAndInput, utxo::Utxo},
        },
        tests::shared::make_mock_transaction,
    };

    use super::*;

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

    #[test]
    fn test_keygen_sign_verify() {
        let mut rng = thread_rng();
        let seed: Digest = rng.gen();
        let spending_key = SpendingKey::derive_from_seed(seed);
        let receiving_address = ReceivingAddress::derive_from_seed(seed);

        let msg: Digest = rng.gen();
        let witness_data = spending_key.binding_unlock(msg);
        assert!(receiving_address._reference_verify_unlock(msg, witness_data));

        let receiving_address_again = spending_key.to_address();
        assert_eq!(receiving_address, receiving_address_again);
    }

    #[test]
    fn test_bech32m_conversion() {
        for _ in 0..100 {
            let seed: Digest = thread_rng().gen();
            let receiving_address = ReceivingAddress::derive_from_seed(seed);
            let encoded = receiving_address.to_bech32m(Network::Testnet).unwrap();
            let receiving_address_again =
                ReceivingAddress::from_bech32m(encoded, Network::Testnet).unwrap();

            assert_eq!(receiving_address, receiving_address_again);
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = thread_rng();
        let seed: Digest = rng.gen();
        let spending_key = SpendingKey::derive_from_seed(seed);
        let receiving_address = ReceivingAddress::from_spending_key(&spending_key);

        let amount: Amount = rng.next_u32().into();
        let coins = amount.to_native_coins();
        let lock_script = receiving_address.lock_script();
        let utxo = Utxo::new(lock_script, coins);

        let sender_randomness: Digest = rng.gen();

        let ciphertext = receiving_address.encrypt(&utxo, sender_randomness).unwrap();
        println!("ciphertext.get_size() = {}", ciphertext.len() * 8);

        let (utxo_again, sender_randomness_again) = spending_key.decrypt(&ciphertext).unwrap();

        assert_eq!(utxo, utxo_again);

        assert_eq!(sender_randomness, sender_randomness_again);
    }

    #[test]
    fn scan_for_announced_utxos_test() {
        // Mark a transaction as containing a generation address, and then verify that
        // this is recognized by the receiver.
        let mut rng = thread_rng();
        let seed: Digest = rng.gen();
        let spending_key = SpendingKey::derive_from_seed(seed);
        let receiving_address = ReceivingAddress::from_spending_key(&spending_key);
        let utxo = Utxo {
            lock_script_hash: receiving_address.lock_script().hash(),
            coins: Into::<Amount>::into(10).to_native_coins(),
        };
        let sender_randomness: Digest = random();

        let (pubscript, pubscript_input) = receiving_address
            .generate_pubscript_and_input(&utxo, sender_randomness)
            .unwrap();
        let mut mock_tx = make_mock_transaction(vec![], vec![]);

        assert!(spending_key.scan_for_announced_utxos(&mock_tx).is_empty());

        // Add a pubscript for our keys and verify that they are recognized
        assert!(pubscript_input_is_marked(&pubscript_input));
        mock_tx
            .kernel
            .pubscript_hashes_and_inputs
            .push(PubScriptHashAndInput {
                pubscript_hash: Hash::hash(&pubscript),
                pubscript_input,
            });

        let announced_txs = spending_key.scan_for_announced_utxos(&mock_tx);
        assert_eq!(1, announced_txs.len());

        let (read_ar, read_utxo, read_sender_randomness, returned_receiver_preimage) =
            announced_txs[0].clone();
        assert_eq!(utxo, read_utxo);

        let expected_addition_record = commit::<Hash>(
            Hash::hash(&utxo),
            sender_randomness,
            receiving_address.privacy_digest,
        );
        assert_eq!(expected_addition_record, read_ar);
        assert_eq!(sender_randomness, read_sender_randomness);
        assert_eq!(returned_receiver_preimage, spending_key.privacy_preimage);
    }
}
