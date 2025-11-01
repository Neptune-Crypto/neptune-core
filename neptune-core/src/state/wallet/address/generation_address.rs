//! provides an asymmetric key interface for sending and claiming [Utxo].
//!
//! The asymmetric key is based on [lattice::kem] and encrypts a symmetric key
//! based on [aes_gcm::Aes256Gcm] which encrypts the actual payload.
//!
//! ### Naming
//!
//! These are called "Generation" keys because they are quantum-secure and it is
//! believed/hoped that the cryptography should be unbreakable for at least a
//! generation and hopefully many generations.  If correct, it would be safe to
//! put funds in a paper or metal wallet and ignore them for decades, perhaps
//! until they are transferred to the original owner's children or
//! grand-children.

use aead::Aead;
use aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use bech32::FromBase32;
use bech32::ToBase32;
use bech32::Variant;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::lattice;
use tasm_lib::twenty_first::math::lattice::kem::CIPHERTEXT_SIZE_IN_BFES;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::common;
use super::common::deterministically_derive_seed_and_nonce;
use super::common::network_hrp_char;
use super::encrypted_utxo_notification::EncryptedUtxoNotification;
use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::announcement::Announcement;
use crate::protocol::consensus::transaction::lock_script::LockScript;
use crate::protocol::consensus::transaction::lock_script::LockScriptAndWitness;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::state::wallet::utxo_notification::UtxoNotificationPayload;

pub(super) const GENERATION_FLAG_U8: u8 = 79;
pub const GENERATION_FLAG: BFieldElement = BFieldElement::new(GENERATION_FLAG_U8 as u64);

// note: we serde(skip) fields that can be computed from the seed in order to
// keep the serialized (including bech32m) representation small.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize)]
pub struct GenerationSpendingKey {
    seed: Digest,

    #[serde(skip)]
    receiver_identifier: BFieldElement,

    #[serde(skip)]
    decryption_key: lattice::kem::SecretKey,

    #[serde(skip)]
    receiver_preimage: Digest,

    #[serde(skip)]
    unlock_key_preimage: Digest,
}

// manually impl Deserialize so we can derive all other fields from the seed.
impl<'de> serde::de::Deserialize<'de> for GenerationSpendingKey {
    // todo: is there a more succinct way to impl this fn that works for
    // both sequential and map visitor access patterns?
    //
    // for seq access (bincode, postcard) we can simply do:
    //    let seed = Digest::deserialize(deserializer)?;
    //    Ok(Self::derive_from_seed(seed))
    //
    // but that fails for crates like serde_json that use map access.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Seed,
        }

        struct FieldVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldVisitor {
            type Value = GenerationSpendingKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct GenerationSpendingKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let seed = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                Ok(GenerationSpendingKey::derive_from_seed(seed))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut seed = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Seed => {
                            if seed.is_some() {
                                return Err(serde::de::Error::duplicate_field("seed"));
                            }
                            seed = Some(map.next_value()?);
                        }
                    }
                }
                let seed_digest = seed.ok_or_else(|| serde::de::Error::missing_field("seed"))?;
                Ok(GenerationSpendingKey::derive_from_seed(seed_digest))
            }
        }

        const FIELDS: &[&str] = &["seed"];
        deserializer.deserialize_struct("GenerationSpendingKey", FIELDS, FieldVisitor)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerationReceivingAddress {
    receiver_identifier: BFieldElement,
    encryption_key: lattice::kem::PublicKey,

    /// Post-image of the receiver preimage
    receiver_postimage: Digest,

    /// Post-image of the hashlock key
    lock_postimage: Digest,
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> Arbitrary<'a> for GenerationReceivingAddress {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = Digest::arbitrary(u)?;
        Ok(Self::derive_from_seed(seed))
    }
}

impl GenerationSpendingKey {
    pub fn to_address(&self) -> GenerationReceivingAddress {
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&self.seed).unwrap());
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = self.receiver_preimage.hash();
        GenerationReceivingAddress {
            receiver_identifier: self.receiver_identifier(),
            encryption_key: pk,
            receiver_postimage: privacy_digest,
            lock_postimage: self.generate_spending_lock(),
        }
    }

    pub(crate) fn lock_script_and_witness(&self) -> LockScriptAndWitness {
        LockScriptAndWitness::standard_hash_lock_from_preimage(self.unlock_key_preimage)
    }

    pub fn derive_from_seed(seed: Digest) -> Self {
        let privacy_preimage =
            Tip5::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(0)]].concat());
        let unlock_key =
            Tip5::hash_varlen(&[seed.values().to_vec(), vec![BFieldElement::new(1)]].concat());
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&seed).unwrap());
        let (sk, _pk) = lattice::kem::keygen(randomness);
        let receiver_identifier = common::derive_receiver_id(seed);

        let spending_key = Self {
            receiver_identifier,
            decryption_key: sk,
            receiver_preimage: privacy_preimage,
            unlock_key_preimage: unlock_key,
            seed: seed.to_owned(),
        };

        // Sanity check that spending key's receiver address can be encoded to
        // bech32m without loss of information.
        let network = Network::Main;
        let receiving_address = spending_key.to_address();
        let encoded_address = receiving_address.to_bech32m(network).unwrap();
        let decoded_address =
            GenerationReceivingAddress::from_bech32m(&encoded_address, network).unwrap();
        assert_eq!(
            receiving_address, decoded_address,
            "encoding/decoding from bech32m must succeed. Receiving address was: {receiving_address:#?}"
        );

        spending_key
    }

    /// Decrypt a Generation Address ciphertext
    pub(super) fn decrypt(&self, ciphertext: &[BFieldElement]) -> Result<(Utxo, Digest)> {
        // parse ciphertext
        ensure!(
            ciphertext.len() > CIPHERTEXT_SIZE_IN_BFES,
            "Ciphertext does not have nonce.",
        );
        let (kem_ctxt, remainder_ctxt) = ciphertext.split_at(CIPHERTEXT_SIZE_IN_BFES);
        ensure!(
            remainder_ctxt.len() > 1,
            "Ciphertext does not have payload.",
        );
        let (nonce_ctxt, dem_ctxt) = remainder_ctxt.split_at(1);
        let kem_ctxt_array: [BFieldElement; CIPHERTEXT_SIZE_IN_BFES] = kem_ctxt.try_into().unwrap();

        // decrypt
        let Some(shared_key) = lattice::kem::dec(self.decryption_key, kem_ctxt_array.into()) else {
            bail!("Could not establish shared secret key.");
        };
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce_as_bytes = [nonce_ctxt[0].value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext_bytes = common::bfes_to_bytes(dem_ctxt)?;
        let plaintext = cipher
            .decrypt(nonce, ciphertext_bytes.as_ref())
            .map_err(|_| anyhow!("Failed to decrypt symmetric payload."))?;

        // convert plaintext to utxo and digest
        Ok(bincode::deserialize(&plaintext)?)
    }

    fn generate_spending_lock(&self) -> Digest {
        self.unlock_key_preimage.hash()
    }

    /// returns the receiver preimage.
    ///
    /// note: The hash of the preimage is available in the receiving address.
    pub fn receiver_preimage(&self) -> Digest {
        self.receiver_preimage
    }

    /// returns the receiver_identifier, a fingerprint
    pub fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }
}

// future improvements: a strong argument can be made that this type
// should not have any methods with
// outside types as parameters or return types.  for example:
//
// pub(crate) fn generate_announcement(
//     &self,
//     utxo_notification_payload: &UtxoNotificationPayload,
// ) -> Announcement;
//
// this method is dealing with types far outside the concern of
// a key, which means the method belongs elsewhere.
impl GenerationReceivingAddress {
    pub fn from_spending_key(spending_key: &GenerationSpendingKey) -> Self {
        let seed = spending_key.seed;
        let receiver_identifier = common::derive_receiver_id(seed);
        let randomness: [u8; 32] = common::shake256::<32>(&bincode::serialize(&seed).unwrap());
        let (_sk, pk) = lattice::kem::keygen(randomness);
        let privacy_digest = spending_key.receiver_preimage.hash();
        Self {
            receiver_identifier,
            encryption_key: pk,
            receiver_postimage: privacy_digest,
            lock_postimage: spending_key.generate_spending_lock(),
        }
    }

    pub fn derive_from_seed(seed: Digest) -> Self {
        let spending_key = GenerationSpendingKey::derive_from_seed(seed);
        Self::from_spending_key(&spending_key)
    }

    /// Determine whether the given witness unlocks the lock defined by this receiving
    /// address.
    pub fn can_unlock_with(&self, witness: &[BFieldElement]) -> bool {
        match witness.try_into() {
            Ok(witness_array) => Digest::new(witness_array).hash() == self.lock_postimage,
            Err(_) => false,
        }
    }

    pub(crate) fn encrypt(&self, payload: &UtxoNotificationPayload) -> Vec<BFieldElement> {
        let (randomness, nonce_bfe) = deterministically_derive_seed_and_nonce(payload);
        let (shared_key, kem_ctxt) = lattice::kem::enc(self.encryption_key, randomness);

        // convert payload to bytes
        let plaintext = bincode::serialize(payload).unwrap();

        // generate symmetric ciphertext
        let cipher = Aes256Gcm::new(&shared_key.into());
        let nonce_as_bytes = [nonce_bfe.value().to_be_bytes().to_vec(), vec![0u8; 4]].concat();
        let nonce = Nonce::from_slice(&nonce_as_bytes); // almost 64 bits; unique per message
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        let ciphertext_bfes = common::bytes_to_bfes(&ciphertext);

        // concatenate and return
        [
            std::convert::Into::<[BFieldElement; CIPHERTEXT_SIZE_IN_BFES]>::into(kem_ctxt).to_vec(),
            vec![nonce_bfe],
            ciphertext_bfes,
        ]
        .concat()
    }

    /// returns human readable prefix (hrp) of an address.
    pub(super) fn get_hrp(network: Network) -> String {
        // NOLGA: Neptune lattice-based generation address
        let mut hrp = "nolga".to_string();
        let network_byte = network_hrp_char(network);
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

    pub fn from_bech32m(encoded: &str, network: Network) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(encoded)?;

        ensure!(
            variant == Variant::Bech32m,
            "Can only decode bech32m addresses.",
        );
        ensure!(
            hrp[0..=5] == Self::get_hrp(network),
            "Could not decode bech32m address because of invalid prefix",
        );

        let payload = Vec::<u8>::from_base32(&data)?;
        bincode::deserialize(&payload)
            .map_err(|e| anyhow!("Could not decode bech32m address because of error: {e}"))
    }

    /// returns an abbreviated address.
    ///
    /// The idea is that this suitable for human recognition purposes
    ///
    /// ```text
    /// format:  <hrp><start>...<end>
    ///
    ///   [4 or 6] human readable prefix. 4 for symmetric-key, 6 for generation.
    ///   8 start of address.
    ///   8 end of address.
    /// ```
    /// it would be nice to standardize on a single prefix-len.  6 chars seems a
    /// bit much.  maybe we could shorten generation prefix to 4 somehow, eg:
    /// ngkm --> neptune-generation-key-mainnet
    pub fn to_bech32m_abbreviated(&self, network: Network) -> Result<String> {
        let bech32 = self.to_bech32m(network)?;
        let first_len = Self::get_hrp(network).len() + 8usize;
        let last_len = 8usize;

        assert!(bech32.len() > first_len + last_len);

        let (first, _) = bech32.split_at(first_len);
        let (_, last) = bech32.split_at(bech32.len() - last_len);

        Ok(format!("{}...{}", first, last))
    }

    /// generates a lock script from the spending lock.
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn lock_script(&self) -> LockScript {
        LockScript::standard_hash_lock_from_after_image(self.lock_postimage)
    }

    pub(crate) fn generate_announcement(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
    ) -> Announcement {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: GENERATION_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_announcement()
    }

    pub(crate) fn private_utxo_notification(
        &self,
        utxo_notification_payload: &UtxoNotificationPayload,
        network: Network,
    ) -> String {
        let encrypted_utxo_notification = EncryptedUtxoNotification {
            flag: GENERATION_FLAG_U8.into(),
            receiver_identifier: self.receiver_identifier(),
            ciphertext: self.encrypt(utxo_notification_payload),
        };

        encrypted_utxo_notification.into_bech32m(network)
    }

    /// returns the receiver_identifier, a public fingerprint
    pub fn receiver_identifier(&self) -> BFieldElement {
        self.receiver_identifier
    }

    /// returns a digest which is the hash of receiver preimage of the matching
    /// [GenerationSpendingKey]
    pub fn receiver_postimage(&self) -> Digest {
        self.receiver_postimage
    }

    /// returns the `spending_lock`
    pub fn spending_lock(&self) -> Digest {
        self.lock_postimage
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    use super::*;

    mod generation_spending_key {
        use super::*;

        // we test serialization roundtrip because we skip fields when serializing and
        // there is a custom impl Deserialization for GenerationSpendingKey
        //
        // serde crates can use either sequential or map visitor access pattern when deserializing
        // so it is important to test both.
        mod serialization {
            use super::*;

            // note: bincode uses sequential access pattern when deserializing.
            #[test]
            pub fn roundtrip_bincode() {
                let spending_key = GenerationSpendingKey::derive_from_seed(rand::random());

                let s = bincode::serialize(&spending_key).unwrap();
                let deserialized_key: GenerationSpendingKey = bincode::deserialize(&s).unwrap();

                assert_eq!(spending_key, deserialized_key);
            }

            // note serde_json uses map access pattern when deserializing.
            #[test]
            pub fn roundtrip_json() {
                let spending_key = GenerationSpendingKey::derive_from_seed(rand::random());

                let s = serde_json::to_string(&spending_key).unwrap();
                let deserialized_key: GenerationSpendingKey = serde_json::from_str(&s).unwrap();

                assert_eq!(spending_key, deserialized_key);
            }
        }
    }

    #[test]
    fn can_parse_valid_address() {
        let network = Network::Main;
        let bech32m_string = "nolgam1cvqtx45kkfqhkmzt74ec98laulywqevxyyqhhchs5v5g07t76uqjnp4la3htxa5jev004wsmtt0w0ktxc08qz03ztpx80t652qgvh44k7s3esxg6flkdnhmljlx9vwz4zt3awn2lj0y3pga5yj7rusp8mtp7alkzkt0fvufxwmqwqyxzg5z8d54a8zj7l0az237yc6wjxr6z04d2skdql82p5qaks7crqwafgu7nm3yjkwjnetrhlqp8u0y22vgavdltgdhc6xql0q7krh6f8rn9snuyr5whufy5pk2ja5mhhkal6v2mt0f4wj9y27fhep60cxgv4gnlyu9j36yava459dr9zzm9ctq32juar4dmpsgt98sq0twnzhvfkmyfvvjtjtdfm9t9yfkexyf5und9xfj3ll9qxy4qdvzz3mft0kj5kw0cggacy7p4f0zuag3pxexh20378k2gr0kt7nkmchaum8ud80a4t697hfj67p6mamu00d8g2erx4fhuu9xfuzv8sjgwqzkfjdkaayrfqy5kvrkmpf27z2r5pyd783ghwzgqk8z96ek0xjxxawem849nn24r80u42m3s63y6zqlsfu3jyy3ddq2rzjn0pj7fyt3f7k2smum9mzhwzw03vfh8lcetrcgtdjc83ctcre4ajmhlkt8s3r2wgnf43d4lndkml20yu7z3xua3ev3nudtq0mt0mx4rvakml08qy8nln08t6dew6v9q46xp94e3s83sf6as8v5w27uvyqvckymqg7mpuhht2gmxrug0tj4uz6hsymatwhaq0m25p4hkptfft4jcgly9l26ufcu23f3knj53u5tfv3gkm3rdzruhjra0k9d6g3xhmvpsu3n780y65m5vx22a3pfyvzenv0zf8te55f4gmhhtqwy57zhazsd3wqkcf0qrd7vpndeprssgu4hc9373ytapkersgufemdvselrkf7fdl3xh7sx4ph42pjxcgtx6vyqqjedeqgtsfev57eefpc9uje6lkvwnzxh5dvmwk8w69ynkmnza0qppnkgzd8m7fnthxrml20v2uce8hl655tfppsgfgnyc80q2mnpmx6f5jkvlmyhdsvd56ywzahr68qs37s8edegwad9u90fw44774yshp9k8kyj9am8hmuqczg0capa38gh3jupsgu3heaxkrlfhwcghl3k8s72dg9ljf76c6f79v5x4jpykvacdkhc7wp02g5je6su8nyqr7zef9z9sqlwwazc8u3cu8s2usum77qmj47eh8w424sued8x8lc7mxj398f6gt8yph0zgrslserjdpmvf877sum79k0nq39haw904eruls6ed0zkpkmw7twj7p67wz6ewhc9nu6dnackmjsugmxsphvqgxwll54fr5v4cy23xsyadtnd5u5p62qwyqz6sv8clgjcyhaekf4sul8zlxmc4p7h0uf75s9929343wn769z7vy0vaj4sfq4544s9zmnxxlyuquxamq94qnwl5nvsqxumfwl3jdef8lxfgreacsv78k89vqfllx7sknx5lr3jj4upynjf5cxlmjdcn8e6rlryrc8ecju70dg98tsuj0h7reqt0j7uagdqk2sqe77eftlrwqmap9ceuwe60n7akkntc2r5pttshv9mpsykhy44mam6k09azgma3m78ktkqr8zm35l5z9vhn0mczfu9sfpsztdehl2wlt4h3dy0lrjvrqf6r69xe05r9ut8x9n87fuvy7ny6crpfdvzfxekzye3pefhr4k8v6th2hjkz3ekxy6r3h4dvzqq7hns0qz0xr5w27xrejvjgaw08m9pmrlzns9uk4tt9ykus34mf6nxfdvgw5pyklnvzj3xnzjessely3u3v6gp2ncfmct47yu507pc5r7uear28llzz8krd8e0zcrlmhvjj69q75ttm9kn6emkqxt2acux63ezjc66hs6pnynrffgffdl6hdns0e0nkz58t5j7h6wltje7hfvzwzxzmshsxvpsgj3flzlptzfwv34udx5g3g4kpcpu04p85xvdq0m0qmkmpg88uv6jsts6u4m2al45gr2tzdg6fuaedwlvhkf9neav0r264eadtvgnk8ahgshfaluqwqz604s73hzp9qj8en397h3lhl6d5a2xz5w2jujak2l62p35c55h07plx4jxz5dwwed6v8ym682dl00eqml7zxewma6dhhl9ufp0rw83ckuw9qft92y7l7t4fqzfumglhcqpkrgl0vjpzkzhda734mauxv6lr2glcjee0xp96ls3rnsl0l5e2qexx4aj2rhllezphmqzka047pafa6l7k2lr75xgyc4p84dvskldmcljm67jgjw4nxawnqternspgph4793fthad5yp3zvt5vtcmcr36sygjkw89zu0vewcnu9gfx3u7wpwvwz585d0dl5ycg0dq4l2z74cyznn5cmz43qj8745duqgrpmx23vhjzhmzmck8mq37h65duxx547z6ml52mmtnkc0x2hh2tm83t6s37l0aau8v2kw88v4gx3jfmez2re626lgydhz5je47zh8rlc74qxk83pr87nwcvhtlh2jjn8ksv38hc8g5sh4gtx9emj7q8kzsgjqvsn0l8rnhzx0ztseqr3usuztva7ejkj7degxgyur2w92n4m7mudufslz9d5puuzd6yzk3g4rjyphr6sun0v28qffumdupx737udpeextntdnkrl8u8h7kgntwj7eh8ynvwqcuer5xne36nmhmr3awv7kyfc7xh9g4sl4xj9zg5fzmehjda6d9zwcnkwfhcar2gh84jmew47e69uak2s329x6mg7sn23dkswyla7xjfn5r23a7uj7r3r5jt4djg8m7en5p6vh290jajs5fpm4hkfza4uwp29nqtn9wf05hlvgjnx9fjh3pzlhd97s3ge3xczchl306ayqunlu2kyasklt8lu0mt6dy734wdtgxpu2s5jw3m8jrkm5epz6s9mf03z6xsf4efaahzamxpdvvx68ykqjpeu3y0mps2sj4z86ucxd2tnwtgks00ep5hmrnvcjwmfqkgdfp3x7x3zx9r3tc2fz70mzpal64hd5ewalxvkxmv8uz6rt48vjqfghfe49d5derqdjege6g477esdkgnmpmpj5uhx9vxcm48lqqpucnn7d2xap00twgje3927m80jnuvagw2mfa4j9vcsl9mauzjn7ps9naa5kkg6d2l4yv4f0f6u88er0st25sq65p4zppukfrjknl8nkr4ujgrgk8tulatqh93ydd7hexrlsh9zje0eskp8656zwx25fs53ee6atrknffj95a85mfwtdsd5djafr3rs2c4wvurfeslj6s8869wvlj0yw7a730npk2dhgwgmq4p9ag0eugcuu5ucsycul295xcwprr";

        // no crash
        let _ = GenerationReceivingAddress::from_bech32m(bech32m_string, network).unwrap();
    }
}
