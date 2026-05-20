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
use serde::Deserialize;
use serde::Serialize;
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

pub const HRP_PREFIX: &str = "nolga";

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
        let mut hrp = HRP_PREFIX.to_string();
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
            hrp == Self::get_hrp(network),
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
    ///
    /// # Deprecated
    ///
    /// Use [super::receiving_address::ReceivingAddress::to_display_bech32m_abbreviated]
    /// instead.
    #[deprecated = "suffix length inconsistent with alternative abbreviations"]
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

    use itertools::Itertools;

    use super::*;
    use crate::api::export::WalletEntropy;

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

    #[test]
    fn no_crash_in_bech32_decoding() {
        const SHORT_PREFIX: &str = "n";
        let network = Network::Main;

        // Encodings with valid checksum
        let short_prefix =
            bech32::encode(SHORT_PREFIX, vec![].to_base32(), Variant::Bech32m).unwrap();
        let long_prefix =
            bech32::encode("nolganolga", vec![].to_base32(), Variant::Bech32m).unwrap();

        for str in [short_prefix, long_prefix] {
            assert!(
                GenerationReceivingAddress::from_bech32m(&str, network).is_err(),
                "Invalid bech32 encoding must lead to error: {str}"
            );
        }

        // Not valid checksums.
        for i in 0..10 {
            let as_ = "a".repeat(i);
            assert!(
                GenerationReceivingAddress::from_bech32m(&as_, network).is_err(),
                "Invalid bech32 encoding must lead to error 1"
            );
            assert!(
                GenerationReceivingAddress::from_bech32m(&format!("{HRP_PREFIX}1{as_}"), network)
                    .is_err(),
                "Invalid bech32 encoding must lead to error 2"
            );

            assert!(
                GenerationReceivingAddress::from_bech32m(&format!("{SHORT_PREFIX}1{as_}"), network)
                    .is_err(),
                "Invalid bech32 encoding must lead to error 4"
            );
            assert!(
                GenerationReceivingAddress::from_bech32m(&format!("1{as_}"), network).is_err(),
                "Invalid bech32 encoding must lead to error 5"
            );
        }
    }

    #[test]
    fn encryption_is_deterministic() {
        let expected = "9b60a3868707eee6837226b63bcea23929226726f2ffcbd2a5185e795d2ff87a1f85abf5207cae623b2c7ce112e28f9a70b8dec4eddff914fdd5250bb72457d26b64aa5d8f03156fb99df8ed7953a428b1840edb9af044972b8b942545aba6eb07be6d2412de7f88a13209044a110943df66da65929eec8e28008f9c46160fd36ef89edb1c11c7ca1a405eac4fb75fc103c065c8b9daef8f342dd82114e64eb94aa6855f1821fa54a7fe6551692a99dbff714f122d511ce72e3863e5f0ef7c2354ec821123d03f8481b9cee6fb6cf03377238e2c204dabb19d1f9816b7dd5d4523d5b666d1bfeac3ced0644eca4828f93c12eac3a37d670ad572aeae0936ee492a7e06cfdde77abaabbad478ea2bf833acf3005c4700213556e76f53494d6bfff4bc5e849323612b9899c74a9b56bacb8eb28c9a6cdf2f91204458cdc827dbce3e223a3ae6da89ce08964402a21f8e377307f126169cf4d91b3c2258e75fc58af2587e60ccf4badbbd767470a62f5c50c8af265b775f3155f7ac8cd04525c5101907aeaf040164381697c6e88aecb639cc56e9f47b8d3d05ac84c1a84ba8297887979ec393e0dfc5c3f94ac34cd4b32d8b63706e9b50dfef6d9acff20972c321eb70811b46173a9d7e152299e35fc4eaabe836e8931e924cf2d8c869015113c88b114270d4a76f7ac79d010af09fa8d83bbeeb9383e1a8f07b68f7eaf58b355f889f0c46d6e68f5eb081c25c020baf9f68a3dba9f342ac805ec88be475e8a8b58dcb7962c7cb272a8fead87ee6b2fae75bdd489c02209e7ff2536270d01fa618a1cc57fb072bde77a74ddf1a566d56014f442267087d5880a6fc4109c142c37ffb83361cf9fca890a02e4d70d9e9637145c492183890b4ea895e840ec5300bba237ebb0b4f147afba7cd8850c83b1ea47537ee299f28fcb8b3a92b5cf4a687daa8898daa5d921a23c03c7d5dea9bfcfc2da804c7db34542717b4a523a0dc2705b060b4ecb54f237122ccb2f3ea01ae15d1a73ec33733c79e43192432c0fd33c55b46a3e67a4e284a92009a3aa7741060b1771f81a200d0f4d1bfd433cb761e3a0b247cdd215d4dc141c0192c5acb7c1cda77771166d1dea3eaebf28230faaa4425efd813395e882aa1d91f24f8323fdd60f8453ef416f49c36719ce66e745d3abeecb2a04cdbe8f22179b3f55f1870664808f5c746b2502250e16b0eefbe133a89309aba04f2e652ed69d1beeee8d069d18833cc217e4b555d53bdcb8b97e05a58d3204912e0c1fb39fde792c3d52b59e42b9c3b8fd45092f8284a2c4f25a7edc52c7734262f354a863264fac04edfd4c3e624ee71bf82872e823a0fa464f9f2668db178a93d0421b8f1a0c1aeebcae97db6bffd715acbd79758f08d1639ee936bd20179ddbcdfcb0630482237868d43b99e3b55c9c1e465c8e0d89b6bdba982edcbcb6f0644484dbfe2f79593b34d4f8ae6e7637a9152ad4971560105528bbf0f14cb490d4e3a6fd12e0c0c0a9ba958512673e2c550781f4c915439b3a980fffab4af95bb0778b37264733edb64d256b3e41607b4b2a6ae0ff5b73f1d810098c8ec47d7ac677afd47016d570621b69c925b8f5f49dbf2538ef5bbc77f6e933b56d88e6e6bbb46d205515ea6d435780d5049dd6dd884ffb13447c0fdecfce31cf0530d2c89bedcdad96d45cb4c1c0912330ddb4f16b6f7e235207df767dcbb9ae363e6690953d52c527a3c9f36a0daf1271efd7402a5a8a2e5e5c32b3709b3a4013f3069c02ce816910fa8e251d593dddc55eb452ee698b484fff9133ebcfbb3c9acb4aee07533ce4c0f07eace2d6d7153fadaad36e07605920f593bf17cda0ec1a32dd609c76338069e6ec180a6df3a81411fb43eff9a9c81477a4a6bb20425cbebe67354ace59b18b8dfe0b173ccc3a957476ad0a59bb0d2ec9981b55e35bb7eaab2fda99caf8a07ac372370070b68652f441b09801cab8494b3c3aeffc6d8cb24c1ae1993c89154dae28b9c017435d917cd712d7de81b81b536d1869af2369b798613f2c8927abea290a990231dd7abafe7b4c161919ad17fa716ae2ff38046fdb2e6dde5cda2ebfe51739bd4f6800dea5f79de97334503cd6fa4071255dac7d58a1f6740e148ebb425bb6b65783e22ee1e4e578155bad8fcf261232acfcd2dce3cace4a46b4e8dfa974bbff2d7343a254dec3226b63667da42160f720b7e14701c22ef35f35a5b7b372a8af33dfc9e3f7ce24d1152ae2e4ffe1a3674290ca09925598848bda3c361e4bdd0841c511f91c1fe7beabaf794b30344b3a03b8bfd64186209440de2d1f062b8feb0418ece6aa068953fb7cea35732fa326fc1f2aee6048e034d2169d453e57ac1c3888e7f82c879b056ce40a566efa12760258bd30ee34911f7d6dae5d63b6f13c22ec9241522203d3397f289e522cd5679fcbd0f9136a6f8c91cf2f53bf334fe0abe533ebecfe9ce5c42c9a0b688b16e78e63a41468da319886cb80aa928d165f3028d0ae346314077b0a7bc807b7ff863ec3c9b94d8d158e3642de47b36953b137a7a5e74b4dfc18ea3ca59d5d946a5d7aa6085826dd94f0ab94a39a9745cb77ce4b3ba848380c58542c73f6d19f95ae21c76d8447f6b85f7ad72d41338bb918f9d6e23841737528035f2517ca0f32a0b1e77c42e7908d7ad9cd056d8b2a39f1d9ec963b6993c6ee9e42c6599a64e28f0bb985a437209a6f62d4e5d774f84ed34b9487faab8a5d87d48e0d3f638dd2af6ee15705c74dc909741f7a0abfe279ddeb1e1b38e5ae46ae7d81f11574eecf72c2853f748881a9fa645829dece4bb8237f09f6c93e79b4fd8a079635df7a306a7cb3360094f5a31ec9b5e9573481798e6f599a1f8f02b1f4dc0157a0d4ff7f2491a932a331f36c968440521efba36e85816bbdfc034cf6e5c39fcd33993f9c0a73fb5f0fc085d84651c6c659048e7748af1a58f6424575dada964b26f57b2291f5fa8cdeaafa485171c940dd8efe9bb5802a2c7231136d40254f1d1771c8abe6d71644f97473a06deba95bbef287696959931bf46bddac2e64387cf707ee050723119cd82a17e3979e1510fe26a4d8ef4abe8f77a3439f9adb1b43636e01be31addc8b56fe19e38034fc9229cc06a52d646345778e8637b44998e84329c9d14dc2b58aa4bbe22f8e08673197443e9605026ab0d9993637d08a50956a271690e1a96328758d34c68a5e3594d0ea0103e31ae2eeeedfd16f6b16bf7959a03d00f3c75b6f6bdb2b277c8eb69ee048bb81bd67ff29cde92a948bad10fedb9a7d122a30b4b76251f7918607bad49c31e0d2b52bd12fd81a11305d329a38cb918786ca5e8f8fc563227746f6cb1f83c0de1baa11575d5d323bd78d7ebafc1e8fdac8373c2bd38ce4199fad77fdfd7db0fe07fd20e9273b7c85546ba08a8db9c97a468ca3f052d164cf585bd0a1ea326cf1b021608b4464c0681cdee36b8558764533fef28428be4e70546a604bd503440240d5e41d97d564ced22022564e027edccc0b1665db1b5b8cc6284a5acd018dcfc3cc7940b2e98e9ef16743222a6b5fde4fc961c9d2e042148e5663d7702d9de3338948d094f51b129accea8978e790edad1d52415c55a3ddcd94285580000000000000068225d33d5262501f73db7222235a0e578be0a9ad4444c18d5336c6ef9919a531acbd86f0d06a423a4146cdb9c18f03d7bc2ff77e35f8c840b48ff07fd947c2fb7d6ef7ac7b0e1a03d33f463b54b4eb66e284a5f2ee5eae6d57658f07b9d47ed9d8577225d1192279a";
        let payload = UtxoNotificationPayload::new(Utxo::empty_dummy(), Digest::default());
        let result = GenerationSpendingKey::derive_from_seed(Digest::default())
            .to_address()
            .encrypt(&payload);

        assert_eq!(
            expected,
            result.iter().map(|bfe| format!("{bfe:016x}")).join("")
        );
    }

    #[test]
    fn bech32_representation_is_unchanged() {
        assert_eq!(
            "nolgam16n494axmrtxsxhftn2sgvn4uggt6tag8skztcfc8a2yrrn5l69n8gk5f8eenhf0pelr0rt5wxk82z46juq9ndpzx4377hv2ngns06x5hcchvtmr8wxtpvvykujq6tszt2w4mhdwmssknyfpjx59f6ywyz9crc2s4md0dksv0ayklk5rx3duz7p2gjtmtlc3sgz07urxljtf77a9yrwn6qy300f2e36z6humz3rehvphpaddj7vd02ucuktw9ux476njx9hn3sv92ay6up50ef4n3zh2a6jvdfcgsp6ed5k2q8e4lfpmc3p9uyrej7scarvkefe6e2muup8tyn5a4fvfsy48e3rcpxncfkz9wk0j5wss98rv3zq50uddhafh77z93ulleysdm839emh8v69y053v4hvpffr3s5x3lxmshkrq0087lyppqaj5xn52fhu6tkjxg2cvlxuarh85c58vnyatuaytcnshux4tk2qwgmu8kk0s6u34xv643aq59yrsnsvu5wskzvkwzjjrhlzjnhs5z5xg8fyvanv5806cpzjea277950vpt2npf9qr7qd96rttst05fdcxk5j0ut4c7qfpa03tq5rrk6n94m0fzu2km9hc4lez47e0v9yeu0xt6jkpjsvwcrwu0gxnuq4j2qjmcnkvafsuteyayhqvtwm3ypqyknr6zx7zcusp9h29970073wzwywp8gx0t3yh4usw23gvlhauctsfye8g3n4tvfg2xuhgrfr86q5z9u9kkec39krmyvzpewah3c36em0zskkns49jl9q4zynj8rymgaethxsrmjmakj0epe42xctu744ktwp9ms7xh2gumzexfhmgkqpypusx5sv7ag03pstlhqpp3s8vptaeqt4p57ejjlxl3v2zqdvsnvvcjv5twrcgv8s5a5hp27v8vqltxmfz9hd5m2l7yf9ux9d6rehz26gz0fuymnmcpru3500y689wq6k45xacwzhvlxwh0gk84090yxmeng8vwjvs35xkhnew7dn5zxky8g63kyfwhnz2m6vjwl655gwv9wgxynjsyga2h98hqz63eej8lpn6g3u4tar4j4d9ul2es2s28sdg9p0d4mawt7gryc69mvzadteyzxadg5h44vcm94gmynn9860fqxp2wgcwrm9df5vy32ylekjdvgmlxq63x2r3su50d25r3w90cl34pmmexhdeqj7g3kqphagvf5yff92am8f83s49c6y5mc972frs4qmmjew4f260e0tpsruqyxcyqm07kn6jmc7ptkfk0ky3hd3cv8xrjarrru69zqyxstn8d4lzjf2qsuvlktmqu037dfvmws8ejksrp66dqvezyndfz4sr6rcqsaexl8dk3kfyks6g8hdnspehnqcqw4pj8675ql4zwwsq74l0q8nu8a2ww38nz9psdf0t9cszvxk4y755pgfverlg4ew2u742sfv9f0ftwvcmu96p54gfd52hcsg6y0nlzmrdm2yqd08dvcdug9nyl27mchu2puhkmxdwylyuf26fdmya3tm6886sjx0v7ms50f0vsuyhsrewemkgykskldlfaqgfncaz0y60y0yw50t9mlshfezyp2sksn7zgpleuhqmqj5g5dh4ytqnt676ufr3g9aquq6dx8qdkqs5t5ptektsqlrpda9l4slycsy7hz5gyn4dzv45008e0fplhwwxwuarsjace2cr8qnzc55e7uwgs32juxfefflsv5942z5y33p2cgjm983npmw02v82jn9ktrmvadhvcraaz9avp3hpx6vd07pcwk76wml26zr2ew6e4uyjv0455uadvrldq4hev7fh3menu7hk9mvgl7yaez8afn5ysa95uvf4gwg4metjx78js4ssdqj4z5rk20ue0tl9d5k3x9cuefjyxzc6uu9mduke8k4wuz8hfj5wqpv35dzhj3je7g7phrcahrd9u24n04r2g5akupq05trs3h2r924rh53we5p6a3cresh73e9jy5ptr34a3fnhxlhg8gwn0uz5ra27lw5j392zhmjype9qtwmgrhm6y7whqqwkukmwthq40t2hd4j8ld2mckv3fyy97wcyf8dzjqnnqmcwvw0l4uwtl6e9z77w3mrenasvtdre320jhzq4phskk3q5r27avt6fa3k0j0evd8sanpgq6wtk0gssa3tlhstev2fuwpcf87h20v3apfvuglqj6kf4ra85x7zwks5g5tklfkxwswjlgheccypj4832wfu76gggxwvm9vzy5sxttns983z7qqul48ndp0u9268gj2l4qvxzv0r2xvzwc3nanc6sazwwgjc5fy6fg5vezsq93yft3znpwjpm4hqzu4mh2he84ru88gq43hrk4xld6et72m23cts8mlv0c9wc0shjg9jt7u5jn9le095jm32nt7dm257j6de0ym06ah3rpljfwf23gyf2ms8g2dj8hvyc59u7aquj35ajqhvjw55vhn8r2gdap607puwzvwlrvts0mrtsnkqnjq5u84pc39pf9x4pxhv0aghxwmj5wkqx9ynlcwh99wggeh2wk20f79anchlhe645lfzed3u82cf76yza8vhaz2lh42umza4hwfpz20mvjw6thm0vnj3etxvdeu73mjemv4mw27dhwku0726446tklc7memzet7ppdj9x3jvrmsstspt23zjnx8dl9w8akw88hyhlhtglal2gejqf9ktnuhng9p6paasth3sc5x7yjhtpvxr2ma435lfr4jceu6pn0na7n5h37qwuahtac9cpxuley7dvy0sslkq4n0nz0dwj9660pwkymmdj5e8mjnk5r2d2v8qgp4ymz83306teu3ge5rgjlmx0wnz5vpx6rtmgfhk2rphntwgmxd4c4m5cxt4q4y2lz03j0chqrrvjqycwe5kyr0tnhg954wntsx2fzgjx9pma7hq9qtfzweawps7j3mrzxkeg8eh9ve247tnyu4lqmx2f5wx2ql4slfkx2vd4a53n95ymt4frmr89jp8fx59c9jqevwzqzl5fz08clkn5wzawac8qhywryldnwvsjt8tz6s7w5qa85sqzyj23ep58lw2rl0ev8hez534cj2qyw34f8mue8g38s75pa2nju478qq6ylatguat4dam0r8vpepmslm3da3t8nrwm7gjwe968u0ps5nksp3d9svfptudr9sacqvxjcspru2vwzk099uq0pt38clvr3ezmuyq5cjg0ajvn70x8s7qfla3j5w8nwgrrssqfskcxk62zd9k6ssv26vm3p2g5n3lnvhd3dpv87l9hv5w0mvm4hl705t7cfm9tuc7ayxz5jux3u33vvlc84p5ewe5ruzcl7h2gy8u0ehqd38jz5335tme458ndm983gmhfqmcg38uukkzv8p9wz40a6e6",
            WalletEntropy::devnet_wallet()
                .nth_generation_spending_key(0)
                .to_address()
                .to_bech32m(Network::Main).unwrap());
    }
}
