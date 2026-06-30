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
use crate::protocol::consensus::network::Network;
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

        #[test]
        fn genaddr_hash_lock_from_seed_matches_generation_address() {
            for _ in 0..10 {
                let seed: Digest = rand::random();
                let from_key =
                    GenerationSpendingKey::derive_from_seed(seed).lock_script_and_witness();
                let from_seed = LockScriptAndWitness::genaddr_like_hash_lock_from_seed(seed);
                assert_eq!(from_key.program, from_seed.program);
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
        let expected = "a6f6beec20234de353f4abed0eb9a199a6c1e021cfc4eb26b94d3834b1790155549f215b9079cfc532b42c537251e0b3ec26d8316d0c38d3d7fa2f2467a934888523e90bcc53456c4df0ae25bf4b8007b5c67b9ea5992c53ffa1e799a1d2b77471fb69a73229671b31c29b7e849c1712b907e4aa91e711e262a5c23a7c7312ee6bc7b9c9648583368898ed4ca0ca2de954cc668ecf46ee8bc3aeeba435a39dbf59d3a9391c93366b355fb2664cbb64f2c4143cc8e44fe64c34d66075229c83cecd6753b02bf95ae47db63ebab75f46edbe958db2cdde80cc2197609fe73faebf0e58cf7fc99507d7e4ee17fee444dc4ed26b7b48c2d2ff15bbba856f7f08ba5d5f090303d2c971d62dbef16b7ac0b2a7c113806e7b62a5fd80a6735a59673c0b46bab15893f8870b2cacf01b51dd2f8bdb5284ccbf168694a27add40188024229576309f7cf03aa1eb9122321548e60462b039f02cf22126beead83ef5f0523b278a16cf0ac69e5c08a36b2d3eb6ff6af4a2574abe6564c0c96ae4bfcd6051a9878d476b6ce53449b9e48813c037dd904faab3707383a12b5c802764065cd2a2227790d5459d0d1823aea9f93be467564cb56e034bf6c556873f9e087e981c329314363be5f0aad2f70e8cf9534402787d83acc60c452da60e5088d60bd033f5444aef2927100f15250c60499a6420a8c949c90cc18333e2b07a6f986d7dae9560f289eb2797a79d3f3fcc7ec47e92183c61c4137600695960a374df1df34cea9753b6f88a0ebc8c80cce3f4cbcbc6f80479ec60058f101d3aea22d32f6901f08209bf9ee75cddc5d42a11de0ac45653ac3a017fd94d8e3490d988103e159f8d6f05d609e0dc127914c73fe50d679ed5bfc667a8c31ad879d3f754f6d3819244f6c4474df62b5c4bba35d9bee1583d5451c9bb9ba3c1d034b818a6796c280292954d17b7e27ee16c1bd54253a00917691060b4a79d0a141bec6c0529c3f07ead435968ef259a4e3efcd0b440e0030e07a0c307a7d0faa9b20780e8444cfa31df4c42371f12686e9f9d8f5bbd2f0102becc6feef60097fcefa243562c3fd1da5d9d8222aa54eb533defbefa0d8b66f77bacfbb71695c6ef36330546e849cd07172c9f83fe5faf11a4d938df76944b900b8efd3598eb0b120d1a798c6d7f66995b0f6bcd8997ee5dc17867b8995fa6ec03d70ec121bf0e0972207e199563eb697e387bc2563291f1c96e38308b407eab1701e7d1d8f61dd09d5e22b3ef7886fa408b5aea5803c093118fcdb33b781f48139bbc9ec8ea7fdb5876eec246f06422cc74067063e650c5fad131db5bc445c571fd980073a67fdc47be886b4d7546a93a655ffe347d6ae4e347f88c5318b436bbc8af543363b2898b95439004ef5acd60e7bce55b4364abc890acdb38ef4c5b535adc0533bf1b6d24719e4f82a8f921ec2dc6b1764e983ea26ddc5016599114b45cc631159f9df26d102b278c4dd0a38d54294b9832c0f6fa973decdb8e58a13c425545f16cc9eb3f2bcb9246d209519898e4253b2ac3cfb2abbab016aef3899272414736a68d469e3bc4e2336b17e95a8d0597fb5a864b2015e35a86d208a83f97f8e88f05de7fc8d0c5e48ff285fccfaba75c442a0396022c0978ad5c780d0a881a8e348cdc7f98c8a1f0090b8e2cf916190f047e25f7934029e9dd58caa83bed6d6b6e655a0422d54f556a66723b49d1d0b6300e3872eef975e610a14662c864dc5ba6fb14adc2f35be4add4f7dc214e8156a0187b5276bf942dedd98690ae303e79659b78e2ca67a0a817a3357ca7bdaa3fd1ba191982fe49e539f154216228eb03fbc126cb41536c91a8a4d6c34b670b664083f617c2684c8f19ffb56e5d768876ff1b0c24d8ec837cfa5d4a5637664d3ad30f6857deacfabd758c05740aecc14ceaa6b171718f1e9ca97dea1c2973edd4741a903e20db05185d071278bc9c9b4c98704eb5e8836ee02de35a7b5b7aa368ab1f227159d6ec1bb1d8bc3fb26f5ede3e40743c232ae27bf34c1adb127be154cbcd860fdbf96b22cd5af9c1ca42d0f7a04f20cdb20d6e363917108ed5edb41c3bcd8f70fa7a1053d6016ebbd4a65c44784a75c2458477cebf457c39a68235e8dec91a4165bc88e9ea7900a6dc88f5d25d2ac9656fda4f6a28b783aedf7031788107b263daf7b0f21012f70c4964efcc76ebfa256e45c98642cbc2390bc0ae9d29e1bbde28c820cd3f7adfcd4ca9566c74366871bc1067934167bf16d45b2ac29934e6a526409a53fef88606503e13c5a38a459dcb4383831c5080a064822ec023c171407944baf620070c5b288e1ba4d7632abd8883b037b5e97341b75103309650aece515af1a2315979bfb547f480e8d59404316e53e710607363281c2bb880fe1f829f258a34d776ab875341c2fa33aa15236381d4ffdf3e1f05340fed21bb5da077983dc9fe2d730622ccc7d205d742bfc71dc832f6d54029ad107b1792a6962355504b005e9ebcd98b2e39bc88e8be0bea371a376a3f032712f89e10c35f2ff32f82cb96d195790a667eb1a601c14f3d48fce573d5a02956bf1d2569116964e2852cee1533294d969e99ef7e813c6d2329335ec3bfca1630721ba58d7ff1356704ac011bf0e25136c109b937d943052776a7fb22091d52a9c9763a613c9d3c3d8f46d79047ba89bced8316499e6220c10bab048dea29885a3a0ec0d62f06800da79699ced933ea3c3a4b4408d2c92b8f3d46560164cceb6645fe4b350460e7bbefe36ed8fd282fdf480388e01ab2927dcfb478a6eb52508df0c07137be9d2f4d4a82c6fa7ca8f214f74227234d2d0bcd1ca00f6d368478d2fd16fff3043384b9ebc186045bd3e66dcf3db8d6b3be7d1c37ebf6361b7ad53acd0dce9170dde4200731cef69c80e9eec90021faadf162e9fe419fb33bf6ef80b8304bc70974f1c03a5d4617c916f07f2c76a746cdb28e0f6763854951cee508ea1a3d318111635eb5b9fc7743fe365c85eaccc16f55a4edc91ff4a004099e105eb52d5a7c5ccb502b7ac790fcfda0257c3e3abb975ba75dacfaee24ab5c974510f8b8a206017f8c03dad6c563936fb30643f082eec6f8eedccc8c49d2148d72cc25ddf71af0978ae6f5c708c53389879b09896f6363f091d9d59715f45bc670b294ee333bc1a863efc1a92eb189f04300f117e6467de101780106b2c3be92ef45e55fa4e2492afe23a844da88e7720e58793068a9c5949f1656d8c92e986681a7d43669d626a3fc4f99d953c73483ebb80ee3b00042cee0f64d736fe74c993d9f6003dabf796186d13d82dd4a917aa8fff07db3816db350e39bf419650fa34bd0425869ad27ccfbcdc6582d19d4fb514e0f25211f6cad7325f01b79ba96e0b7a1c18f743712d31053c3e476ee462641ba6ab2002d088c0e1e131bbbe6ddd40666bf322432ff11d1525e0829fb780ce0f8fc1de4313d6002f464b70ab9e827bd7145dc3c52fc9378ee33bdc219d776d6b5e2290544f2776886f9e63064ab1e1e9bca62de867cc31fe669297b53b840fa8595cff1b830a5321cd0cea3fc08aebeae6a4e92812c33f29900ba3846376f3851150322de48981ec2317fcfd6157ee13d77a48b4c4777fc3e760000000000000068384919ea4d941d353093102ddc3a4eba01bf4df856a5afc2546519e495752863060ef564e23dd6ea2333b633ce40f8cf82a13c99ecc053e691c1eb852bef239c7bea007a660438dcfb57eb11732815800666f1b390b084eba1fb0c4a34daf3c73bb4fabf4c4c4faf";
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
