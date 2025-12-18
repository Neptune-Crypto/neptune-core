use std::fmt::Display;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Div;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Neg;
use std::ops::Sub;
use std::ops::SubAssign;

use anyhow::Result;
use bip39::Mnemonic;
use bip39::MnemonicType;
use itertools::Itertools;
use num_traits::ConstOne;
use num_traits::ConstZero;
use num_traits::One;
use num_traits::Zero;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;
use strum::Display;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::prelude::Polynomial;
use zeroize::Zeroize;

use crate::prelude::triton_vm::prelude::FiniteField;
use crate::prelude::triton_vm::prelude::XFieldElement;
use crate::prelude::twenty_first::bfe_vec;
use crate::prelude::twenty_first::bfieldcodec_derive::BFieldCodec;
use crate::prelude::twenty_first::math::traits::CyclicGroupGenerator;
use crate::prelude::twenty_first::math::traits::ModPowU64;
use crate::prelude::twenty_first::math::traits::PrimitiveRootOfUnity;
use crate::prelude::twenty_first::prelude::Inverse;
use crate::prelude::twenty_first::prelude::ModPowU32;
use crate::prelude::twenty_first::xfe;

/// Holds the secret seed of a wallet.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub enum SecretKeyMaterial {
    V0(XFieldElement),
    V1(BField32Bytes),
}

impl Zeroize for SecretKeyMaterial {
    fn zeroize(&mut self) {
        match self {
            SecretKeyMaterial::V0(x) => *x = XFieldElement::zero(),
            SecretKeyMaterial::V1(x) => *x = BField32Bytes::zero(),
        };
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Display)]
pub enum ShamirSecretSharingError {
    /// When t = 0 or t = 1, Shamir secret sharing is disallowed because (t=0)
    /// it is impossible or (t=1) all shares contain all of the information
    /// about the secret being shared, undermining the security benefits.
    QuorumTooSmall,

    /// When t > n, Shamir secret sharing is disallowed because it would be
    /// impossible to reconstruct the original secret from *all* of the shares,
    /// let alone a smaller quorum.
    ImpossibleRecombination,

    /// When n < 1, there are no shares to hand out, so Shamir secret sharing
    /// is disallowed.
    NotEnoughSharesToSplit,

    /// Attempting to combine <t shares from a t-out-of-n Shamir secret sharing
    /// scheme will fail because the original sharing polynomial cannot uniquely
    /// be determined.
    TooFewSharesToRecombine,

    /// You should not be able to issue a share corresponding to the evaluation
    /// of the sharing polynomial at 0, as this share is identical to the
    /// original secret.
    InvalidShare,

    /// When trying to reconstruct the original secret from a list of >=t
    /// shares, it is important to guarantee that all shares have distinct
    /// indices. Otherwise, there is either a duplicate share (both coordinates
    /// are the same) and redundant information is provided, or else there is
    /// a pair of inconsistent shares (having the same x-coordinate and
    /// different y-coordinates).
    DuplicateIndex,

    /// When combining >t shares from a t-out-of-n Shamir secret sharing scheme,
    /// the reconstructed sharing polynomial should be of degree (at most) t.
    /// If this not the case, at least one of the shares is corrupt.
    InconsistentShares,
}

impl SecretKeyMaterial {
    /// The version of the secret key material.
    pub fn version(&self) -> u8 {
        match self {
            SecretKeyMaterial::V0(_) => 0, // mnemonic with 18 words
            SecretKeyMaterial::V1(_) => 1, // mnemonic with 24 words
        }
    }

    /// Split the secret across n shares such that combining any t of them
    /// yields the secret again.
    ///
    /// A t-out-of-n Shamir secret sharing scheme defines a polynomial p(X) of
    /// degree at most t with uniformly random coefficients except the constant
    /// coefficient, which is equal to the secret S being shared, *i.e.*,
    /// p(0) = S . The shares are then (i, p(i)) for i in 1..=n.
    ///
    /// Upon combining t (or more) shares, one reproduces the original secret S
    /// by first interpolating the polynomial through the t points, and then by
    /// evaluating this polynomial in zero.
    ///
    /// This function is responsible for the splitting part.
    /// [`combine_shamir`](Self::combine_shamir) does the recombination.
    pub fn share_shamir(
        &self,
        t: usize,
        n: usize,
        seed: [u8; 32],
    ) -> Result<Vec<(usize, Self)>, ShamirSecretSharingError> {
        if n < 1 {
            return Err(ShamirSecretSharingError::NotEnoughSharesToSplit);
        }
        if t < 2 {
            return Err(ShamirSecretSharingError::QuorumTooSmall);
        }
        if t > n {
            return Err(ShamirSecretSharingError::ImpossibleRecombination);
        }
        let mut rng = StdRng::from_seed(seed);

        match self {
            SecretKeyMaterial::V0(sk) => {
                let polynomial_coefficients = (0..t)
                    .map(|i| if i == 0 { *sk } else { rng.random() })
                    .collect_vec();

                let evaluation_indices = (1..=n).collect_vec();
                let evaluation_points = evaluation_indices.iter().map(|i| xfe!(*i)).collect_vec();
                let secret_shares = Polynomial::new(polynomial_coefficients)
                    .batch_evaluate(&evaluation_points)
                    .iter()
                    .map(|e| Self::V0(*e))
                    .collect_vec();
                Ok(evaluation_indices
                    .into_iter()
                    .zip(secret_shares)
                    .collect_vec())
            }
            SecretKeyMaterial::V1(sk) => {
                let polynomial_coefficients = (0..t)
                    .map(|i| if i == 0 { *sk } else { rng.random() })
                    .collect_vec();

                let evaluation_indices = (1..=n).collect_vec();
                let evaluation_points = evaluation_indices
                    .iter()
                    .map(|i| BField32Bytes::new_const(BFieldElement::from(*i as u64)))
                    .collect_vec();
                let secret_shares = Polynomial::new(polynomial_coefficients)
                    .batch_evaluate(&evaluation_points)
                    .iter()
                    .map(|e| Self::V1(*e))
                    .collect_vec();
                Ok(evaluation_indices.into_iter().zip(secret_shares).collect())
            }
        }
    }

    /// Combine a quorum of Shamir secret shares into one.
    ///
    /// See [`share_shamir`](Self::share_shamir).
    pub fn combine_shamir(
        t: usize,
        shares: Vec<(usize, SecretKeyMaterial)>,
    ) -> Result<SecretKeyMaterial, ShamirSecretSharingError> {
        if shares.len() < t {
            return Err(ShamirSecretSharingError::TooFewSharesToRecombine);
        }

        let mut indices = shares.iter().map(|(i, _)| *i).collect_vec();

        match shares[0].1 {
            SecretKeyMaterial::V0(_) => {
                if shares
                    .iter()
                    .any(|(_, y)| !matches!(y, SecretKeyMaterial::V0(_)))
                {
                    return Err(ShamirSecretSharingError::InconsistentShares);
                }

                let ordinates = indices
                    .iter()
                    .map(|i| XFieldElement::new_const(BFieldElement::from(*i as u64)))
                    .collect_vec();
                indices.sort();
                indices.dedup();
                if indices.len() != ordinates.len() {
                    return Err(ShamirSecretSharingError::DuplicateIndex);
                }
                if ordinates.contains(&XFieldElement::ZERO) {
                    return Err(ShamirSecretSharingError::InvalidShare);
                }
                let abscissae = shares
                    .into_iter()
                    .map(|(_, y)| {
                        if let SecretKeyMaterial::V0(x) = y {
                            x
                        } else {
                            unreachable!()
                        }
                    })
                    .collect_vec();
                let polynomial = Polynomial::interpolate(&ordinates, &abscissae);
                if polynomial.degree() > 0 && polynomial.degree() as usize >= t {
                    return Err(ShamirSecretSharingError::InconsistentShares);
                }

                let p0 = polynomial.evaluate(XFieldElement::ZERO);
                Ok(SecretKeyMaterial::V0(p0))
            }

            SecretKeyMaterial::V1(_) => {
                if shares
                    .iter()
                    .any(|(_, y)| !matches!(y, SecretKeyMaterial::V1(_)))
                {
                    return Err(ShamirSecretSharingError::InconsistentShares);
                }

                let ordinates = indices
                    .iter()
                    .map(|i| BField32Bytes::new_const(BFieldElement::from(*i as u64)))
                    .collect_vec();
                indices.sort();
                indices.dedup();
                if indices.len() != ordinates.len() {
                    return Err(ShamirSecretSharingError::DuplicateIndex);
                }
                if ordinates.contains(&BField32Bytes::ZERO) {
                    return Err(ShamirSecretSharingError::InvalidShare);
                }

                let abscissae = shares
                    .into_iter()
                    .map(|(_, y)| {
                        if let SecretKeyMaterial::V1(x) = y {
                            x
                        } else {
                            unreachable!()
                        }
                    })
                    .collect_vec();
                let polynomial = Polynomial::interpolate(&ordinates, &abscissae);
                if polynomial.degree() > 0 && polynomial.degree() as usize >= t {
                    return Err(ShamirSecretSharingError::InconsistentShares);
                }

                let p0 = polynomial.evaluate(BField32Bytes::ZERO);
                Ok(SecretKeyMaterial::V1(p0))
            }
        }
    }

    /// Convert a seed phrase into [`SecretKeyMaterial`].
    ///
    /// The returned secret key material is wrapped in a `Result`, which is
    /// `Err` if the words are not 24 or 18 valid BIP-39 words.
    pub fn from_phrase(phrase: &[String]) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(&phrase.join(" "), bip39::Language::English)?;
        match MnemonicType::for_word_count(phrase.len())? {
            MnemonicType::Words18 => {
                let secret_seed: [u8; 24] = mnemonic.entropy().try_into()?;
                let xfe = XFieldElement::new(
                    secret_seed
                        .chunks(8)
                        .map(|ch| u64::from_le_bytes(ch.try_into().unwrap()))
                        .map(BFieldElement::new)
                        .collect_vec()
                        .try_into()
                        .unwrap(),
                );
                Ok(Self::V0(xfe))
            }
            MnemonicType::Words24 => {
                let secret_seed: [u8; 32] = mnemonic.entropy().try_into()?;
                let xfe = BField32Bytes::new(
                    secret_seed
                        .chunks(8)
                        .map(|ch| u64::from_le_bytes(ch.try_into().unwrap()))
                        .map(BFieldElement::new)
                        .collect_vec()
                        .try_into()
                        .unwrap(),
                );
                Ok(Self::V1(xfe))
            }
            _ => unreachable!(),
        }
    }

    /// Convert the secret key material into a BIP-39 phrase consisting of 24
    /// words (for 256 bits of entropy).
    pub fn to_phrase(&self) -> Vec<String> {
        match self {
            SecretKeyMaterial::V0(sk) => {
                let entropy = sk
                    .coefficients
                    .iter()
                    .flat_map(|bfe| bfe.value().to_le_bytes())
                    .collect_vec();
                assert_eq!(
                    entropy.len(),
                    24,
                    "Entropy for secret seed does not consist of 24 bytes."
                );
                let mnemonic = Mnemonic::from_entropy(&entropy, bip39::Language::English)
                    .expect("Wrong entropy length (should be 24 bytes).");
                mnemonic
                    .phrase()
                    .split(' ')
                    .map(|s| s.to_string())
                    .collect_vec()
            }
            SecretKeyMaterial::V1(sk) => {
                let entropy =
                    sk.0.iter()
                        .flat_map(|bfe| bfe.value().to_le_bytes())
                        .collect_vec();
                assert_eq!(
                    entropy.len(),
                    32,
                    "Entropy for secret seed does not consist of 32 bytes."
                );
                let mnemonic = Mnemonic::from_entropy(&entropy, bip39::Language::English)
                    .expect("Wrong entropy length (should be 32 bytes).");
                mnemonic
                    .phrase()
                    .split(' ')
                    .map(|s| s.to_string())
                    .collect_vec()
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, BFieldCodec)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct BField32Bytes(pub(crate) [BFieldElement; 4]);

impl Distribution<BField32Bytes> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BField32Bytes {
        BField32Bytes(rng.random())
    }
}

impl Display for BField32Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl ConstOne for BField32Bytes {
    const ONE: Self = Self([
        BFieldElement::ONE,
        BFieldElement::ZERO,
        BFieldElement::ZERO,
        BFieldElement::ZERO,
    ]);
}

impl One for BField32Bytes {
    fn one() -> Self {
        Self::ONE
    }
}

impl Mul<Self> for BField32Bytes {
    type Output = Self;

    #[allow(clippy::many_single_char_names)]
    #[inline]
    fn mul(self, other: Self) -> Self {
        // (a x^3 + b x^2 + c x + d) * (e x^3 + f x^2 + g x + h) mod (x^4 + x + 1)
        let [d, c, b, a] = self.0; // c0..c3
        let [h, g, f, e] = other.0;

        // Raw (before reduction)
        let u0 = d * h; // x^0
        let u1 = d * g + c * h; // x^1
        let u2 = d * f + c * g + b * h; // x^2
        let u3 = d * e + c * f + b * g + a * h; // x^3
        let u4 = c * e + b * f + a * g; // x^4
        let u5 = b * e + a * f; // x^5
        let u6 = a * e; // x^6

        // Reduction inline using x^4 = -x -1:
        // x^4  -> -x -1
        // x^5  -> -x^2 - x
        // x^6  -> -x^3 - x^2

        let r0 = u0 - u4 - u5 - u6; // constant
        let r1 = u1 - u4 - u5; // x^1
        let r2 = u2 - u5 - u6; // x^2
        let r3 = u3 - u6; // x^3

        Self::new([r0, r1, r2, r3])
    }
}

impl Sub<Self> for BField32Bytes {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Div<Self> for BField32Bytes {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        rhs.inverse() * self
    }
}

impl Neg for BField32Bytes {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.map(Neg::neg))
    }
}

impl AddAssign for BField32Bytes {
    fn add_assign(&mut self, rhs: Self) {
        for i in 0..self.0.len() {
            self.0[i] += rhs.0[i]
        }
    }
}

impl MulAssign for BField32Bytes {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl SubAssign for BField32Bytes {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl CyclicGroupGenerator for BField32Bytes {
    fn get_cyclic_group_elements(&self, max: Option<usize>) -> Vec<Self> {
        let mut val = *self;
        let mut ret: Vec<Self> = vec![Self::one()];

        loop {
            ret.push(val);
            val *= *self;
            if val.is_one() || max.is_some() && ret.len() >= max.unwrap() {
                break;
            }
        }
        ret
    }
}

impl PrimitiveRootOfUnity for BField32Bytes {
    fn primitive_root_of_unity(n: u64) -> Option<Self> {
        let b_root = BFieldElement::primitive_root_of_unity(n);
        Some(Self([
            b_root?,
            BFieldElement::ZERO,
            BFieldElement::ZERO,
            BFieldElement::ZERO,
        ]))
    }
}

impl Inverse for BField32Bytes {
    fn inverse(&self) -> Self {
        assert!(
            !self.is_zero(),
            "Cannot invert the zero element in the extension field."
        );
        let self_as_poly: Polynomial<BFieldElement> = Polynomial::new(self.0.to_vec());
        let (_, a, _) = Polynomial::<BFieldElement>::xgcd(self_as_poly, Self::shah_polynomial());
        a.into()
    }
}

impl ModPowU32 for BField32Bytes {
    fn mod_pow_u32(&self, exp: u32) -> Self {
        self.mod_pow_u64(u64::from(exp))
    }
}

impl ModPowU64 for BField32Bytes {
    #[inline]
    fn mod_pow_u64(&self, exponent: u64) -> Self {
        let mut x = *self;
        let mut result = Self::one();
        let mut i = exponent;

        while i > 0 {
            if i & 1 == 1 {
                result *= x;
            }

            x *= x;
            i >>= 1;
        }

        result
    }
}

impl From<u64> for BField32Bytes {
    fn from(value: u64) -> Self {
        BField32Bytes::new_const(value.into())
    }
}
impl FiniteField for BField32Bytes {}

impl Mul<BField32Bytes> for BFieldElement {
    type Output = BField32Bytes;

    #[inline]
    fn mul(self, other: BField32Bytes) -> BField32Bytes {
        let coefficients = other.0.map(|c| c * self);
        BField32Bytes(coefficients)
    }
}

impl Mul<BFieldElement> for BField32Bytes {
    type Output = Self;

    #[inline]
    fn mul(self, other: BFieldElement) -> Self {
        let coefficients = self.0.map(|c| c * other);
        Self(coefficients)
    }
}

impl MulAssign<BFieldElement> for BField32Bytes {
    #[inline]
    fn mul_assign(&mut self, rhs: BFieldElement) {
        *self = *self * rhs;
    }
}

impl From<Polynomial<'_, BFieldElement>> for BField32Bytes {
    fn from(poly: Polynomial<'_, BFieldElement>) -> Self {
        let (_, rem) = poly.naive_divide(&Self::shah_polynomial());
        let mut xfe = [BFieldElement::ZERO; 4];

        let Ok(rem_degree) = usize::try_from(rem.degree()) else {
            return Self::ZERO;
        };
        xfe[..=rem_degree].copy_from_slice(&rem.coefficients()[..=rem_degree]);

        BField32Bytes(xfe)
    }
}

impl Zero for BField32Bytes {
    fn zero() -> Self {
        Self::ZERO
    }

    fn is_zero(&self) -> bool {
        self == &Self::ZERO
    }
}

impl Add<Self> for BField32Bytes {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut res = self;
        for (i, x) in res.0.iter_mut().enumerate() {
            *x += rhs.0[i];
        }
        res
    }
}

impl ConstZero for BField32Bytes {
    const ZERO: Self = Self([BFieldElement::ZERO; 4]);
}

impl<T: Into<BFieldElement>> From<[T; 4]> for BField32Bytes {
    fn from(value: [T; 4]) -> Self {
        Self(value.map(|e| e.into()))
    }
}

impl BField32Bytes {
    #[inline]
    pub fn shah_polynomial() -> Polynomial<'static, BFieldElement> {
        // todo hduoc: check
        // x^4 + x + 1
        Polynomial::new(bfe_vec![1, 1, 0, 0, 1])
    }
    const fn new_const(e: BFieldElement) -> Self {
        Self([
            e,
            BFieldElement::ZERO,
            BFieldElement::ZERO,
            BFieldElement::ZERO,
        ])
    }

    fn new(elements: [BFieldElement; 4]) -> Self {
        Self(elements)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    mod phrase_conversion {
        use rand::rng;

        use super::*;

        proptest::proptest! {
            #[test]
            fn phrase_conversion_works(
                secret in proptest_arbitrary_interop::arb::<BField32Bytes>()
            ) {
                let wallet_secret = SecretKeyMaterial::V1(secret);
                let phrase = wallet_secret.to_phrase();
                let wallet_again = SecretKeyMaterial::from_phrase(&phrase).unwrap();
                let phrase_again = wallet_again.to_phrase();

                assert_eq!(wallet_secret, wallet_again);
                assert_eq!(phrase, phrase_again);
            }
        }

        #[test]
        fn bad_phrase_conversion_fails() {
            let wallet_secret = SecretKeyMaterial::V1(rng().random());
            let mut phrase = wallet_secret.to_phrase();
            phrase.push("blank".to_string());
            assert!(SecretKeyMaterial::from_phrase(&phrase).is_err());
            assert!(SecretKeyMaterial::from_phrase(&phrase[0..phrase.len() - 2]).is_err());
            phrase[0] = "bbb".to_string();
            assert!(SecretKeyMaterial::from_phrase(&phrase[0..phrase.len() - 1]).is_err());
        }
    }

    mod shamir {
        use proptest::prelude::Just;
        use proptest::prop_assert_eq;
        use proptest::prop_assume;
        use proptest::sample;
        use proptest_arbitrary_interop::arb;
        use test_strategy::proptest;

        use super::*;

        #[proptest]
        fn happy_path_all_shares(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            let shares = secret_key
                .share_shamir(t, n, seed)
                .expect("sharing on happy path should succeed");
            let recombination = SecretKeyMaterial::combine_shamir(t, shares)
                .expect("recombining on happy path should succeed");

            prop_assert_eq!(secret_key, recombination);
        }

        #[proptest]
        fn happy_path_t_shares(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
            #[strategy(sample::subsequence((0..#n).collect_vec(), #t))] indices: Vec<usize>,
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            let shares = secret_key
                .share_shamir(t, n, seed)
                .expect("sharing on happy path should succeed");
            let selected_shares = indices.into_iter().map(|i| shares[i]).collect_vec(); // #arbitraryHashSetIterator
            let recombination = SecretKeyMaterial::combine_shamir(t, selected_shares)
                .expect("recombining on happy path should succeed");

            prop_assert_eq!(secret_key, recombination);
        }

        #[proptest]
        fn catch_quorum_too_small(
            #[strategy(2usize..20)] n: usize,
            #[strategy(0usize..=1)] t: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            prop_assert_eq!(
                secret_key.share_shamir(t, n, seed),
                Err(ShamirSecretSharingError::QuorumTooSmall)
            );
        }

        #[proptest]
        fn catch_impossible_recombination(
            #[strategy(2usize..20)] n: usize,
            #[strategy(#n+1..30)] t: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            prop_assert_eq!(
                secret_key.share_shamir(t, n, seed),
                Err(ShamirSecretSharingError::ImpossibleRecombination)
            );
        }

        #[proptest]
        fn catch_not_enough_shares_to_split(
            #[strategy(Just(0usize))] n: usize,
            #[strategy(2usize..10)] t: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            prop_assert_eq!(
                secret_key.share_shamir(t, n, seed),
                Err(ShamirSecretSharingError::NotEnoughSharesToSplit)
            );
        }

        #[proptest]
        fn catch_too_few_shares_to_recombine(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(sample::subsequence((0..#n).collect_vec(), #t - 1))] indices: Vec<usize>,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            let shares = secret_key
                .share_shamir(t, n, seed)
                .expect("sharing on happy path should succeed");
            let selected_shares = indices.into_iter().map(|i| shares[i]).collect_vec();
            prop_assert_eq!(
                SecretKeyMaterial::combine_shamir(t, selected_shares),
                Err(ShamirSecretSharingError::TooFewSharesToRecombine)
            );
        }

        #[proptest]
        fn catch_invalid_share(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
            #[strategy(sample::subsequence((0..#n).collect_vec(), #t - 1))] indices: Vec<usize>,
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            let shares = secret_key
                .share_shamir(t, n, seed)
                .expect("sharing on happy path should succeed");
            let mut selected_shares = indices.into_iter().map(|i| shares[i]).collect_vec();
            let invalid_share = (0, secret_key);
            selected_shares.push(invalid_share);
            prop_assert_eq!(
                SecretKeyMaterial::combine_shamir(t, selected_shares),
                Err(ShamirSecretSharingError::InvalidShare)
            );
        }

        #[proptest]
        fn catch_duplicate_index(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(0usize..#t - 1)] dup_ind: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed: [u8; 32],
            #[strategy(sample::subsequence((0..#t).collect_vec(), #t - 1))] indices: Vec<usize>,
        ) {
            let secret_key = SecretKeyMaterial::V1(s);
            let shares = secret_key
                .share_shamir(t, n, seed)
                .expect("sharing on happy path should succeed");
            let mut selected_shares = indices.into_iter().map(|i| shares[i]).collect_vec();
            let duplicate_share = selected_shares[dup_ind];
            selected_shares.push(duplicate_share);
            println!("selected shares: {:?}", selected_shares);
            prop_assert_eq!(
                SecretKeyMaterial::combine_shamir(t, selected_shares),
                Err(ShamirSecretSharingError::DuplicateIndex)
            );
        }

        #[proptest]
        fn catch_inconsistent_shares(
            #[strategy(3usize..20)] n: usize,
            #[strategy(2usize..#n)] t: usize,
            #[strategy(arb())] s: BField32Bytes,
            #[strategy([arb(); 32])] seed_a: [u8; 32],
            #[strategy([arb(); 32])] seed_b: [u8; 32],
            #[strategy(sample::subsequence((0..#n).collect_vec(), #t + 1))] indices: Vec<usize>,
            #[strategy(proptest::collection::vec(proptest::prelude::any::<bool>(), #t + 1))]
            choices: Vec<bool>,
        ) {
            // Make a random selection of t+1 shares such that both sharings are represented. There can be no duplicate indices.
            prop_assume!(choices.iter().any(|x| x != &choices[0]));
            // nothing to test here if the sharings are identical
            prop_assume!(seed_a != seed_b);

            let secret_key = SecretKeyMaterial::V1(s);
            let shares_a = secret_key
                .share_shamir(t, n, seed_a)
                .expect("sharing on happy path should succeed");
            let shares_b = secret_key
                .share_shamir(t, n, seed_b)
                .expect("sharing on happy path should succeed");

            let mut selected_shares = Vec::with_capacity(t + 1);
            for (index, choice) in std::iter::zip(indices, choices) {
                if choice {
                    selected_shares.push(shares_b[index]);
                } else {
                    selected_shares.push(shares_a[index]);
                }
            }

            prop_assert_eq!(
                SecretKeyMaterial::combine_shamir(t, selected_shares),
                Err(ShamirSecretSharingError::InconsistentShares)
            );
        }
    }

    mod secret_key_material {
        use crate::state::wallet::secret_key_material::SecretKeyMaterial;

        #[test]
        fn test_parse_json() {
            let sk: SecretKeyMaterial = serde_json::from_str("[10885651799413792391,15419758986129414034,2225506014986644298,13704052757432991042]").unwrap();
            assert!(matches!(sk, SecretKeyMaterial::V1(_)));
            let sk2: SecretKeyMaterial = serde_json::from_str(
                "{\"coefficients\":[5223899872919692492,9765490249295514317,5978636154531078456]}",
            )
            .unwrap();
            assert!(matches!(sk2, SecretKeyMaterial::V0(_)));
        }
    }
}
