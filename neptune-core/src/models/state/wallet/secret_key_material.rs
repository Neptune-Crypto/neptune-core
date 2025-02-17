use anyhow::Result;
use bip39::Mnemonic;
use itertools::Itertools;
use num_traits::ConstZero;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;
use strum::Display;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::XFieldElement;
use tasm_lib::twenty_first::prelude::Polynomial;
use tasm_lib::twenty_first::xfe;
use zeroize::Zeroize;

/// Holds the secret seed of a wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretKeyMaterial(pub(crate) XFieldElement);

impl Zeroize for SecretKeyMaterial {
    fn zeroize(&mut self) {
        self.0 = XFieldElement::zero();
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

        let polynomial_coefficients = (0..t)
            .map(|i| if i == 0 { self.0 } else { rng.random() })
            .collect_vec();

        let evaluation_indices = (1..=n).collect_vec();
        let evaluation_points = evaluation_indices.iter().map(|i| xfe!(*i)).collect_vec();
        let secret_shares =
            Polynomial::new(polynomial_coefficients).batch_evaluate(&evaluation_points);
        Ok(evaluation_indices
            .into_iter()
            .zip(secret_shares.into_iter().map(SecretKeyMaterial))
            .collect_vec())
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

        let ordinates = indices.iter().map(|i| xfe!(*i)).collect_vec();
        indices.sort();
        indices.dedup();
        if indices.len() != ordinates.len() {
            return Err(ShamirSecretSharingError::DuplicateIndex);
        }
        if ordinates.contains(&XFieldElement::ZERO) {
            return Err(ShamirSecretSharingError::InvalidShare);
        }

        let abscissae = shares.into_iter().map(|(_, y)| y.0).collect_vec();
        let polynomial = Polynomial::interpolate(&ordinates, &abscissae);
        if polynomial.degree() > 0 && polynomial.degree() as usize >= t {
            return Err(ShamirSecretSharingError::InconsistentShares);
        }

        let p0 = polynomial.evaluate(XFieldElement::ZERO);
        Ok(SecretKeyMaterial(p0))
    }

    /// Convert a seed phrase into [`SecretKeyMaterial`].
    ///
    /// The returned secret key material is wrapped in a `Result`, which is
    /// `Err` if the words are not 18 valid BIP-39 words.
    pub fn from_phrase(phrase: &[String]) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(&phrase.iter().join(" "), bip39::Language::English)?;
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
        Ok(Self(xfe))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod shamir {
        use proptest::prelude::Just;
        use proptest::prop_assert_eq;
        use proptest_arbitrary_interop::arb;
        use test_strategy::proptest;

        use super::*;

        #[proptest]
        fn happy_path_all_shares(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial(s);
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
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let mut rng = StdRng::from_seed(seed);
            let secret_key = SecretKeyMaterial(s);
            let mut shares = secret_key
                .share_shamir(t, n, rng.random())
                .expect("sharing on happy path should succeed");
            let selected_shares = (0..t)
                .map(|_| shares.swap_remove(rng.random_range(0..shares.len())))
                .collect_vec();
            let recombination = SecretKeyMaterial::combine_shamir(t, selected_shares)
                .expect("recombining on happy path should succeed");

            prop_assert_eq!(secret_key, recombination);
        }

        #[proptest]
        fn catch_quorum_too_small(
            #[strategy(2usize..20)] n: usize,
            #[strategy(0usize..=1)] t: usize,
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial(s);
            prop_assert_eq!(
                secret_key.share_shamir(t, n, seed),
                Err(ShamirSecretSharingError::QuorumTooSmall)
            );
        }

        #[proptest]
        fn catch_impossible_recombination(
            #[strategy(2usize..20)] n: usize,
            #[strategy(#n+1..30)] t: usize,
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial(s);
            prop_assert_eq!(
                secret_key.share_shamir(t, n, seed),
                Err(ShamirSecretSharingError::ImpossibleRecombination)
            );
        }

        #[proptest]
        fn catch_not_enough_shares_to_split(
            #[strategy(Just(0usize))] n: usize,
            #[strategy(2usize..10)] t: usize,
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let secret_key = SecretKeyMaterial(s);
            prop_assert_eq!(
                secret_key.share_shamir(t, n, seed),
                Err(ShamirSecretSharingError::NotEnoughSharesToSplit)
            );
        }

        #[proptest]
        fn catch_too_few_shares_to_recombine(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let mut rng = StdRng::from_seed(seed);
            let secret_key = SecretKeyMaterial(s);
            let mut shares = secret_key
                .share_shamir(t, n, rng.random())
                .expect("sharing on happy path should succeed");
            let selected_shares = (0..t - 1)
                .map(|_| shares.swap_remove(rng.random_range(0..shares.len())))
                .collect_vec();
            prop_assert_eq!(
                SecretKeyMaterial::combine_shamir(t, selected_shares),
                Err(ShamirSecretSharingError::TooFewSharesToRecombine)
            );
        }

        #[proptest]
        fn catch_invalid_share(
            #[strategy(2usize..20)] n: usize,
            #[strategy(2usize..=#n)] t: usize,
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let mut rng = StdRng::from_seed(seed);
            let secret_key = SecretKeyMaterial(s);
            let mut shares = secret_key
                .share_shamir(t, n, rng.random())
                .expect("sharing on happy path should succeed");
            let mut selected_shares = (0..t - 1)
                .map(|_| shares.swap_remove(rng.random_range(0..shares.len())))
                .collect_vec();
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
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let mut rng = StdRng::from_seed(seed);
            let secret_key = SecretKeyMaterial(s);
            let mut shares = secret_key
                .share_shamir(t, n, rng.random())
                .expect("sharing on happy path should succeed");
            let mut selected_shares = (0..t - 1)
                .map(|_| shares.swap_remove(rng.random_range(0..shares.len())))
                .collect_vec();
            let duplicate_share =
                selected_shares[rng.random_range(0..selected_shares.len())].clone();
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
            #[strategy(arb())] s: XFieldElement,
            #[strategy([arb(); 32])] seed: [u8; 32],
        ) {
            let mut rng = StdRng::from_seed(seed);
            let secret_key = SecretKeyMaterial(s);
            let mut shares_a = secret_key
                .share_shamir(t, n, rng.random())
                .expect("sharing on happy path should succeed");
            let mut shares_b = secret_key
                .share_shamir(t, n, rng.random())
                .expect("sharing on happy path should succeed");

            // Make a random selection of t+1 shares such that both sharings are
            // represented. There can be no duplicate indices so n > t.
            let mut selected_shares = vec![];
            let insert_unique_index =
                |collection: &mut Vec<_>, share: (usize, SecretKeyMaterial)| {
                    if !collection.iter().any(|(i, _)| *i == share.0) {
                        collection.push(share);
                        false
                    } else {
                        true
                    }
                };

            // add one share a, randomly selected
            insert_unique_index(
                &mut selected_shares,
                shares_a.swap_remove(rng.random_range(0..shares_a.len())),
            );

            // add one from b, randomly selected, and make sure it gets added
            // even if we get an index collision on the first guess
            while insert_unique_index(
                &mut selected_shares,
                shares_b.swap_remove(rng.random_range(0..shares_b.len())),
            ) {}

            // complete the collection by drawing randomly from a or b when
            // possible
            while selected_shares.len() < t + 1 {
                let next_share = if shares_a.is_empty() && shares_b.is_empty() {
                    panic!("cannot happen: both were populated with more than 2 elements");
                } else if !shares_a.is_empty() && shares_b.is_empty() {
                    shares_a.swap_remove(rng.random_range(0..shares_a.len()))
                } else if shares_a.is_empty() && !shares_b.is_empty() {
                    shares_b.swap_remove(rng.random_range(0..shares_b.len()))
                } else if rng.random() {
                    shares_a.swap_remove(rng.random_range(0..shares_a.len()))
                } else {
                    shares_b.swap_remove(rng.random_range(0..shares_b.len()))
                };
                insert_unique_index(&mut selected_shares, next_share);
            }

            prop_assert_eq!(
                SecretKeyMaterial::combine_shamir(t, selected_shares),
                Err(ShamirSecretSharingError::InconsistentShares)
            );
        }
    }
}
