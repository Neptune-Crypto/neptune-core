use std::fmt::Display;
use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::protocol::consensus::type_scripts::known_type_scripts::is_known_type_script_with_valid_state;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct Coin {
    pub type_script_hash: Digest,
    pub state: Vec<BFieldElement>,
}

impl Display for Coin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = if self.type_script_hash == NativeCurrency.hash() {
            let amount = match NativeCurrencyAmount::decode(&self.state) {
                Ok(boxed_amount) => boxed_amount.to_string(),
                Err(_) => "Error: Unable to decode amount".to_owned(),
            };
            format!("Native currency: {amount}")
        } else if self.type_script_hash == TimeLock.hash() {
            let release_date = self.release_date().unwrap();
            format!("Timelock until: {release_date}")
        } else {
            "Unknown type script hash".to_owned()
        };

        write!(f, "{}", output)
    }
}

impl Coin {
    pub fn release_date(&self) -> Option<Timestamp> {
        if self.type_script_hash == TimeLock.hash() {
            Timestamp::decode(&self.state).ok().map(|b| *b)
        } else {
            None
        }
    }

    pub fn new_native_currency(amount: NativeCurrencyAmount) -> Self {
        Self {
            type_script_hash: NativeCurrency.hash(),
            state: amount.encode(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject)]
pub struct Utxo {
    lock_script_hash: Digest,
    coins: Vec<Coin>,
}

impl Display for Utxo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.coins
                .iter()
                .enumerate()
                .map(|(i, coin)| format!("coin {i}: {coin}"))
                .join("; ")
        )
    }
}

impl GetSize for Utxo {
    fn get_stack_size() -> usize {
        size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        let mut total = self.lock_script_hash().get_heap_size();
        for v in &self.coins {
            total += size_of::<Digest>();
            total += v.state.len() * size_of::<BFieldElement>();
        }

        total
    }
}

impl Utxo {
    pub fn new(lock_script_hash: Digest, coins: Vec<Coin>) -> Self {
        Self {
            lock_script_hash,
            coins,
        }
    }

    pub fn coins(&self) -> &[Coin] {
        &self.coins
    }

    pub fn lock_script_hash(&self) -> Digest {
        self.lock_script_hash
    }

    pub fn new_native_currency(lock_script_hash: Digest, amount: NativeCurrencyAmount) -> Self {
        Self {
            coins: vec![Coin::new_native_currency(amount)],
            lock_script_hash,
        }
    }

    /// Add to the amount of the UTXO with a delta.
    pub(crate) fn add_to_amount(mut self, delta: NativeCurrencyAmount) -> Self {
        let current_amount = self.get_native_currency_amount();
        let new_amount = current_amount + delta;
        let new_amount = Coin::new_native_currency(new_amount);
        let remove = self
            .coins
            .iter()
            .find_position(|coin| coin.type_script_hash == NativeCurrency.hash());
        if let Some((idx, _)) = remove {
            self.coins[idx] = new_amount;
        } else {
            self.coins.push(new_amount);
        };

        self
    }

    pub fn has_native_currency(&self) -> bool {
        self.coins
            .iter()
            .any(|coin| coin.type_script_hash == NativeCurrency.hash())
    }

    /// Return all type script hashes referenced by any coin in any UTXO,
    /// without duplicates.
    ///
    /// Always includes [`NativeCurrency`].
    pub(crate) fn type_script_hashes<'a, I: Iterator<Item = &'a Self>>(utxos: I) -> Vec<Digest> {
        vec![NativeCurrency.hash()]
            .into_iter()
            .chain(
                utxos
                    .into_iter()
                    .flat_map(|utxo| utxo.coins.iter().map(|c| c.type_script_hash).collect_vec()),
            )
            .unique()
            .collect()
    }

    /// Get the amount of native currency that are encapsulated in this UTXO,
    /// regardless of which other coins are present. (Even if that makes the
    /// native currency unspendable.)
    pub fn get_native_currency_amount(&self) -> NativeCurrencyAmount {
        crate::macros::log_slow_scope!();
        self.coins
            .iter()
            .filter(|coin| coin.type_script_hash == NativeCurrency.hash())
            .map(|coin| match NativeCurrencyAmount::decode(&coin.state) {
                Ok(boxed_amount) => *boxed_amount,
                Err(_) => NativeCurrencyAmount::zero(),
            })
            .sum()
    }

    /// If the UTXO has a timelock, find out what the release date is.
    pub fn release_date(&self) -> Option<Timestamp> {
        self.coins.iter().find_map(Coin::release_date)
    }

    /// Test the coins for state validity, relative to known type scripts.
    pub fn all_type_script_states_are_valid(&self) -> bool {
        self.coins.iter().all(is_known_type_script_with_valid_state)
    }

    /// Determine if the UTXO can be spent at a given date in the future,
    /// assuming it can be unlocked. Currently, this boils down to checking
    /// whether it has a time lock and if it does, verifying that the release
    /// date is in the past.
    pub fn can_spend_at(&self, timestamp: Timestamp) -> bool {
        crate::macros::log_slow_scope!();
        // unknown type script
        if !self.all_type_script_states_are_valid() {
            return false;
        }

        // decode and test release date(s) (if any)
        for state in self
            .coins
            .iter()
            .filter(|c| c.type_script_hash == TimeLock.hash())
            .map(|c| c.state.clone())
        {
            match Timestamp::decode(&state) {
                Ok(release_date) => {
                    if timestamp <= *release_date {
                        return false;
                    }
                }
                Err(_) => {
                    return false;
                }
            };
        }

        true
    }

    /// Adds a time-lock coin, if necessary.
    ///
    /// Does nothing if there is a time lock present already whose release date
    /// is later than the argument.
    pub(crate) fn with_time_lock(self, release_date: Timestamp) -> Self {
        if self.release_date().is_some_and(|x| x >= release_date) {
            self
        } else {
            let mut coins = self
                .coins
                .into_iter()
                .filter(|c| c.type_script_hash != TimeLock.hash())
                .collect_vec();
            coins.push(TimeLock::until(release_date));
            Self {
                lock_script_hash: self.lock_script_hash,
                coins,
            }
        }
    }

    /// Determine whether there is a time-lock, with any release date, on the
    /// UTXO.
    pub(crate) fn is_timelocked(&self) -> bool {
        self.coins
            .iter()
            .filter_map(Coin::release_date)
            .any(|_| true)
    }
}

/// Make `Utxo` hashable with `StdHash` for using it in `HashMap`.
///
/// The Clippy warning is safe to suppress, because we do not violate the invariant: k1 == k2 => hash(k1) == hash(k2).
impl StdHash for Utxo {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.encode(), state);
    }
}

impl Distribution<Utxo> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Utxo {
        Utxo::new(
            rng.random(),
            NativeCurrencyAmount::coins(rng.next_u32() % 42000000).to_native_coins(),
        )
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use super::*;

    impl<'a> Arbitrary<'a> for Utxo {
        /// Produce a strategy for "arbitrary" UTXOs where "arbitrary" means:
        ///  - lock script corresponding to an arbitrary generation address
        ///  - one coin of type NativeCurrency and arbitrary, non-negative amount.
        fn arbitrary(u: &mut ::arbitrary::Unstructured<'a>) -> ::arbitrary::Result<Self> {
            let lock_script_hash: Digest = Digest::arbitrary(u)?;
            let type_script_hash = NativeCurrency.hash();
            let amount = NativeCurrencyAmount::arbitrary(u)?.abs();
            let coins = vec![Coin {
                type_script_hash,
                state: amount.encode(),
            }];
            Ok(Utxo::new(lock_script_hash, coins))
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;
    use tracing_test::traced_test;

    use super::*;
    use crate::protocol::consensus::transaction::lock_script::LockScript;
    use crate::triton_vm::prelude::*;

    impl Utxo {
        pub(crate) fn with_coin(mut self, coin: Coin) -> Self {
            self.coins.push(coin);
            self
        }

        pub(crate) fn append_to_coin_state(
            mut self,
            coin_index: usize,
            new_element: BFieldElement,
        ) -> Self {
            self.coins[coin_index].state.push(new_element);
            self
        }

        pub(crate) fn empty_dummy() -> Self {
            Self {
                lock_script_hash: Digest::default(),
                coins: vec![],
            }
        }

        pub(crate) fn dummy_with_num_coins(num_coins: usize) -> Self {
            let dummy_coin = Coin {
                type_script_hash: Digest::default(),
                state: vec![],
            };
            Self {
                lock_script_hash: Digest::default(),
                coins: vec![dummy_coin.clone(); num_coins],
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn hash_utxo_test(output in arb::<Utxo>()) {
            let _digest = Tip5::hash(&output);
        }
    }

    #[traced_test]
    #[proptest]
    fn serialization_test(#[strategy(arb::<Utxo>())] utxo: Utxo) {
        let serialized: String = serde_json::to_string(&utxo).unwrap();
        let utxo_again: Utxo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(utxo, utxo_again);
    }

    #[proptest]
    fn utxo_timelock_test(
        #[strategy(0_u64..1 << 63)]
        #[map(|t| Timestamp(bfe!(t)))]
        release_date: Timestamp,
        #[strategy(0_u64..1 << 63)]
        #[map(|t| Timestamp(bfe!(t)))]
        #[filter(Timestamp::zero() < #delta && #delta <= #release_date)]
        delta: Timestamp,
    ) {
        let no_lock = LockScript::new(triton_program!(halt));
        let mut coins = NativeCurrencyAmount::coins(1).to_native_coins();
        coins.push(TimeLock::until(release_date));
        let utxo = Utxo::new(no_lock.hash(), coins);

        prop_assert!(!utxo.can_spend_at(release_date - delta));
        prop_assert!(utxo.is_timelocked());

        let epsilon = Timestamp::millis(1);
        prop_assert!(!utxo.can_spend_at(release_date - epsilon));
        prop_assert!(!utxo.can_spend_at(release_date));
        prop_assert!(utxo.can_spend_at(release_date + epsilon));
        prop_assert!(utxo.can_spend_at(release_date + delta));
    }

    #[test]
    fn always_include_native_currency_type_script() {
        assert!(Utxo::type_script_hashes([].iter()).contains(&NativeCurrency.hash()));
        let utxo = Utxo {
            lock_script_hash: Digest::default(),
            coins: vec![],
        };
        assert!(Utxo::type_script_hashes([utxo].iter()).contains(&NativeCurrency.hash()));
    }
}
