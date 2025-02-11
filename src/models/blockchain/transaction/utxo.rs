use std::fmt::Display;
use std::hash::Hash as StdHash;
use std::hash::Hasher as StdHasher;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::tip5::Digest;

use super::lock_script::LockScript;
use crate::models::blockchain::type_scripts::known_type_scripts::is_known_type_script_with_valid_state;
use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::blockchain::type_scripts::time_lock::TimeLock;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::address::hash_lock_key::HashLockKey;
use crate::prelude::twenty_first;

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
        // self.lock_script.get_heap_size() + self.coins.len() * (std::mem::size_of::<Digest>())
        let mut total = self.lock_script_hash().get_heap_size();
        for v in self.coins.iter() {
            total += size_of::<Digest>();
            total += v.state.len() * size_of::<BFieldElement>();
        }

        total
    }
}

impl From<(Digest, Vec<Coin>)> for Utxo {
    fn from((lock_script_hash, coins): (Digest, Vec<Coin>)) -> Self {
        Self {
            lock_script_hash,
            coins,
        }
    }
}

impl Utxo {
    pub fn new(lock_script: LockScript, coins: Vec<Coin>) -> Self {
        (lock_script.hash(), coins).into()
    }

    pub fn coins(&self) -> &[Coin] {
        &self.coins
    }

    pub fn lock_script_hash(&self) -> Digest {
        self.lock_script_hash
    }

    /// Returns true iff this UTXO is a lock script with the preimage provided
    /// as input argument.
    pub(crate) fn is_lockscript_with_preimage(&self, preimage: Digest) -> bool {
        self.lock_script_hash == HashLockKey::from_preimage(preimage).lock_script_hash()
    }

    pub fn new_native_currency(lock_script: LockScript, amount: NativeCurrencyAmount) -> Self {
        Self::new(lock_script, vec![Coin::new_native_currency(amount)])
    }

    pub fn has_native_currency(&self) -> bool {
        self.coins
            .iter()
            .any(|coin| coin.type_script_hash == NativeCurrency.hash())
    }

    /// Get the amount of Neptune coins that are encapsulated in this UTXO,
    /// regardless of which other coins are present. (Even if that makes the
    /// Neptune coins unspendable.)
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
        self.coins.iter().filter_map(Coin::release_date).next()
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

    /// Determine whether the only thing preventing the UTXO from being spendable
    /// is the timelock whose according release date is in the future.
    pub fn is_timelocked_but_otherwise_spendable_at(&self, timestamp: Timestamp) -> bool {
        if !self.all_type_script_states_are_valid() {
            return false;
        }

        self.coins
            .iter()
            .filter_map(Coin::release_date)
            .any(|release_date| timestamp <= release_date)
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
}

/// Make `Utxo` hashable with `StdHash` for using it in `HashMap`.
///
/// The Clippy warning is safe to suppress, because we do not violate the invariant: k1 == k2 => hash(k1) == hash(k2).
#[allow(clippy::derived_hash_with_manual_eq)]
impl StdHash for Utxo {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        StdHash::hash(&self.encode(), state);
    }
}

/// Generate a UTXO pseudorandomly, for testing purposes
pub fn pseudorandom_utxo(seed: [u8; 32]) -> Utxo {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    Utxo::from((
        rng.random(),
        NativeCurrencyAmount::coins(rng.next_u32() % 42000000).to_native_coins(),
    ))
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
            Ok((lock_script_hash, coins).into())
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;
    use rand::Rng;
    use test_strategy::proptest;
    use tracing_test::traced_test;

    use super::*;
    use crate::triton_vm::prelude::*;

    fn make_random_utxo() -> Utxo {
        let mut rng = rand::rng();
        let lock_script = LockScript::anyone_can_spend();
        let lock_script_hash = lock_script.hash();
        let num_coins = rng.random_range(0..10);
        let mut coins = vec![];
        for _i in 0..num_coins {
            let amount = NativeCurrencyAmount::from_raw_i128(
                rng.random_range(0i128..=NativeCurrencyAmount::MAX_NAU),
            );
            coins.push(Coin::new_native_currency(amount));
        }

        (lock_script_hash, coins).into()
    }

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
    }

    #[test]
    fn hash_utxo_test() {
        let output = make_random_utxo();
        let _digest = crate::Hash::hash(&output);
    }

    #[traced_test]
    #[test]
    fn serialization_test() {
        let utxo = make_random_utxo();
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
        let utxo = Utxo::new(no_lock, coins);

        prop_assert!(!utxo.can_spend_at(release_date - delta));
        prop_assert!(utxo.is_timelocked_but_otherwise_spendable_at(release_date - delta));

        let epsilon = Timestamp::millis(1);
        prop_assert!(!utxo.can_spend_at(release_date - epsilon));
        prop_assert!(!utxo.can_spend_at(release_date));
        prop_assert!(utxo.can_spend_at(release_date + epsilon));
        prop_assert!(utxo.can_spend_at(release_date + delta));
        prop_assert!(!utxo.is_timelocked_but_otherwise_spendable_at(release_date + delta));
    }
}
