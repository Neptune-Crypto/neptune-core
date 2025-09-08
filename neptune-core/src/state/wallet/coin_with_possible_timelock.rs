use std::fmt::Display;

use itertools::Itertools;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;

use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::timestamp::Timestamp;

/// An amount of Neptune coins, with confirmation timestamp and (if time-locked) its
/// release date. For reporting purposes.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CoinWithPossibleTimeLock {
    pub amount: NativeCurrencyAmount,
    pub confirmed: Timestamp,
    pub release_date: Option<Timestamp>,
}

impl Display for CoinWithPossibleTimeLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let confirmed_total_length = 25;
        let confirmed = self.confirmed.format("%Y-%m-%d %H:%M:%S");
        let confirmed_padding = " ".repeat(confirmed_total_length - confirmed.len());

        let release_total_length = 25;
        let (release, release_padding) = match self.release_date {
            Some(date) => {
                let string = date.format("%Y-%m-%d %H:%M:%S");
                let string_padding = " ".repeat(release_total_length - string.len());
                (string, string_padding)
            }
            None => ("".to_string(), " ".repeat(release_total_length)),
        };

        let amount_total_length = 15;
        let amount_as_string = self.amount.to_string();
        let amount_parts = amount_as_string.split('.').collect_vec();
        let amount_padding_front = " ".repeat(amount_total_length - 3 - amount_parts[0].len());
        let amount_padding_back = if amount_parts.len() > 1 {
            "".to_string()
        } else {
            "   ".to_string()
        };

        write!(f, " {confirmed}{confirmed_padding} {release}{release_padding} {amount_padding_front}{amount_as_string}{amount_padding_back}")
    }
}

impl CoinWithPossibleTimeLock {
    pub fn report(coins: &[Self]) -> String {
        let confirmed_total_length = 25;
        let release_total_length = 25;
        let amount_total_length = 15;
        let total_length = confirmed_total_length + release_total_length + amount_total_length;

        let confirmed = "confirmed";
        let confirmed_padding = " ".repeat(confirmed_total_length - confirmed.len());
        let release_date = "release_date";
        let release_date_padding = " ".repeat(release_total_length - release_date.len());
        let amount = "amount (NPT)";
        let amount_padding = " ".repeat(amount_total_length - amount.len());
        let heading_with_release = format!("{confirmed}{confirmed_padding} {release_date}{release_date_padding} {amount_padding}{amount}");
        let heading_without_release = format!(
            "{confirmed}{confirmed_padding} {} {amount_padding}{amount}",
            " ".repeat(release_total_length)
        );

        let mut result = format!("# coins available\n{heading_without_release}\n");
        result = format!("{result}{}\n", "-".repeat(total_length));
        for coin in coins {
            if coin.release_date.is_some() {
                continue;
            }
            result = format!("{result}{coin}\n");
        }
        result = format!("{result}\n");

        let mut result = format!("{result}# time-locked coins\n{heading_with_release}\n");
        result = format!("{result}{}\n", "-".repeat(total_length));
        for coin in coins {
            if coin.release_date.is_none() {
                continue;
            }
            result = format!("{result}{coin}\n");
        }
        result = format!("{result}\n");

        let total_available = coins
            .iter()
            .filter(|c| c.release_date.is_none())
            .map(|c| c.amount)
            .sum::<NativeCurrencyAmount>();
        result = format!("{result}total available: {total_available} NPT\n");

        let total_timelocked = coins
            .iter()
            .filter(|c| c.release_date.is_some())
            .map(|c| c.amount)
            .sum::<NativeCurrencyAmount>();
        if !total_timelocked.is_zero() {
            result = format!("{result}total time-locked: {total_timelocked} NPT\n");
        }
        result
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use arbitrary::Arbitrary;
    use arbitrary::Unstructured;
    use rand::Rng;
    use rand::RngCore;

    use super::CoinWithPossibleTimeLock;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;

    #[test]
    fn sample_report() {
        let mut rng = rand::rng();
        let num_coins = rng.random_range(0..20);
        let mut coins = vec![];
        for _ in 0..num_coins {
            let coin = CoinWithPossibleTimeLock {
                amount: if rng.random::<bool>() {
                    NativeCurrencyAmount::coins(rng.next_u32() % 100000)
                } else {
                    NativeCurrencyAmount::arbitrary(&mut Unstructured::new(
                        &rng.random::<[u8; 32]>(),
                    ))
                    .unwrap()
                },
                release_date: if rng.random::<bool>() {
                    Some(rng.random::<Timestamp>())
                } else {
                    None
                },
                confirmed: rng.random::<Timestamp>(),
            };
            coins.push(coin);
        }

        println!("{}", CoinWithPossibleTimeLock::report(&coins));
    }
}
