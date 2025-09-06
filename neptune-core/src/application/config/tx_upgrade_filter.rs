use std::str::FromStr;

use tasm_lib::prelude::Digest;

use crate::api::export::TransactionKernelId;

/// Filter rule for TXIDs: Only upgrade transaction if
/// `txid % divisor == remainder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxUpgradeFilter {
    /// Divisor in `txid % divisor` expression.
    divisor: u8,

    /// Remainder after `txid % divisor` division. Must be less than
    /// [`Self::divisor`].
    remainder: u8,
}

impl FromStr for TxUpgradeFilter {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Support format "4:2"
        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() != 2 {
            return Err(format!(
                "Expected two integers separated by ':', got '{}'",
                s
            ));
        }

        let divisor = parts[0].parse::<u8>().map_err(|e| e.to_string())?;
        let remainder = parts[1].parse::<u8>().map_err(|e| e.to_string())?;

        if remainder >= divisor {
            return Err(format!(
                "Invalid filter: remainder ({}) must be less than divisor ({})",
                remainder, divisor
            ));
        }

        if 0 == divisor {
            return Err("Invalid filter: divisor may not be zero.".to_owned());
        }

        Ok(TxUpgradeFilter { divisor, remainder })
    }
}

impl TxUpgradeFilter {
    /// Return the transaction upgrade filter that matches all transactions.
    pub(crate) fn match_all() -> Self {
        Self {
            divisor: 1u8,
            remainder: 0u8,
        }
    }

    pub(crate) fn matches(&self, txid: TransactionKernelId) -> bool {
        let txid: Digest = txid.into();
        let txid: [u8; Digest::BYTES] = txid.into();

        txid.last().unwrap() % self.divisor == self.remainder
    }
}

#[cfg(test)]
mod tests {
    use rand::random;

    use super::*;

    #[test]
    fn parses_valid_tx_filter() {
        let f: TxUpgradeFilter = "4:2".parse().unwrap();
        assert_eq!(f.divisor, 4);
        assert_eq!(f.remainder, 2);
    }

    #[test]
    fn parses_match_all_filter() {
        assert_eq!(TxUpgradeFilter::match_all(), "1:0".parse().unwrap());
    }

    #[test]
    fn rejects_invalid_tx_filter() {
        let err = "4:7".parse::<TxUpgradeFilter>().unwrap_err();
        assert!(
            err.contains("remainder (7) must be less than divisor (4)"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn match_all_filter_matches_all() {
        let num_tests = 50;

        let match_all = TxUpgradeFilter::match_all();
        for _ in 0..num_tests {
            let txid: TransactionKernelId = random();
            assert!(match_all.matches(txid));
        }
    }

    #[test]
    fn matches_half_filter_approximately_half_the_time() {
        let mut matches_1st = 0;
        let mut matches_2nd = 0;

        let first = TxUpgradeFilter {
            divisor: 2,
            remainder: 0,
        };
        let second = TxUpgradeFilter {
            divisor: 2,
            remainder: 1,
        };

        let num_tests = 1000;
        for _ in 0..num_tests {
            let txid: TransactionKernelId = random();
            if first.matches(txid) {
                assert!(!second.matches(txid));
                matches_1st += 1;
            } else if second.matches(txid) {
                assert!(!first.matches(txid));
                matches_2nd += 1;
            } else {
                unreachable!("Math just broke");
            }
        }

        // Probability of failure: Less than 10^(-35)
        assert!(matches_1st < 700);
        assert!(matches_2nd < 700);
    }
}
