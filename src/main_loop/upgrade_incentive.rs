use crate::api::export::NativeCurrencyAmount;

/// Enumerate the incentive to perform a transaction upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeIncentive {
    /// The transaction is upgraded because fees can be gobbled.
    Gobble(NativeCurrencyAmount),

    /// The transaction is upgraded because we'd like to see it go through for
    /// other reasons that fee-collection. Usually because it affects our
    /// balance, in either positive or negative direction.
    BalanceAffecting(NativeCurrencyAmount),

    /// The transaction is upgraded because it is critical, e.g. a transaction
    /// that we initiated.
    Critical,
}

impl UpgradeIncentive {
    pub(crate) fn upgrade_is_worth_it(&self, min_gobbling_fee: NativeCurrencyAmount) -> bool {
        match self {
            UpgradeIncentive::Gobble(gobble_amt) => *gobble_amt >= min_gobbling_fee,
            _ => true,
        }
    }

    /// On successful proof-upgrading, the new transaction will affect our
    /// balance in the case fees were gobbled. Return the upgrade incentive as
    /// it looks after a successful proof-upgrading.
    pub(crate) fn after_upgrade(self) -> Self {
        match self {
            UpgradeIncentive::Critical => UpgradeIncentive::Critical,
            UpgradeIncentive::Gobble(native_currency_amount) => {
                UpgradeIncentive::BalanceAffecting(native_currency_amount)
            }
            UpgradeIncentive::BalanceAffecting(native_currency_amount) => {
                UpgradeIncentive::BalanceAffecting(native_currency_amount)
            }
        }
    }
}

impl PartialOrd for UpgradeIncentive {
    // Implemented such that balance affecting transactions are always
    // prioritized over the chance to gobble fees.
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (UpgradeIncentive::Gobble(self_amt), UpgradeIncentive::Gobble(other_amt)) => {
                Some(self_amt.cmp(other_amt))
            }
            (UpgradeIncentive::Gobble(_), _) => Some(std::cmp::Ordering::Less),
            (UpgradeIncentive::BalanceAffecting(_), UpgradeIncentive::Gobble(_)) => {
                Some(std::cmp::Ordering::Greater)
            }
            (
                UpgradeIncentive::BalanceAffecting(self_amt),
                UpgradeIncentive::BalanceAffecting(other_amt),
            ) => Some(self_amt.cmp(other_amt)),
            (UpgradeIncentive::BalanceAffecting(_), UpgradeIncentive::Critical) => {
                Some(std::cmp::Ordering::Less)
            }
            (UpgradeIncentive::Critical, UpgradeIncentive::Critical) => {
                Some(std::cmp::Ordering::Equal)
            }
            (UpgradeIncentive::Critical, _) => Some(std::cmp::Ordering::Greater),
        }
    }
}

impl Ord for UpgradeIncentive {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).expect("Ord must be implemented.")
    }
}
