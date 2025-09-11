use crate::api::export::NativeCurrencyAmount;

/// The magnitude of the incentive to perform a transaction upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeIncentive {
    /// The transaction is upgraded because fees can be gobbled.
    Gobble(NativeCurrencyAmount),

    /// The transaction is upgraded because we'd like to see it go through for
    /// other reasons than fee-collection. Usually because it affects our
    /// balance in a positive way. This may be because we've already gobbled up
    /// fees from the transaction and we now have an incentive in it being
    /// mined.
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
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UpgradeIncentive {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Implemented such that balance affecting transactions are always
        // prioritized over the chance to gobble fees.
        use std::cmp::Ordering::Equal;
        use std::cmp::Ordering::Greater;
        use std::cmp::Ordering::Less;

        use UpgradeIncentive::BalanceAffecting;
        use UpgradeIncentive::Critical;
        use UpgradeIncentive::Gobble;
        match (self, other) {
            (Gobble(self_amt), Gobble(other_amt)) => self_amt.cmp(other_amt),
            (Gobble(_), _) => Less,
            (BalanceAffecting(_), Gobble(_)) => Greater,
            (BalanceAffecting(self_amt), BalanceAffecting(other_amt)) => self_amt.cmp(other_amt),
            (BalanceAffecting(_), Critical) => Less,
            (Critical, Critical) => Equal,
            (Critical, _) => Greater,
        }
    }
}
