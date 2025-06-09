use std::ops::Add;

use crate::api::export::NativeCurrencyAmount;
use crate::main_loop::upgrade_incentive::UpgradeIncentive;

/// Used by memory pool subscribers to indicate how interested they are in
/// a specific transaction.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize))]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub(crate) enum UpgradePriority {
    #[default]
    Irrelevant,

    /// There's a certain amount of interest.
    ///
    /// For example, wallets can use the sum of the outputs the transaction
    /// sends to them.
    Interested(NativeCurrencyAmount),

    /// The transaction in question is of the highest possible priority. Wallets
    /// should use this for transactions they have initiated.
    Critical,
}

impl From<UpgradeIncentive> for UpgradePriority {
    fn from(incentive: UpgradeIncentive) -> Self {
        match incentive {
            UpgradeIncentive::Gobble(amount) => UpgradePriority::Interested(amount),
            UpgradeIncentive::BalanceAffecting(amount) => UpgradePriority::Interested(amount),
            UpgradeIncentive::Critical => UpgradePriority::Critical,
        }
    }
}

impl PartialOrd for UpgradePriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (UpgradePriority::Irrelevant, UpgradePriority::Irrelevant) => {
                Some(std::cmp::Ordering::Equal)
            }
            (UpgradePriority::Irrelevant, _) => Some(std::cmp::Ordering::Less),
            (UpgradePriority::Interested(_), UpgradePriority::Irrelevant) => {
                Some(std::cmp::Ordering::Greater)
            }
            (UpgradePriority::Interested(self_amt), UpgradePriority::Interested(other_amt)) => {
                self_amt.partial_cmp(other_amt)
            }
            (UpgradePriority::Interested(_), UpgradePriority::Critical) => {
                Some(std::cmp::Ordering::Less)
            }
            (UpgradePriority::Critical, UpgradePriority::Critical) => {
                Some(std::cmp::Ordering::Equal)
            }
            (UpgradePriority::Critical, _) => Some(std::cmp::Ordering::Greater),
        }
    }
}
impl Ord for UpgradePriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).expect("Ord must be implemented.")
    }
}

impl UpgradePriority {
    /// Returns true if the priority is irrelevant.
    pub(crate) fn is_irrelevant(&self) -> bool {
        matches!(self, UpgradePriority::Irrelevant)
    }

    /// Given the gobbling potential of the transaction, return the incentive to
    /// perform an upgrade.
    pub(crate) fn incentive_given_gobble_potential(
        &self,
        gobbling_potential: NativeCurrencyAmount,
    ) -> UpgradeIncentive {
        match self {
            UpgradePriority::Irrelevant => UpgradeIncentive::Gobble(gobbling_potential),
            UpgradePriority::Interested(native_currency_amount) => {
                UpgradeIncentive::BalanceAffecting(*native_currency_amount)
            }
            UpgradePriority::Critical => UpgradeIncentive::Critical,
        }
    }
}

impl Add for UpgradePriority {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        match (self, other) {
            (UpgradePriority::Irrelevant, _) => other,
            (_, UpgradePriority::Irrelevant) => self,
            (UpgradePriority::Interested(self_amt), UpgradePriority::Interested(other_amt)) => {
                UpgradePriority::Interested(self_amt + other_amt)
            }
            (_, UpgradePriority::Critical) | (UpgradePriority::Critical, _) => {
                UpgradePriority::Critical
            }
        }
    }
}
