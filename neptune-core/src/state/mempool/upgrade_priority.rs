use std::ops::Add;

use get_size2::GetSize;

use crate::api::export::NativeCurrencyAmount;
use crate::application::loops::main_loop::upgrade_incentive::UpgradeIncentive;

/// Used by memory pool subscribers to indicate how interested they are in
/// a specific transaction.
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, GetSize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub enum UpgradePriority {
    #[default]
    Irrelevant,

    /// There's a certain amount of interest.
    ///
    /// For example, wallets can use the sum of the outputs the transaction
    /// sends to them. Should also be used when this node has upgraded the
    /// transaction.
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
        Some(self.cmp(other))
    }
}

impl Ord for UpgradePriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::Equal;
        use std::cmp::Ordering::Greater;
        use std::cmp::Ordering::Less;

        use UpgradePriority::Critical;
        use UpgradePriority::Interested;
        use UpgradePriority::Irrelevant;
        match (self, other) {
            (Irrelevant, Irrelevant) => Equal,
            (Irrelevant, _) => Less,
            (Interested(_), Irrelevant) => Greater,
            (Interested(self_amt), Interested(other_amt)) => self_amt.cmp(other_amt),
            (Interested(_), Critical) => Less,
            (Critical, Critical) => Equal,
            (Critical, _) => Greater,
        }
    }
}

impl UpgradePriority {
    /// Returns true if the priority is irrelevant.
    pub(crate) fn is_irrelevant(&self) -> bool {
        *self == UpgradePriority::Irrelevant
    }

    /// Given the gobbling potential of the transaction, return the incentive to
    /// perform an upgrade.
    pub(crate) fn incentive_given_gobble_potential(
        &self,
        gobbling_potential: NativeCurrencyAmount,
    ) -> UpgradeIncentive {
        use UpgradePriority::Critical;
        use UpgradePriority::Interested;
        use UpgradePriority::Irrelevant;
        match self {
            Irrelevant => UpgradeIncentive::Gobble(gobbling_potential),
            Interested(native_currency_amount) => {
                UpgradeIncentive::BalanceAffecting(*native_currency_amount)
            }
            Critical => UpgradeIncentive::Critical,
        }
    }
}

impl Add for UpgradePriority {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        use UpgradePriority::Critical;
        use UpgradePriority::Interested;
        use UpgradePriority::Irrelevant;
        match (self, other) {
            (Irrelevant, _) => other,
            (_, Irrelevant) => self,
            (Interested(self_amt), Interested(other_amt)) => Interested(self_amt + other_amt),
            (_, Critical) | (Critical, _) => Critical,
        }
    }
}
