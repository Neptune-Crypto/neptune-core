//! provides a builder and related types for selecting which inputs to use in a
//! transaction in order to cover the target spend amount.
//!
//! The `InputSelectionPolicy` enum provides a set of policies for selecting
//! inputs.
//!
//! If one wishes to use custom logic for selecting and ordering inputs
//! that can be done by manipulating the spendable inputs directly, and then
//! pass `InputSelectionPolicy::ByProvidedOrder` to the builder.
//!
//! see [builder](super) for examples of using the builders together.
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use rand::rng;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;

use crate::api::tx_initiation::error;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::wallet::input_candidate::InputCandidate;

/// defines sort ordering: ascending or descending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    /// ascending order
    Ascending,
    /// descending order
    Descending,
}

impl Display for SortOrder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SortOrder::Ascending => "asc",
            SortOrder::Descending => "desc",
        };
        write!(f, "{s}")
    }
}

// ##multicoin## :
//  1. how do we select inputs if spending a token?
//  2. how do we select inputs if input or output utxo represent
//     a smart contract?
//  3. what if input or output utxo(s) contain more than one Coin?

/// Defines a strategy for prioritizing some inputs over others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum InputSelectionPriority {
    /// choose inputs at random
    #[default]
    Random,

    /// Use the order in which the inputs are given to the algorithm.
    ByProvidedOrder,

    /// choose inputs by native currency amount in specified sort order.
    ByNativeCoinAmount(SortOrder),

    /// choose inputs by utxo size (bytes) in specified sort order
    ByUtxoSize(SortOrder),
    // ##multicoin## : is something like this possible?
    // eg, so we can order by a particular token amount, like USDT.
    // ByCoinAmount(Coin, SortOrder)
    ByAge(SortOrder),
}

impl Display for InputSelectionPriority {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InputSelectionPriority::Random => {
                write!(f, "random")
            }
            InputSelectionPriority::ByProvidedOrder => {
                write!(f, "provided-order")
            }
            InputSelectionPriority::ByNativeCoinAmount(order) => {
                write!(f, "native-amount:{order}")
            }
            InputSelectionPriority::ByUtxoSize(order) => {
                write!(f, "utxo-size:{order}")
            }
            InputSelectionPriority::ByAge(order) => {
                write!(f, "age:{order}")
            }
        }
    }
}

impl FromStr for InputSelectionPriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "random" => return Ok(InputSelectionPriority::Random),
            "provided-order" => return Ok(InputSelectionPriority::ByProvidedOrder),
            _ => {}
        }

        // Variants with sort order use `prefix:asc|desc`
        let (prefix, order_str) = s
            .split_once(':')
            .ok_or_else(|| format!("Invalid InputSelectionPriority: '{s}'"))?;

        let sort_order = match order_str {
            "asc" => SortOrder::Ascending,
            "desc" => SortOrder::Descending,
            _ => {
                return Err(format!(
                    "Invalid sort order '{order_str}' in InputSelectionPriority"
                ))
            }
        };

        match prefix {
            "native-amount" => Ok(InputSelectionPriority::ByNativeCoinAmount(sort_order)),
            "utxo-size" => Ok(InputSelectionPriority::ByUtxoSize(sort_order)),
            "age" => Ok(InputSelectionPriority::ByAge(sort_order)),
            _ => Err(format!("Invalid InputSelectionPriority: '{s}'")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InputSelectionPolicy {
    priority: InputSelectionPriority,

    /// Ignore inputs with fewer confirmations than this.
    required_number_of_confirmations: usize,

    /// If set, number of selected inputs will exceed this number.
    max_num_inputs: Option<usize>,

    /// Whether or not the user tolerates lustrations of the inputs.
    accept_lustrations: bool,
}

impl From<InputSelectionPriority> for InputSelectionPolicy {
    fn from(priority: InputSelectionPriority) -> Self {
        Self {
            priority,
            required_number_of_confirmations: 1,
            max_num_inputs: None,
            accept_lustrations: false,
        }
    }
}

impl InputSelectionPolicy {
    pub fn prioritize(mut self, priority: InputSelectionPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn require_confirmations(mut self, required_number_of_confirmations: usize) -> Self {
        self.required_number_of_confirmations = required_number_of_confirmations;
        self
    }

    pub fn cap_num_inputs(mut self, max_num_inputs: usize) -> Self {
        self.max_num_inputs = Some(max_num_inputs);
        self
    }

    pub fn set_lustration_acceptance(mut self, accept_lustrations: bool) -> Self {
        self.accept_lustrations = accept_lustrations;
        self
    }
}

/// a builder to select transaction inputs from all available inputs based on an
/// [InputSelectionPolicy].
///
/// Input selection is a key stage in a complex pipeline connecting the wallet's
/// `MonitoredUtxo`s to the transaction input list on a `TransactionDetails`:
///
/// ```text
///    `WalletState`      |  `MonitoredUtxo`s live in the wallet database, which
///          |            |  is managed by the `WalletState`.
///          |            |
///          |            |  User calls `get_wallet_status` to generate a wallet
///          |            |  status.
///          v
///    `WalletStatus`     |  `WalletStatus` contains a list of all UTXOs the
///          |            |  wallet knows about, both synced and unsynced
///          |            |  fetched from the database and unconfirmed fetched
///          |            |  from the mempool.
///          |            |  The user calls `spendable_inputs` to get a list of
///          |            |  candidate inputs for building a transaction. These
///          |            |  candidate inputs are not unlocked.
///          v
/// `Vec<InputCandidate>` |  The difference between a `InputCandidate` and a raw
///          |            |  UTXO known to be under management by the wallet is
///          |            |  metadata for enforcing a transaction input
///          |            |  selection policy.
///          v
///   `InputSelector`     |  The `InputSelector` makes a selection of the given
///          |            |  inputs suitable for the intended transaction. It
///          |            |  makes this selection based on an
///          |            |  `InputSelectionPolicy`.
///          v
///    `GlobalState`      |  The selected inputs need to be unlocked: extended
///          |            |  membership proofs and witness data that enable the
///          |            |  production of the proofs in the proof collection
///          |            |  relative to these inputs. The reason why this
///          |            |  process involves `GlobalState` is because the
///          |            |  `GlobalState` knows whether it is archival or
///          |            |  light.
///          |            |  If it is a light node, then the membership proofs
///          |            |  are fetched from the wallet. If it is an archival
///          |            |  node, then the membership proofs are fetched from
///          |            |  the archival mutator set. In either case, the
///          |            |  remaining witness data are fetched from the wallet.
///          v
/// `Vec<UnlockedUtxo>`   |  An `UnlockedUtxo` is ready for the proof collection
///          |            |  production step. But as a convenience layer it is
///          |            |  wrapped in a ...
///          v
///     `TxInputs`        |  ... vector new type. The `TxInputs` is what lives
///                       |  on the `TransactionDetails`.
/// ```
#[derive(Debug, Default)]
pub struct InputSelector {
    // note: all fields intentionally private
    input_candidates_inputs: Vec<InputCandidate>,
    policy: InputSelectionPolicy,

    // ##multicoin## : maybe this should be Coin or Vec<Coin> instead of NativeCurrencyAmount?
    spend_amount: NativeCurrencyAmount,

    /// The highest last AOCL leaf that requires lustration.
    lustration_threshold: Option<u64>,
}

impl InputSelector {
    /// instantiate
    pub fn new(lustration_threshold: Option<u64>) -> Self {
        Self {
            lustration_threshold,
            ..Default::default()
        }
    }

    /// set input candidates
    pub fn input_candidates(mut self, inputs: Vec<InputCandidate>) -> Self {
        self.input_candidates_inputs = inputs;
        self
    }

    /// set an input selection policy
    pub fn policy<IntoPolicy>(mut self, policy: IntoPolicy) -> Self
    where
        InputSelectionPolicy: From<IntoPolicy>,
    {
        self.policy = policy.into();
        self
    }

    // ##multicoin## : maybe this should be Coin or Vec<Coin> instead of NativeCurrencyAmount?

    /// set the target spend amount
    pub fn spend_amount(mut self, spend_amount: NativeCurrencyAmount) -> Self {
        self.spend_amount = spend_amount;
        self
    }

    fn filter_by_confirmation_count<'a, InputCandidateIter>(
        &'a self,
        inputs: InputCandidateIter,
    ) -> impl IntoIterator<Item = &'a InputCandidate>
    where
        InputCandidateIter: IntoIterator<Item = &'a InputCandidate>,
    {
        inputs.into_iter().filter(|input_candidate| {
            input_candidate.number_of_confirmations >= self.policy.required_number_of_confirmations
        })
    }

    fn filter_by_lustration_requirement<'a, InputCandidateIter>(
        &'a self,
        inputs: InputCandidateIter,
    ) -> impl IntoIterator<Item = &'a InputCandidate>
    where
        InputCandidateIter: IntoIterator<Item = &'a InputCandidate>,
    {
        inputs.into_iter().filter(|input_candidate| {
            let min_aocl_range = match input_candidate.index_set().aocl_range() {
                Ok((min, _max)) => min,
                Err(err) => panic!("Failed to get AOCL range for input candidate during lustration filtering: {err}"),
            };

            // if lustration is not acceptable, exclude inputs with AOCL range
            // that includes or is less than the lustration threshold.
            self.policy.accept_lustrations
                || self
                    .lustration_threshold
                    .is_none_or(|threshold| threshold >= min_aocl_range)
        })
    }

    fn prioritize<'a, InputCandidateIter>(
        &'a self,
        inputs: InputCandidateIter,
    ) -> impl IntoIterator<Item = &'a InputCandidate>
    where
        InputCandidateIter: IntoIterator<Item = &'a InputCandidate>,
    {
        match self.policy.priority {
            InputSelectionPriority::Random => {
                let mut rng = rng();
                let mut decorated: Vec<_> = inputs
                    .into_iter()
                    .map(|item| (rng.next_u64(), item))
                    .collect();

                decorated.sort_by_key(|(key, _)| *key);

                decorated
                    .into_iter()
                    .map(|(_, item)| item)
                    .collect::<Vec<_>>()
            }
            InputSelectionPriority::ByProvidedOrder => inputs.into_iter().collect::<Vec<_>>(),
            InputSelectionPriority::ByNativeCoinAmount(order) => inputs
                .into_iter()
                .sorted_by(|a, b| {
                    sort(
                        order,
                        &a.utxo.get_native_currency_amount(),
                        &b.utxo.get_native_currency_amount(),
                    )
                })
                .collect::<Vec<_>>(),
            InputSelectionPriority::ByUtxoSize(order) => inputs
                .into_iter()
                .sorted_by(|a, b| sort(order, &a.utxo.get_heap_size(), &b.utxo.get_heap_size()))
                .collect::<Vec<_>>(),

            InputSelectionPriority::ByAge(order) => {
                inputs
                    .into_iter()
                    .sorted_by(|a, b| {
                        sort(order, &a.aocl_leaf_index(), &b.aocl_leaf_index()).reverse()
                        // higher index means smaller age
                    })
                    .collect::<Vec<_>>()
            }
        }
    }

    /// Build the list of transaction inputs, taking `number`-many inputs after
    /// after filtering out policy-incompliant UTXOs and after sorting by
    /// priority.
    pub fn take(self, number: usize) -> Vec<InputCandidate> {
        let iter = self.input_candidates_inputs.iter();
        let iter = self.filter_by_confirmation_count(iter);
        let iter = self.filter_by_lustration_requirement(iter);
        let iter = self.prioritize(iter);
        iter.into_iter().take(number).cloned().collect_vec()
    }

    /// Build the list of transaction inputs, taking inputs filtered for policy-
    /// compliance and sorted by priority until we have enough native currency.
    pub fn build(self) -> Result<Vec<InputCandidate>, error::CreateTxError> {
        // scan sequence until we have enough
        let spend_amount = self.spend_amount;

        // Avoid filtering by lustration requirement here since that's handled
        // better in the loop below.
        let iter = self.input_candidates_inputs.iter();
        let iter = self.filter_by_confirmation_count(iter);
        let iter = self.prioritize(iter);

        let reject_lustrations = !self.policy.accept_lustrations;
        let mut lustration_rejects_acc = NativeCurrencyAmount::zero();

        let mut selected_inputs = vec![];
        let mut current_amount = NativeCurrencyAmount::zero();
        let max_num_inputs = self.policy.max_num_inputs.unwrap_or(usize::MAX);
        for input in iter {
            let value = input.utxo.get_native_currency_amount();
            let aocl_range_min = match input.index_set().aocl_range() {
                Ok((min, _max)) => min,
                Err(err) => return Err(error::CreateTxError::MutatorSetError(err)),
            };
            if reject_lustrations
                && self
                    .lustration_threshold
                    .is_some_and(|threshold| threshold >= aocl_range_min)
            {
                lustration_rejects_acc += value;
                continue;
            }

            if current_amount < spend_amount && max_num_inputs > selected_inputs.len() {
                current_amount += value;
                selected_inputs.push(input.clone());
            } else if max_num_inputs <= selected_inputs.len() {
                // The input priority is incompatible with the maximum number
                // of inputs allowed by the policy.
                return Err(error::CreateTxError::TooManyInputs);
            } else {
                break;
            }
        }

        if current_amount < spend_amount && !lustration_rejects_acc.is_zero() {
            return Err(error::CreateTxError::RequiresLustration);
        }

        Ok(selected_inputs)
    }
}

fn sort<O: Ord>(order: SortOrder, a: &O, b: &O) -> std::cmp::Ordering {
    match order {
        SortOrder::Ascending => Ord::cmp(a, b),
        SortOrder::Descending => Ord::cmp(b, a),
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::*;
    use crate::state::wallet::wallet_status::SyncedUtxo;
    use crate::util_types::mutator_set::shared::WINDOW_SIZE;

    #[expect(clippy::derivable_impls)]
    impl Default for SortOrder {
        // Needed for `strum::EnumIter` derivation in downstream type
        // `InputSelectionPriority`.
        fn default() -> Self {
            Self::Descending
        }
    }

    #[test]
    fn no_panic_in_prioritize() {
        let dummy_inputs = (0..100).map(dummy_input).collect_vec();

        for priority in InputSelectionPriority::iter() {
            let policy = InputSelectionPolicy {
                priority,
                required_number_of_confirmations: 13,
                max_num_inputs: None,
                accept_lustrations: false,
            };
            let input_selector = InputSelector {
                input_candidates_inputs: dummy_inputs.clone(),
                policy,
                spend_amount: NativeCurrencyAmount::coins(100),
                lustration_threshold: None,
            };

            // Ensure no panic when calling `prioritize`
            let _inputs = input_selector.prioritize(&dummy_inputs);
        }
    }

    #[test]
    fn filters_on_lustration_requirement() {
        let dummy_inputs = (0u64..=u64::from(WINDOW_SIZE) * 40)
            .step_by(WINDOW_SIZE as usize)
            .map(dummy_input)
            .collect_vec();
        let num_utxos = dummy_inputs.len();

        let lustration_threshold = Some(u64::from(WINDOW_SIZE) * 2);
        let reject_lustration = InputSelector::new(lustration_threshold)
            .input_candidates(dummy_inputs.clone())
            .policy(InputSelectionPolicy {
                priority: InputSelectionPriority::ByAge(SortOrder::Descending),
                required_number_of_confirmations: 0,
                max_num_inputs: None,
                accept_lustrations: false,
            });

        assert!(
            (reject_lustration
                .filter_by_lustration_requirement(&dummy_inputs)
                .into_iter()
                .count())
                < num_utxos
        );

        let accept_lustration = InputSelector::new(lustration_threshold)
            .input_candidates(dummy_inputs.clone())
            .policy(InputSelectionPolicy {
                priority: InputSelectionPriority::ByAge(SortOrder::Descending),
                required_number_of_confirmations: 0,
                max_num_inputs: None,
                accept_lustrations: true,
            });
        assert_eq!(
            num_utxos,
            accept_lustration
                .filter_by_lustration_requirement(&dummy_inputs)
                .into_iter()
                .count()
        );
    }

    fn dummy_input(aocl_leaf_index: u64) -> InputCandidate {
        InputCandidate {
            synced_utxo: SyncedUtxo::empty_dummy(aocl_leaf_index),
            number_of_confirmations: 14,
        }
    }
}
