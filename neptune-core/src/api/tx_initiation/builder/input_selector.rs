//! provides a builder and related types for selecting which inputs to use in a
//! transaction in order to cover the target spend amount.
//!
//! all spendable inputs may be obtained via
//! [TransactionInitiator::spendable_inputs()](super::super::initiator::TransactionInitiator::spendable_inputs()).
//!
//! The `InputSelectionPolicy` enum provides a set of policies for selecting
//! inputs.
//!
//! If one wishes to use custom logic for selecting and ordering inputs
//! that can be done by manipulating the spendable inputs directly, and then
//! pass `InputSelectionPolicy::ByProvidedOrder` to the builder.
//!
//! see [builder](super) for examples of using the builders together.
use get_size2::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use rand::rng;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;

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

// ##multicoin## :
//  1. how do we select inputs if spending a token?
//  2. how do we select inputs if input or output utxo represent
//     a smart contract?
//  3. what if input or output utxo(s) contain more than one Coin?

/// Defines a strategy for prioritizing some inputs over others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InputSelectionPolicy {
    priority: InputSelectionPriority,

    /// Ignore inputs with fewer confirmations than this.
    required_number_of_confirmations: usize,
}

impl From<InputSelectionPriority> for InputSelectionPolicy {
    fn from(priority: InputSelectionPriority) -> Self {
        Self {
            priority,
            required_number_of_confirmations: 1,
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
}

impl InputSelector {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
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
                inputs.into_iter().sorted_by_key(|_| rng.next_u64())
            }
            InputSelectionPriority::ByProvidedOrder => {
                // leave input order unchanged.
                let mut i = 0;
                inputs.into_iter().sorted_by_key(|_| {
                    i += 1;
                    i
                })
            }
            InputSelectionPriority::ByNativeCoinAmount(order) => {
                inputs.into_iter().sorted_by(|a, b| {
                    sort(
                        order,
                        &a.utxo.get_native_currency_amount(),
                        &b.utxo.get_native_currency_amount(),
                    )
                })
            }
            InputSelectionPriority::ByUtxoSize(order) => inputs
                .into_iter()
                .sorted_by(|a, b| sort(order, &a.utxo.get_heap_size(), &b.utxo.get_heap_size())),

            InputSelectionPriority::ByAge(order) => {
                inputs.into_iter().sorted_by(|a, b| {
                    sort(order, &a.aocl_leaf_index(), &b.aocl_leaf_index()).reverse()
                    // higher index means smaller age
                })
            }
        }
    }

    /// Build the list of transaction inputs, taking `number`-many inputs after
    /// after filtering out policy-incompliant UTXOs and after sorting by
    /// priority.
    pub fn take(self, number: usize) -> Vec<InputCandidate> {
        let iter = self.input_candidates_inputs.iter();
        let iter = self.filter_by_confirmation_count(iter);
        let iter = self.prioritize(iter);
        iter.into_iter().take(number).cloned().collect_vec()
    }

    /// Build the list of transaction inputs, taking inputs filtered for policy-
    /// compliance and sorted by priority until we have enough native currency.
    pub fn build(self) -> Vec<InputCandidate> {
        // scan sequence until we have enough
        let zero: NativeCurrencyAmount = NativeCurrencyAmount::zero();
        let spend_amount = self.spend_amount;

        let iter = self.input_candidates_inputs.iter();
        let iter = self.filter_by_confirmation_count(iter);
        let iter = self.prioritize(iter);
        iter.into_iter()
            .scan((zero, spend_amount), |(current_amount, target), input| {
                if *current_amount < *target {
                    *current_amount += input.utxo.get_native_currency_amount();
                    Some(input.clone())
                } else {
                    None
                }
            })
            .collect_vec()
    }
}

fn sort<O: Ord>(order: SortOrder, a: &O, b: &O) -> std::cmp::Ordering {
    match order {
        SortOrder::Ascending => Ord::cmp(a, b),
        SortOrder::Descending => Ord::cmp(b, a),
    }
}
