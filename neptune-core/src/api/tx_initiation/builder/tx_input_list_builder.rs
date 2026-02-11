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
use num_traits::Zero;
use rand::rng;
use rand::seq::SliceRandom;
use serde::Deserialize;
use serde::Serialize;

use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::state::wallet::transaction_input::TxInput;

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

/// defines a policy for selecting from available transaction inputs in order
/// to cover the target spend amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum InputSelectionPolicy {
    /// choose inputs at random
    #[default]
    Random,

    /// use the natural order of the provided inputs.
    ByProvidedOrder,

    /// choose inputs by native currency amount in specified sort order.
    ByNativeCoinAmount(SortOrder),

    /// choose inputs by utxo size (bytes) in specified sort order
    ByUtxoSize(SortOrder),
    // ##multicoin## : is something like this possible?
    // eg, so we can order by a particular token amount, like USDT.
    // ByCoinAmount(Coin, SortOrder)

    // I'm unsure how/if this is possible (to lookup block-height of input confirmation)
    // ByBlockHeight(SortOrder)
}

/// a builder to select transaction inputs from all available inputs based on an
/// [InputSelectionPolicy].
#[derive(Debug, Default)]
pub struct TxInputListBuilder {
    // note: all fields intentionally private
    spendable_inputs: Vec<TxInput>,
    policy: InputSelectionPolicy,

    // ##multicoin## : maybe this should be Coin or Vec<Coin> instead of NativeCurrencyAmount?
    spend_amount: NativeCurrencyAmount,

    /// Maximum number of inputs to select. `None` means no limit.
    max_inputs: Option<usize>,
}

impl TxInputListBuilder {
    /// instantiate
    pub fn new() -> Self {
        Default::default()
    }

    /// set available spendable inputs.  These may be obtained via
    /// [spendable_inputs()](super::super::initiator::TransactionInitiator::spendable_inputs())
    pub fn spendable_inputs(mut self, inputs: Vec<TxInput>) -> Self {
        self.spendable_inputs = inputs;
        self
    }

    /// set an input selection policy
    pub fn policy(mut self, policy: InputSelectionPolicy) -> Self {
        self.policy = policy;
        self
    }

    // ##multicoin## : maybe this should be Coin or Vec<Coin> instead of NativeCurrencyAmount?

    /// set the target spend amount
    pub fn spend_amount(mut self, spend_amount: NativeCurrencyAmount) -> Self {
        self.spend_amount = spend_amount;
        self
    }

    /// set optional max number of inputs to select
    pub fn max_inputs(mut self, max_inputs: Option<usize>) -> Self {
        self.max_inputs = max_inputs;
        self
    }

    /// build the list of transaction inputs.
    ///
    /// When `max_inputs` is set, uses a sliding window on the sorted inputs
    /// to find the smallest subset (fewest inputs first) that covers the
    /// spend amount. When `max_inputs` is `None`, uses a greedy scan.
    pub fn build(self) -> Vec<TxInput> {
        let Self {
            mut spendable_inputs,
            policy,
            spend_amount,
            max_inputs,
        } = self;

        // apply ordering
        match policy {
            InputSelectionPolicy::Random => {
                spendable_inputs.shuffle(&mut rng());
            }
            InputSelectionPolicy::ByProvidedOrder => {}
            InputSelectionPolicy::ByNativeCoinAmount(order) => {
                spendable_inputs.sort_by(|a, b| {
                    sort(
                        order,
                        &a.utxo.get_native_currency_amount(),
                        &b.utxo.get_native_currency_amount(),
                    )
                });
            }
            InputSelectionPolicy::ByUtxoSize(order) => {
                spendable_inputs
                    .sort_by(|a, b| sort(order, &a.utxo.get_heap_size(), &b.utxo.get_heap_size()));
            }
        }

        match max_inputs {
            Some(limit) => {
                // UTXO consolidation: pick the best window of up to `limit`
                // contiguous inputs (sorted ascending) that covers the spend
                // amount while maximizing the number of small UTXOs consumed.
                // Try from the smallest end first; slide right if needed.
                let max_window = limit.min(spendable_inputs.len());

                // Try full window first (max consolidation), slide to find
                // the window starting at the smallest possible index.
                for start in 0..=(spendable_inputs.len() - max_window) {
                    let window = &spendable_inputs[start..start + max_window];
                    let sum = window
                        .iter()
                        .fold(NativeCurrencyAmount::zero(), |acc, input| {
                            acc + input.utxo.get_native_currency_amount()
                        });
                    if sum >= spend_amount {
                        return window.to_vec();
                    }
                }

                // No valid window found — return empty (caller handles insufficient funds)
                Vec::new()
            }
            None => {
                // Greedy scan: take inputs in order until target is met
                let mut collected = Vec::new();
                let mut current = NativeCurrencyAmount::zero();
                for input in spendable_inputs {
                    if current >= spend_amount {
                        break;
                    }
                    current += input.utxo.get_native_currency_amount();
                    collected.push(input);
                }
                collected
            }
        }
    }
}

fn sort<O: Ord>(order: SortOrder, a: &O, b: &O) -> std::cmp::Ordering {
    match order {
        SortOrder::Ascending => Ord::cmp(a, b),
        SortOrder::Descending => Ord::cmp(b, a),
    }
}
