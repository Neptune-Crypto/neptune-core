use get_size2::GetSize;
use itertools::Itertools;
use rand::rng;
use rand::seq::SliceRandom;
use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::state::wallet::transaction_input::TxInput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum InputSelectionPolicy {
    #[default]
    Random,

    ByNativeCoinAmount(SortOrder),

    // is this useful?
    ByUtxoSize(SortOrder),
    // is something like this possible?
    // eg, so we can order by a particular token amount, like USDT.
    // ByCoinAmount(Coin, SortOrder)

    // I'm unsure how/if this is possible.
    // ByBlockHeight(SortOrder)
}

// note: all fields intentionally private
#[derive(Debug, Default)]
pub struct TxInputListBuilder {
    spendable_inputs: Vec<TxInput>,
    policy: InputSelectionPolicy,
    spend_amount: NativeCurrencyAmount,
}

impl TxInputListBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn spendable_inputs(mut self, inputs: Vec<TxInput>) -> Self {
        self.spendable_inputs = inputs;
        self
    }

    pub fn policy(mut self, policy: InputSelectionPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn spend_amount(mut self, spend_amount: NativeCurrencyAmount) -> Self {
        self.spend_amount = spend_amount;
        self
    }

    pub fn build(self) -> impl IntoIterator<Item = TxInput> {
        let Self {
            mut spendable_inputs,
            policy,
            spend_amount,
        } = self;

        let zero: NativeCurrencyAmount = 0.into();

        // create an ordering for the sequence
        let ordered_iter = match policy {
            InputSelectionPolicy::Random => {
                spendable_inputs.shuffle(&mut rng());
                spendable_inputs.into_iter()
            }

            InputSelectionPolicy::ByNativeCoinAmount(order) => {
                spendable_inputs.into_iter().sorted_by(|a, b| {
                    sort(
                        order,
                        &a.utxo.get_native_currency_amount(),
                        &b.utxo.get_native_currency_amount(),
                    )
                })
            }

            InputSelectionPolicy::ByUtxoSize(order) => spendable_inputs
                .into_iter()
                .sorted_by(|a, b| sort(order, &a.utxo.get_heap_size(), &b.utxo.get_heap_size())),
        };

        // scan sequence until we have enough
        ordered_iter.scan((zero, spend_amount), |(current_amount, target), input| {
            if *current_amount < *target {
                *current_amount = *current_amount + input.utxo.get_native_currency_amount();
                Some(input.clone())
            } else {
                None
            }
        })
    }
}

fn sort<O: Ord>(order: SortOrder, a: &O, b: &O) -> std::cmp::Ordering {
    match order {
        SortOrder::Ascending => Ord::cmp(a, b),
        SortOrder::Descending => Ord::cmp(b, a),
    }
}
