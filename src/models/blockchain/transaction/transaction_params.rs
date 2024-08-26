//! This module implements TxParams which is used as input to
//! create_transaction() and the send() rpc.
use num_traits::CheckedSub;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::consensus::timestamp::Timestamp;

use super::TxInputList;
use super::TxOutputList;

/// represents validation errors when constructing TxParams
#[derive(Debug, Clone, Error)]
pub enum TxParamsError {
    #[error("inputs ({inputs_sum}) is less than outputs ({outputs_sum})")]
    InsufficientInputs {
        inputs_sum: NeptuneCoins,
        outputs_sum: NeptuneCoins,
    },

    #[error("negative amount is not permitted for inputs or outputs")]
    NegativeAmount,
}

// About serialization+validation
//
// the goal is to validate inside the impl Deserialize to ensure
// correct-by-construction using the "parse, don't validate" design philosophy.
//
// unfortunately serde does not yet directly support validating when using
// derive Deserialize.  So a workaround pattern is to create a shadow
// struct with the same fields that gets deserialized without validation
// and then use try_from to validate and construct the target.
//
// see: https://github.com/serde-rs/serde/issues/642#issuecomment-683276351

/// In RPC usage TxParams will typically be created by the generate_tx_params()
/// RPC and then used as an argument to the send() RPC.  For the send RPC, it
/// is an untrusted data source.
///
/// Basic validation of input/output amounts occurs when TxParams is constructed
/// including via deserialization (on both client and server).
///
/// This means that validation occurs on the client as well as on the server
/// before create_transaction() is ever called.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "TxParamsShadow")]
pub struct TxParams {
    tx_input_list: TxInputList,
    tx_output_list: TxOutputList,
    timestamp: Timestamp,
}

// note: this only exists to get deserialized without validation.  we also
// derive Serialize for unit tests (only) in order to simulate invalid input
// data.
#[cfg_attr(test, derive(Serialize))]
#[derive(Deserialize)]
struct TxParamsShadow {
    tx_input_list: TxInputList,
    tx_output_list: TxOutputList,
    timestamp: Timestamp,
}

impl std::convert::TryFrom<TxParamsShadow> for TxParams {
    type Error = TxParamsError;

    fn try_from(s: TxParamsShadow) -> Result<Self, Self::Error> {
        Self::new_with_timestamp(s.tx_input_list, s.tx_output_list, s.timestamp)
    }
}

impl TxParams {
    /// construct a new TxParams using the current time
    pub fn new(tx_inputs: TxInputList, tx_outputs: TxOutputList) -> Result<Self, TxParamsError> {
        Self::new_with_timestamp(tx_inputs, tx_outputs, Timestamp::now())
    }

    /// construct a new TxParams with a custom timestamp
    pub fn new_with_timestamp(
        tx_input_list: TxInputList,
        tx_output_list: TxOutputList,
        timestamp: Timestamp,
    ) -> Result<Self, TxParamsError> {
        // validate that all input and output amounts are non-negative. (zero is allowed)
        for amount in tx_input_list
            .iter()
            .map(|i| i.utxo.get_native_currency_amount())
            .chain(
                tx_output_list
                    .iter()
                    .map(|o| o.utxo.get_native_currency_amount()),
            )
        {
            if amount.is_negative() {
                return Err(TxParamsError::NegativeAmount);
            }
        }

        if tx_input_list.total_native_coins() < tx_output_list.total_native_coins() {
            return Err(TxParamsError::InsufficientInputs {
                inputs_sum: tx_input_list.total_native_coins(),
                outputs_sum: tx_output_list.total_native_coins(),
            });
        }

        // todo: consider validating that all inputs are spendable now.
        // todo: any other validations?

        Ok(Self {
            tx_input_list,
            tx_output_list,
            timestamp,
        })
    }

    /// return the fee amount which is sum(inputs) - sum(outputs)
    ///
    /// fee will always be >= 0, guaranteed by [Self::new()]
    pub fn fee(&self) -> NeptuneCoins {
        // note: the unwrap will never fail because fee always >= 0, else a serious bug.
        self.tx_input_list
            .total_native_coins()
            .checked_sub(&self.tx_output_list.total_native_coins())
            .unwrap()
    }

    /// get the transaction inputs
    pub fn tx_input_list(&self) -> &TxInputList {
        &self.tx_input_list
    }

    /// get the transaction outputs
    pub fn tx_output_list(&self) -> &TxOutputList {
        &self.tx_output_list
    }

    /// get the timestamp
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use crate::models::blockchain::transaction::TxInput;
    use crate::models::blockchain::transaction::TxOutput;

    use super::*;

    #[test]
    pub fn validate_insufficient_inputs() -> anyhow::Result<()> {
        let tx_input = TxInput::new_random(NeptuneCoins::new(15));
        let tx_output = TxOutput::new_random(NeptuneCoins::new(20));

        // test TxParams::new()
        assert!(matches!(
            TxParams::new(tx_input.clone().into(), tx_output.clone().into()),
            Err(TxParamsError::InsufficientInputs { .. })
        ));

        // test TxParams::new_with_timestamp()
        assert!(matches!(
            TxParams::new_with_timestamp(
                tx_input.clone().into(),
                tx_output.clone().into(),
                Timestamp::now()
            ),
            Err(TxParamsError::InsufficientInputs { .. })
        ));

        // test TxParams::deserialize()
        {
            let serialized = bincode::serialize(&TxParamsShadow {
                tx_input_list: tx_input.clone().into(),
                tx_output_list: tx_output.clone().into(),
                timestamp: Timestamp::now(),
            })?;

            let result = bincode::deserialize::<TxParams>(&serialized);
            assert!(matches!(
                *result.unwrap_err(),
                bincode::ErrorKind::Custom(s) if s == TxParams::new(tx_input.into(), tx_output.into()).unwrap_err().to_string()
            ));
        }

        Ok(())
    }

    // validates that a NegativeAmount error occurs if inputs has a negative-amount entry.
    // checks TxParams::new(), TxParams::new_with_timestamp() and TxParams::deserialize()
    #[test]
    pub fn validate_negative_input_amount() -> anyhow::Result<()> {
        worker::validate_negative_amount("-5".parse().unwrap(), NeptuneCoins::new(15))
    }

    // validates that a NegativeAmount error occurs if outputs has a negative-amount entry.
    // checks TxParams::new(), TxParams::new_with_timestamp() and TxParams::deserialize()
    #[test]
    pub fn validate_negative_output_amount() -> anyhow::Result<()> {
        worker::validate_negative_amount(NeptuneCoins::new(15), "-5".parse().unwrap())
    }

    mod worker {
        use super::*;

        // validates that a NegativeAmount error occurs if inputs or outputs has a negative-amount entry.
        // requires that caller pass a negative value for at least one arg.
        // checks TxParams::new(), TxParams::new_with_timestamp() and TxParams::deserialize()
        pub fn validate_negative_amount(
            input_amt: NeptuneCoins,
            output_amt: NeptuneCoins,
        ) -> anyhow::Result<()> {
            let tx_input = TxInput::new_random(input_amt);
            let tx_output = TxOutput::new_random(output_amt);

            // test TxParams::new()
            assert!(matches!(
                TxParams::new(tx_input.clone().into(), tx_output.clone().into()),
                Err(TxParamsError::NegativeAmount { .. })
            ));

            // test TxParams::new_with_timestamp()
            assert!(matches!(
                TxParams::new_with_timestamp(
                    tx_input.clone().into(),
                    tx_output.clone().into(),
                    Timestamp::now()
                ),
                Err(TxParamsError::NegativeAmount)
            ));

            // test TxParams::deserialize()
            {
                let serialized = bincode::serialize(&TxParamsShadow {
                    tx_input_list: tx_input.clone().into(),
                    tx_output_list: tx_output.clone().into(),
                    timestamp: Timestamp::now(),
                })?;

                let result = bincode::deserialize::<TxParams>(&serialized);
                assert!(matches!(
                    *result.unwrap_err(),
                    bincode::ErrorKind::Custom(s) if s == TxParams::new(tx_input.into(), tx_output.into()).unwrap_err().to_string()
                ));
            }

            Ok(())
        }
    }
}
