use std::fmt::Display;
use std::str::FromStr;

use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::api::export::Network;
use neptune_cash::api::export::OutputFormat;
use neptune_cash::api::export::ReceivingAddress;
use neptune_cash::api::export::Timestamp;
use neptune_cash::prelude::triton_vm::prelude::BFieldElement;
use neptune_cash::prelude::twenty_first::error::ParseBFieldElementError;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Beneficiary {
    // Addresses are represented as strings here because we cannot parse them
    // without knowing the network.
    address: String,
    amount: NativeCurrencyAmount,
    release_date: Option<Timestamp>,
}

impl Beneficiary {
    pub(crate) fn to_output_format(&self, network: Network) -> Result<OutputFormat, anyhow::Error> {
        let address = ReceivingAddress::from_bech32m(&self.address, network)?;
        if let Some(release_date) = self.release_date {
            Ok(OutputFormat::AddressAndAmountAndReleaseDate(
                address,
                self.amount,
                release_date,
            ))
        } else {
            Ok(OutputFormat::AddressAndAmount(address, self.amount))
        }
    }
}

impl Display for Beneficiary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let appendix = if let Some(date) = self.release_date {
            format!(":{}", date.0.value())
        } else {
            "".to_string()
        };
        write!(
            f,
            "{}:{}{appendix}",
            self.address,
            self.amount.display_lossless()
        )
    }
}

#[derive(Debug)]
pub enum ParseBeneficiaryError {
    Format,
    Address(bech32::Error),
    Amount(anyhow::Error),
    Timestamp(ParseBFieldElementError),
}

impl Display for ParseBeneficiaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseBeneficiaryError::Format => write!(f, "invalid beneficiary format"),
            ParseBeneficiaryError::Address(e) => write!(f, "invalid address: {e}"),
            ParseBeneficiaryError::Amount(e) => write!(f, "invalid amount: {e}"),
            ParseBeneficiaryError::Timestamp(e) => write!(f, "invalid timestamp: {e}"),
        }
    }
}

impl std::error::Error for ParseBeneficiaryError {}

impl FromStr for Beneficiary {
    type Err = ParseBeneficiaryError;

    /// Parse a string as a Beneficiary.
    ///
    /// Parses
    ///
    ///  - "address:amount" into
    ///    `Beneficiary {address, amount, release_date: None }`, and
    ///  - "address:amount:date" into
    ///    `Beneficiary {address, amount, release_date: Some(date) }`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();

        match parts.as_slice() {
            // address:amount
            [addr_str, amount_str] => {
                let (_, _, _) = bech32::decode(addr_str).map_err(ParseBeneficiaryError::Address)?;
                let amount = NativeCurrencyAmount::coins_from_str(amount_str)
                    .map_err(ParseBeneficiaryError::Amount)?;
                Ok(Beneficiary {
                    address: (*addr_str).to_string(),
                    amount,
                    release_date: None,
                })
            }
            // address:amount:release_date
            [addr_str, amount_str, ts_str] => {
                let (_, _, _) = bech32::decode(addr_str).map_err(ParseBeneficiaryError::Address)?;
                let amount = NativeCurrencyAmount::coins_from_str(amount_str)
                    .map_err(ParseBeneficiaryError::Amount)?;
                let release_date = BFieldElement::from_str(ts_str)
                    .map_err(ParseBeneficiaryError::Timestamp)
                    .map(Timestamp)?;
                Ok(Beneficiary {
                    address: (*addr_str).to_string(),
                    amount,
                    release_date: Some(release_date),
                })
            }
            _ => Err(ParseBeneficiaryError::Format),
        }
    }
}

#[cfg(test)]
mod tests {
    use neptune_cash::api::export::Digest;
    use neptune_cash::api::export::GenerationSpendingKey;
    use neptune_cash::api::export::KeyType;
    use neptune_cash::api::export::Network;
    use neptune_cash::api::export::SpendingKey;
    use neptune_cash::api::export::SymmetricKey;
    use neptune_cash::prelude::triton_vm::prelude::BFieldElement;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    impl<'a> arbitrary::Arbitrary<'a> for Beneficiary {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let address_type = usize::arbitrary(u)? % KeyType::all_types().len();
            let spending_key: SpendingKey = if address_type == 0 {
                SymmetricKey::from_seed(Digest::arbitrary(u)?).into()
            } else if address_type == 1 {
                GenerationSpendingKey::derive_from_seed(Digest::arbitrary(u)?).into()
            } else {
                unreachable!()
            };
            let address = spending_key.to_address().to_bech32m(Network::Main).unwrap();

            let amount = NativeCurrencyAmount::from_nau((u128::arbitrary(u)? >> 3) as i128);
            let release_date = if bool::arbitrary(u)? {
                None
            } else {
                let bfe = BFieldElement::arbitrary(u)?;
                let timestamp = Timestamp(bfe);
                Some(timestamp)
            };

            Ok(Beneficiary {
                address,
                amount,
                release_date,
            })
        }
    }

    #[proptest]
    fn arbitrary_display_parse_round_trip(
        #[strategy(arb::<Beneficiary>())] beneficiary: Beneficiary,
    ) {
        let displayed = beneficiary.to_string();
        let parsed = Beneficiary::from_str(&displayed).unwrap();
        prop_assert_eq!(beneficiary, parsed.clone());

        let as_string_again = parsed.to_string();
        prop_assert_eq!(displayed, as_string_again);
    }

    #[proptest]
    fn arbitrary_string_cannot_crash_parser(s: String) {
        let _ = Beneficiary::from_str(&s); // no crash
    }
}
