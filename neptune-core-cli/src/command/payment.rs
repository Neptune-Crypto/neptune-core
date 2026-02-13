use std::path::PathBuf;

use clap::Parser;
use neptune_cash::api::export::NativeCurrencyAmount;
use neptune_cash::state::wallet::utxo_notification::UtxoNotificationMedium;

use crate::parser::beneficiary::Beneficiary;

/// Meta Command -- a command related to initiating payments.
#[derive(Debug, Clone, Parser)]
pub(crate) enum PaymentCommand {
    /// send a payment to a single recipient
    Send {
        /// recipient's address
        address: String,

        /// amount to send
        #[clap(value_parser = NativeCurrencyAmount::coins_from_str)]
        amount: NativeCurrencyAmount,

        /// transaction fee
        #[clap(value_parser = NativeCurrencyAmount::coins_from_str)]
        fee: NativeCurrencyAmount,

        /// local tag for identifying a receiver
        receiver_tag: String,
        notify_self: UtxoNotificationMedium,
        notify_other: UtxoNotificationMedium,
    },

    /// send a payment to one or more recipients
    SendToMany {
        #[clap(long, value_parser, required = false)]
        file: Option<PathBuf>,
        /// format: address:amount address:amount ...
        #[clap(value_parser, num_args = 0.., value_delimiter = ' ')]
        outputs: Vec<Beneficiary>,
        #[clap(long, value_parser = NativeCurrencyAmount::coins_from_str)]
        fee: NativeCurrencyAmount,
    },

    /// Like `SendToMany` but the resulting transaction will be *transparent*.
    /// No privacy.
    ///
    /// Specifically, the transaction will include announcements that expose the
    /// raw UTXOs and all commitment randomness. This information suffices to
    /// track amounts as well as origins and destinations. Because of the added
    /// announcements, these transactions require a higher fee than
    /// non-transparent transactions.
    SendTransparent {
        #[clap(long, value_parser, required = false)]
        file: Option<PathBuf>,
        /// format: address:amount address:amount ...
        #[clap(value_parser, num_args = 0.., value_delimiter = ' ')]
        outputs: Vec<Beneficiary>,
        #[clap(long, value_parser = NativeCurrencyAmount::coins_from_str)]
        fee: NativeCurrencyAmount,
    },

    /// Initiate and broadcast a transaction for consolidating UTXOs.
    ///
    /// Specifically, spend `batch`-many UTXOs to the node's own wallet,
    /// resulting in 3 fewer UTXOs to manage in total. This operation has no
    /// effect if the number of liquid UTXOs under management is less than
    /// `batch`, of if the node is configured to not initiate transactions.
    /// If omitted, `batch = 4`.
    Consolidate {
        #[clap(long, required = false, default_value_t = 4)]
        batch: usize,

        #[clap(long, required = false)]
        address: Option<String>,
    },
}
