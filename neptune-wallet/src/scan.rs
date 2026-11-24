//! Finding a wallet's UTXOs in blocks and transactions.
//!
//! Every function here takes keys, or [`ComposerParameters`], and no
//! [`WalletEntropy`](crate::wallet_entropy::WalletEntropy) and no storage, so
//! that any wallet that derives the keys can call it, whatever its secret and
//! wherever it keeps its UTXOs.

use itertools::Itertools;
use neptune_consensus::block::Block;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_mutator_set::addition_record::AdditionRecord;
use tracing::info;
use tracing::warn;

use crate::address::KeyType;
use crate::address::SpendingKey;
use crate::composer_parameters::ComposerParameters;
use crate::incoming_utxo::IncomingUtxo;

/// Whether the announced UTXO is among the transaction's outputs, warning if it
/// is not.
fn is_output(incoming_utxo: &IncomingUtxo, outputs: &[AdditionRecord]) -> bool {
    let is_output = outputs.contains(&incoming_utxo.addition_record());
    if !is_output {
        warn!(
            "Transaction does not contain announced UTXO encrypted to own receiving address. \
            Announced UTXO was: {:#?}",
            incoming_utxo.utxo
        );
    }
    is_output
}

/// The UTXOs announced to any of `keys` whose addition records are among
/// `outputs`.
///
/// An announcement does not create a UTXO, so an announced UTXO whose addition
/// record is not among the transaction's outputs is dropped, with a warning.
/// Each announcement is matched against the keys in a single lookup, so the
/// cost is `O(keys + announcements)`.
pub fn utxos_announced_to_keys(
    announcements: &[Announcement],
    outputs: &[AdditionRecord],
    keys: impl IntoIterator<Item = SpendingKey>,
) -> Vec<IncomingUtxo> {
    SpendingKey::scan_announcements_for_keys(announcements, keys)
        .into_iter()
        .filter(|incoming_utxo| is_output(incoming_utxo, outputs))
        .collect()
}

/// The UTXOs announced to any of `keys` whose addition records are among
/// `outputs`, each with the key type and derivation index of the key it was
/// announced to.
///
/// A wallet that scans keys beyond its derivation counter learns from the
/// indices how far to advance the counter.
pub fn utxos_announced_to_indexed_keys(
    announcements: &[Announcement],
    outputs: &[AdditionRecord],
    keys: impl IntoIterator<Item = (KeyType, u64, SpendingKey)>,
) -> Vec<(KeyType, u64, IncomingUtxo)> {
    keys.into_iter()
        .flat_map(|(key_type, derivation_index, key)| {
            utxos_announced_to_keys(announcements, outputs, [key])
                .into_iter()
                .map(move |incoming_utxo| (key_type, derivation_index, incoming_utxo))
        })
        .collect()
}

/// The guesser-fee UTXOs of `block` if one of `keys` guessed it, and none
/// otherwise.
///
/// A block's guesser fee is locked to the address the guesser chose. That is
/// the dedicated guesser-fee key by default, but it is any key of the wallet
/// when a custom mining address is configured, so every given key is checked.
pub fn guesser_fee_utxos(
    block: &Block,
    keys: impl IntoIterator<Item = SpendingKey>,
) -> Vec<IncomingUtxo> {
    let Some(guessing_key) = keys
        .into_iter()
        .find(|key| block.header().was_guessed_by(&key.guesser_receiver_data()))
    else {
        return vec![];
    };

    let sender_randomness = block.hash();
    let receiver_preimage = guessing_key.privacy_preimage();
    block
        .kernel
        .guesser_fee_utxos()
        .expect("Block argument must have guesser fee UTXOs")
        .into_iter()
        .map(|utxo| IncomingUtxo {
            utxo,
            sender_randomness,
            receiver_preimage,
            is_guesser_fee: true,
        })
        .collect_vec()
}

/// The composer-reward UTXOs of `block`, if it was composed with
/// `composer_parameters`, and none otherwise.
///
/// Composer rewards carry no announcement. They are found by computing the
/// composer's outputs again from `composer_parameters`, and keeping those
/// whose addition records are among the block's outputs. Parameters without a
/// receiver preimage find nothing, since the wallet could not spend what they
/// produce.
pub fn composer_reward_utxos(
    block: &Block,
    composer_parameters: &ComposerParameters,
) -> Vec<IncomingUtxo> {
    let Some(receiver_preimage) = composer_parameters.maybe_receiver_preimage() else {
        return vec![];
    };

    let coinbase_amount = Block::block_subsidy(block.header().height);
    let outputs = &block.body().transaction_kernel.outputs;
    composer_parameters
        .tx_outputs(coinbase_amount, block.header().timestamp)
        .iter()
        .map(|composer_output| IncomingUtxo {
            utxo: composer_output.utxo(),
            sender_randomness: composer_output.sender_randomness(),
            receiver_preimage,
            is_guesser_fee: false,
        })
        .filter(|incoming_utxo| outputs.contains(&incoming_utxo.addition_record()))
        .inspect(|incoming_utxo| {
            info!(
                "Found composer fee UTXO worth {}; timelocked? {}",
                incoming_utxo
                    .utxo
                    .get_native_currency_amount()
                    .display_n_decimals(8),
                incoming_utxo.utxo.release_date().is_some()
            );
        })
        .collect()
}
