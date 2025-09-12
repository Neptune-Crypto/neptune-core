use serde::Deserialize;
use serde::Serialize;

/// represents a UtxoTransfer entry in a utxo-transfer file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UtxoTransferEntry {
    pub data_format: String,
    pub recipient_abbrev: String,
    pub recipient: String,
    pub ciphertext: String,
}

impl UtxoTransferEntry {
    pub(crate) fn data_format() -> String {
        "neptune-utxo-transfer-v1.0".to_string()
    }
}
