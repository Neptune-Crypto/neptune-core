mod address_type;
mod common;
mod key_iter;
mod spending_key_range;

pub mod encrypted_utxo_notification;
pub mod generation_address;
pub mod symmetric_key;

/// KeyType simply enumerates the known key types.
pub use address_type::KeyType;
/// ReceivingAddress abstracts over any address type and should be used
/// wherever possible.
pub use address_type::ReceivingAddress;
/// SpendingKey abstracts over any spending key type and should be used
/// wherever possible.
pub use address_type::SpendingKey;
/// Index for deriving child-keys, of any key-type.
pub use common::DerivationIndex;
pub use key_iter::*;
/// spending keys that have been used (derived) by the wallet to date.
pub use spending_key_range::SpendingKeyRange;
