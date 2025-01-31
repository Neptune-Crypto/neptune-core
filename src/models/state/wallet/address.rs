mod address_type;
mod common;

pub mod encrypted_utxo_notification;
pub mod generation_address;
pub(crate) mod hash_lock_key;
pub mod symmetric_key;

/// KeyType simply enumerates the known key types.
pub use address_type::KeyType;
/// ReceivingAddress abstracts over any address type and should be used
/// wherever possible.
pub use address_type::ReceivingAddress;
/// SpendingKey abstracts over any spending key type and should be used
/// wherever possible.
pub use address_type::SpendingKey;
