mod address_type;
pub(super) mod common;

pub mod generation_address;
pub mod symmetric_key;

/// ReceivingAddress abstracts over any address type and should be used
/// wherever possible.
pub use address_type::ReceivingAddress;

/// SpendingKey abstracts over any spending key type and should be used
/// wherever possible.
pub use address_type::SpendingKey;

/// KeyType simply enumerates the known key types.
pub use address_type::KeyType;
