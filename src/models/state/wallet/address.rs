mod address_type;
pub mod generation_address;

/// ReceivingAddressType abstracts over any address type and should be used
/// wherever possible.
pub use address_type::ReceivingAddressType;

/// SpendingKeyType abstracts over any spending key type and should be used
/// wherever possible.
pub use address_type::SpendingKeyType;
