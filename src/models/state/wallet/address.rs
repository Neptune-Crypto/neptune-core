mod address_enum;
pub mod generation_address;

/// AbstractAddress abstracts over address type and should be used wherever
/// possible.
pub use address_enum::AbstractAddress;

/// AbstractSpendingKey abstracts over spending key type and should be used
/// wherever possible.
pub use address_enum::AbstractSpendingKey;
