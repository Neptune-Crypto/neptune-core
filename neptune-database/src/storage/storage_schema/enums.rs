use super::super::storage_vec::Index;
use super::RustyKey;
use super::RustyValue;

/// Database write operations
#[derive(Debug, Clone)]
pub enum WriteOperation {
    /// write operation
    Write(RustyKey, RustyValue),
    /// delete operation
    Delete(RustyKey),
}

/// Vector write operations
#[derive(Debug, Clone)]
pub enum VecWriteOperation<T> {
    /// overwrite, aka set operation
    OverWrite((Index, T)),
    /// push to end operation
    Push(T),
    /// pop from end operation
    Pop,
}
