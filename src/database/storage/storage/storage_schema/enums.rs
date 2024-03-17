use super::super::storage_vec::Index;
use super::{RustyKey, RustyValue};

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
pub enum VecWriteOperation<V> {
    /// overwrite, aka set operation
    OverWrite((Index, V)),
    /// push to end operation
    Push(V),
    /// pop from end operation
    Pop,
}
