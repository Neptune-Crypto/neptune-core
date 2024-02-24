use super::enums::WriteOperation;

/// Represents pending database write operations
#[derive(Debug, Clone, Default)]
pub struct PendingWrites {
    /// list of write ops, newest at end.  cleared once persisted to DB.
    pub(crate) write_ops: Vec<WriteOperation>,

    /// increments each time write ops are persisted to DB.
    pub(crate) persist_count: usize,
}
