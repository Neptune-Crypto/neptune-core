use super::traits::*;
use super::{DbtSingleton, DbtVec, WriteOperation};

pub enum DbTableType<T> {
    Singleton(DbtSingleton<T>),
    Vec(DbtVec<T>),
}

impl DbTable for DbTableType {
    /// Retrieve all unwritten operations and empty write-queue
    async fn pull_queue(&mut self) -> Vec<WriteOperation> {
        match self {
            Self::Singleton(s) => s.pull_queue(),
            Self::Vec(v) => v.pull_queue(),
        }
    }

    /// Restore existing table if present, else create a new one
    async fn restore_or_new(&mut self) {
        match self {
            Self::Singleton(s) => s.restore_or_new(),
            Self::Vec(v) => v.restore_or_new(),
        }
    }
}