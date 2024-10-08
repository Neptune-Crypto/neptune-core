//! Provides simplified lock types for sharing data between threads

mod atomic_mutex;
mod atomic_rw;
mod shared;
pub mod traits;

pub use atomic_mutex::AtomicMutex;
pub use atomic_rw::AtomicRw;
pub use atomic_rw::AtomicRwReadGuard;
pub use atomic_rw::AtomicRwWriteGuard;
pub use shared::LockAcquisition;
pub use shared::LockCallbackFn;
use shared::LockCallbackInfo;
pub use shared::LockEvent;
pub use shared::LockInfo;
pub use shared::LockType;
