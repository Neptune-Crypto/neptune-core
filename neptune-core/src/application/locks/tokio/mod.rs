//! Provides simplified tokio lock types for sharing data between threads

// note: twenty-first::sync has equivalent wrappers for std::sync types.
//       It would make sense to put these tokio wrappers there also except
//       that twenty-first presently has no tokio dependency and I didn't
//       really want to introduce one just for this.  So that's why they are
//       here instead.  We may wish to revisit in the future, and maybe
//       put all the sync types in their own crate.

mod atomic_mutex;
mod atomic_rw;
mod shared;

pub use atomic_mutex::AtomicMutex;
pub use atomic_mutex::AtomicMutexGuard;
pub use atomic_rw::AtomicRw;
pub use atomic_rw::AtomicRwReadGuard;
pub use atomic_rw::AtomicRwWriteGuard;
use shared::now;
pub use shared::LockAcquisition;
pub use shared::LockCallbackFn;
use shared::LockCallbackInfo;
pub use shared::LockEvent;
pub use shared::LockInfo;
pub use shared::LockType;
