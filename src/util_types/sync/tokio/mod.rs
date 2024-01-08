//! Provides simplified tokio lock types for sharing data between threads

// note: twenty-first::sync has equivalent wrappers for std::sync types.
//       It would make sense to put these tokio wrappers there also except
//       that twenty-first presently has no tokio dependency and I didn't
//       really want to introduce one just for this.  So that's why they are
//       here instead.  We may wish to revisit in the future.

mod atomic_mutex;
mod atomic_rw;
mod shared;
pub mod traits;

pub use atomic_mutex::AtomicMutex;
pub use atomic_rw::AtomicRw;
pub use shared::{LockAcquisition, LockCallbackFn, LockEvent, LockInfo, LockType};

use shared::LockCallbackInfo;
