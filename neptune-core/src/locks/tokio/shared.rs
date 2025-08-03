/// Indicates the lock's underlying type
#[derive(Debug, Clone, Copy)]
pub enum LockType {
    Mutex,
    RwLock,
}

impl std::fmt::Display for LockType {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mutex => write!(f, "Mutex"),
            Self::RwLock => write!(f, "RwLock"),
        }
    }
}

/// Indicates how a lock was acquired.
#[derive(Debug, Clone, Copy)]
pub enum LockAcquisition {
    Read,
    Write,
    TryAcquire,
}

impl std::fmt::Display for LockAcquisition {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "Read"),
            Self::Write => write!(f, "Write"),
            Self::TryAcquire => write!(f, "TryAcquire"),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct LockInfoOwned {
    pub name: Option<String>,
    pub lock_type: LockType,
}
impl LockInfoOwned {
    #[inline]
    pub fn as_lock_info(&self) -> LockInfo<'_> {
        LockInfo {
            name: self.name.as_deref(),
            lock_type: self.lock_type,
        }
    }
}

/// Contains metadata about a lock
#[derive(Debug, Clone)]
pub struct LockInfo<'a> {
    name: Option<&'a str>,
    lock_type: LockType,
}
impl LockInfo<'_> {
    /// get the lock's name
    #[inline]
    pub fn name(&self) -> Option<&str> {
        self.name
    }

    /// get the lock's type
    #[inline]
    pub fn lock_type(&self) -> LockType {
        self.lock_type
    }
}

#[derive(Debug, Clone)]
pub(super) struct LockCallbackInfo {
    pub lock_info_owned: LockInfoOwned,
    pub lock_callback_fn: Option<LockCallbackFn>,
}
impl LockCallbackInfo {
    #[inline]
    pub fn new(
        lock_type: LockType,
        name: Option<String>,
        lock_callback_fn: Option<LockCallbackFn>,
    ) -> Self {
        Self {
            lock_info_owned: LockInfoOwned { name, lock_type },
            lock_callback_fn,
        }
    }
}

/// Represents an event (acquire/release) for a lock
#[derive(Debug, Clone)]
pub enum LockEvent<'a> {
    TryAcquire {
        info: LockInfo<'a>,
        acquisition: LockAcquisition,
        location: Option<&'static core::panic::Location<'static>>,
    },
    Acquire {
        info: LockInfo<'a>,
        acquisition: LockAcquisition,
        try_acquire_at: Option<std::time::Instant>,
        acquire_at: Option<std::time::Instant>,
        location: Option<&'static core::panic::Location<'static>>,
    },
    Release {
        info: LockInfo<'a>,
        acquisition: LockAcquisition,
        try_acquire_at: Option<std::time::Instant>,
        acquire_at: Option<std::time::Instant>,
        location: Option<&'static core::panic::Location<'static>>,
    },
}

impl LockEvent<'_> {
    pub fn event_type_name(&self) -> &str {
        match self {
            Self::TryAcquire { .. } => "TryAcquire",
            Self::Acquire { .. } => "Acquire",
            Self::Release { .. } => "Release",
        }
    }
    pub fn info(&self) -> &LockInfo<'_> {
        match self {
            Self::TryAcquire { info, .. } => info,
            Self::Acquire { info, .. } => info,
            Self::Release { info, .. } => info,
        }
    }
    pub fn location(&self) -> Option<&'static core::panic::Location<'static>> {
        match self {
            Self::TryAcquire { location, .. } => *location,
            Self::Acquire { location, .. } => *location,
            Self::Release { location, .. } => *location,
        }
    }
    pub fn try_acquire_at(&self) -> Option<std::time::Instant> {
        match self {
            Self::TryAcquire { .. } => None,
            Self::Acquire { try_acquire_at, .. } => *try_acquire_at,
            Self::Release { try_acquire_at, .. } => *try_acquire_at,
        }
    }
    pub fn acquire_at(&self) -> Option<std::time::Instant> {
        match self {
            Self::TryAcquire { .. } => None,
            Self::Acquire { acquire_at, .. } => *acquire_at,
            Self::Release { acquire_at, .. } => *acquire_at,
        }
    }
    pub fn acquisition(&self) -> LockAcquisition {
        match self {
            Self::TryAcquire { acquisition, .. } => *acquisition,
            Self::Acquire { acquisition, .. } => *acquisition,
            Self::Release { acquisition, .. } => *acquisition,
        }
    }
}

/// A callback fn for receiving [LockEvent] event
/// each time a lock is acquired or released.
pub type LockCallbackFn = fn(lock_event: LockEvent);

#[expect(clippy::unnecessary_wraps)]
#[cfg(feature = "track-lock-time")]
pub fn now() -> Option<std::time::Instant> {
    Some(std::time::Instant::now())
}

#[cfg(not(feature = "track-lock-time"))]
pub fn now() -> Option<std::time::Instant> {
    None
}
