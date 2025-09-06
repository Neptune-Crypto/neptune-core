//! This performs simple tests of acquiring locks
//! for AtomicRw (Arc<RwLock<T>>) and AtomicMutex (Arc<Mutex<T>>).
//!
//! Basically it is comparing RwLock vs Mutex, through our wrappers.
//! People say that Mutex is "faster", but is that true and
//! by how much?  That's what we attempt to measure.
//!
//! Initial results indicate that Mutex is a little faster
//! but not that much.
//!
//! Note that:
//!  1. `lock` and `lock_guard` denote read-lock acquisitions
//!  2. `lock_mut` and `lock_guard_mut` denote write-lock acquisitions
//!  3. For mutex, only write-lock acquisitions are possible.
//!
//! sync_atomic              fastest       │ slowest       │ median        │ mean          │ samples │ iters
//! ├─ lock                                │               │               │               │         │
//! │  ╰─ rw                               │               │               │               │         │
//! │     ╰─ lock_guard      169.1 µs      │ 210.6 µs      │ 169.1 µs      │ 175.3 µs      │ 100     │ 100
//! ╰─ lock_mut                            │               │               │               │         │
//!    ├─ mutex                            │               │               │               │         │
//!    │  ╰─ lock_guard_mut  131.8 µs      │ 217.9 µs      │ 131.8 µs      │ 136.5 µs      │ 100     │ 100
//!    ╰─ rw                               │               │               │               │         │
//!       ╰─ lock_guard_mut  131.8 µs      │ 153.8 µs      │ 131.8 µs      │ 132.7 µs      │ 100     │ 100
//!
//! Analysis:
//!  1. RwLock and Mutex write-lock acquisitions are basically the same.
//!  2. RwLock read-lock acquisitions are about 22% slower than write-lock acquisitions
//!     which seems acceptable for most uses.

use divan::Bencher;
use neptune_cash::application::locks::std::AtomicMutex;
use neptune_cash::application::locks::std::AtomicRw;

fn main() {
    divan::main();
}

mod lock {
    use super::*;

    // note: numbers > 100 make the sync_on_write::put() test really slow.
    const NUM_ACQUIRES: u32 = 10000;

    mod rw {
        use super::*;

        #[divan::bench]
        fn lock_guard(bencher: Bencher) {
            let atom = AtomicRw::from(true);

            bencher.bench_local(|| {
                for _i in 0..NUM_ACQUIRES {
                    let _g = atom.lock_guard();
                }
            });
        }
    }

    // There is no mutex mod because mutex does not have
    // read-only locks.
}

mod lock_mut {
    use super::*;

    // note: numbers > 100 make the sync_on_write::put() test really slow.
    const NUM_ACQUIRES: u32 = 10000;

    mod rw {
        use super::*;

        #[divan::bench]
        fn lock_guard_mut(bencher: Bencher) {
            let mut atom = AtomicRw::from(true);

            bencher.bench_local(|| {
                for _i in 0..NUM_ACQUIRES {
                    let _g = atom.lock_guard_mut();
                }
            });
        }
    }

    mod mutex {
        use super::*;

        #[divan::bench]
        fn lock_guard_mut(bencher: Bencher) {
            let atom = AtomicMutex::from(true);

            bencher.bench_local(|| {
                for _i in 0..NUM_ACQUIRES {
                    let _g = atom.lock_guard();
                }
            });
        }
    }
}
