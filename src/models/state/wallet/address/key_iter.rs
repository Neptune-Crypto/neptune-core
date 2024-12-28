use std::ops::Bound;
use std::ops::RangeBounds;
use std::ops::RangeInclusive;

use serde::Deserialize;
use serde::Serialize;

use super::DerivationIndex;
use super::SpendingKey;

/// an iterator over a range of spending keys
///
/// Given a parent-key, performs iteration over any range of child keys
/// where:
///  1. The maximum range size is usize::MAX
///  2. The lowest reachable index is 0
///  3. the highest reachable index is DerivationIndex::MAX
///
/// Typically this iterator would be used for iterating over range
/// 0..max, where max is defined by the application, keeping in mind
/// that each iteration requires deriving a new child key, which is
/// a relatively expensive operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingKeyIter {
    parent_key: SpendingKey,
    range: RangeInclusive<DerivationIndex>,
    curr: Option<DerivationIndex>,
    curr_back: Option<DerivationIndex>,
}

impl From<SpendingKey> for SpendingKeyIter {
    fn from(parent_key: SpendingKey) -> Self {
        // max range size is usize::MAX because Iterator methods such as
        // size_hint() and len() use usize.
        Self::new_range(parent_key, 0..usize::MAX as DerivationIndex)
    }
}

impl SpendingKeyIter {
    /// creates a new iterator over a range of child-keys of parent-key
    ///
    /// the range length may be at most `usize::MAX`, however it can start at
    /// any value of `DerivationIndex`.
    ///
    /// This limit is due to rust's iterator API. Many of its methods accept or
    /// return `usize`.
    ///
    /// An unbounded range eg `[n..]` is treated as `[n..start + usize::MAX]`
    /// and is capped to `DerivationIndex::MAX`.
    ///
    /// panics if any of these conditions are not true:
    /// ```text
    ///   range.end >= range.start
    ///   range.end - range.start <= usize::MAX
    /// ```
    pub fn new_range(parent_key: SpendingKey, range: impl RangeBounds<DerivationIndex>) -> Self {
        let range = Self::range_bounds_to_inclusive(range);

        assert!(range.end() >= range.start());
        assert!(range.end() - range.start() <= usize::MAX as DerivationIndex);

        let curr_back = if *range.end() == 0 {
            0
        } else {
            *range.end() - 1
        };

        Self {
            parent_key,
            curr: Some(*range.start()),
            curr_back: Some(curr_back),
            range,
        }
    }

    // converts any type that implements `RangeBounds<DerivationIndex>` to `RangeInclusive<DerivationIndex>`
    //
    // note special handling when the range end is unbounded eg [start..]
    // The end of range will be start + usize::MAX, up to DerivationIndex::MAX.
    fn range_bounds_to_inclusive(
        range: impl RangeBounds<DerivationIndex>,
    ) -> RangeInclusive<DerivationIndex> {
        let start = match range.start_bound() {
            Bound::Unbounded => 0 as DerivationIndex,
            Bound::Included(n) => *n,
            Bound::Excluded(n) if *n == DerivationIndex::MAX => *n,
            Bound::Excluded(n) => *n + 1,
        };
        let end = match range.end_bound() {
            Bound::Unbounded => match start.checked_add(usize::MAX as DerivationIndex) {
                Some(v) => v,
                None => DerivationIndex::MAX,
            },
            Bound::Included(n) => *n,
            Bound::Excluded(n) if *n == 0 => 0,
            Bound::Excluded(n) => *n - 1,
        };

        start..=end
    }
}
impl Iterator for SpendingKeyIter {
    type Item = SpendingKey;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.curr, self.curr_back) {
            (Some(c), Some(cb)) => {
                let key = self.parent_key.derive_child(c);
                self.curr = if c >= cb { None } else { Some(c + 1) };
                Some(key)
            }
            _ => None,
        }
    }

    // returns a tuple where the first element is the lower bound, and the
    // second element is the upper bound
    //
    // note: the cast to usize should always succeed because we already
    // assert that range len is <= usize::MAX when iterator is created.
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = (self.range.end() - self.range.start()) as usize;
        (len, Some(len))
    }
}

// rayon needs DoubleEndedIterator, bleah.
// see: https://github.com/rayon-rs/rayon/issues/1053
impl DoubleEndedIterator for SpendingKeyIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        match (self.curr, self.curr_back) {
            (Some(c), Some(cb)) => {
                let key = self.parent_key.derive_child(cb);
                self.curr_back = if cb <= c { None } else { Some(cb - 1) };
                Some(key)
            }
            _ => None,
        }
    }
}

// note: Iterator::size_hint() must return exact size
impl ExactSizeIterator for SpendingKeyIter {}

pub mod par_iter {
    use rayon::iter::plumbing::bridge;
    use rayon::iter::plumbing::Consumer;
    use rayon::iter::plumbing::Producer;
    use rayon::iter::plumbing::ProducerCallback;
    use rayon::iter::plumbing::UnindexedConsumer;
    use rayon::prelude::IndexedParallelIterator;
    use rayon::prelude::ParallelIterator;

    use super::*;

    pub struct SpendingKeyParallelIter(SpendingKeyIter);

    impl From<SpendingKeyIter> for SpendingKeyParallelIter {
        fn from(iter: SpendingKeyIter) -> Self {
            Self(iter)
        }
    }

    impl ParallelIterator for SpendingKeyParallelIter {
        type Item = SpendingKey;

        fn drive_unindexed<C>(self, consumer: C) -> C::Result
        where
            C: UnindexedConsumer<Self::Item>,
        {
            bridge(self, consumer)
        }

        fn opt_len(&self) -> Option<usize> {
            Some(ExactSizeIterator::len(&self.0))
        }
    }

    impl IndexedParallelIterator for SpendingKeyParallelIter {
        fn with_producer<CB: ProducerCallback<Self::Item>>(self, callback: CB) -> CB::Output {
            callback.callback(SpendingKeyRangeProducer::from(self))
        }

        fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
            bridge(self, consumer)
        }

        fn len(&self) -> usize {
            ExactSizeIterator::len(&self.0)
        }
    }

    struct SpendingKeyRangeProducer(SpendingKeyParallelIter);

    impl Producer for SpendingKeyRangeProducer {
        type Item = SpendingKey;
        type IntoIter = SpendingKeyIter;

        fn into_iter(self) -> Self::IntoIter {
            self.0 .0
        }

        fn split_at(self, index: usize) -> (Self, Self) {
            let range_iter = self.0 .0;

            let mid = *range_iter.range.start() + index as DerivationIndex;

            assert!(mid <= *range_iter.range.end());

            let left = SpendingKeyIter::new_range(
                range_iter.parent_key,
                *range_iter.range.start()..=(mid - 1) as DerivationIndex,
            );
            let right =
                SpendingKeyIter::new_range(range_iter.parent_key, mid..=*range_iter.range.end());
            (
                Self(SpendingKeyParallelIter(left)),
                Self(SpendingKeyParallelIter(right)),
            )
        }
    }

    impl From<SpendingKeyParallelIter> for SpendingKeyRangeProducer {
        fn from(range_iter: SpendingKeyParallelIter) -> Self {
            Self(range_iter)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod iter_tests {
        use super::*;

        // tests that ::derive_nth() matches ::next()
        #[test]
        pub fn derive_nth_matches_iter() {
            worker::derive_nth_matches_iter();
        }

        // tests basic iteration, comparing with SpendingKey::derive_child()
        #[test]
        pub fn iterator() {
            let parent_key = helper::make_parent_key();
            worker::iterator(parent_key, parent_key.into_iter());
        }

        // tests basic iteration over a range, comparing with SpendingKey::derive_child()
        #[test]
        pub fn range_iterator() {
            let parent_key = helper::make_parent_key();
            worker::iterator(parent_key, parent_key.into_range_iter(0..50));
        }

        // tests Iterator::nth() method, comparing with SpendingKey::derive_child()
        #[test]
        pub fn iterator_nth() {
            let parent_key = helper::make_parent_key();
            worker::iterator_nth(parent_key, parent_key.into_iter());
        }

        // tests Iterator::nth() method for a range, comparing with SpendingKey::derive_child()
        #[test]
        pub fn range_iterator_nth() {
            let parent_key = helper::make_parent_key();
            worker::iterator_nth(parent_key, parent_key.into_range_iter(0..50));
        }

        // tests that a range iterator reaches last elem and after returns None
        #[test]
        pub fn range_iterator_to_last_elem() {
            let parent_key = helper::make_parent_key();

            let range = 0..=50;
            worker::iterator_to_last_elem(
                parent_key,
                parent_key.into_range_iter(range.clone()),
                range,
            );
        }

        // tests that iterator can reach DerivationIndex::MAX and after returns None
        #[test]
        pub fn iterator_to_max_elem() {
            let parent_key = helper::make_parent_key();

            let range = DerivationIndex::MAX - 10..=DerivationIndex::MAX;
            worker::iterator_to_last_elem(
                parent_key,
                parent_key.into_range_iter(range.clone()),
                range,
            );
        }

        // tests that iterator operates in reverse
        #[test]
        pub fn double_ended_iterator() {
            let parent_key = helper::make_parent_key();
            worker::double_ended_iterator(
                parent_key,
                parent_key.into_iter(),
                0..usize::MAX as DerivationIndex,
            );
        }

        // tests that range iterator operates in reverse
        #[test]
        pub fn double_ended_range_iterator() {
            let parent_key = helper::make_parent_key();
            let range = 0..50;
            worker::double_ended_iterator(
                parent_key,
                parent_key.into_range_iter(range.clone()),
                range,
            );
        }

        // tests that forward and reverse iteration meets in the middle and do
        // not pass eachother.
        #[test]
        pub fn double_ended_iterator_meet_middle() {
            let parent_key = helper::make_parent_key();

            let range = 0..50;
            worker::double_ended_iterator_meet_middle(
                parent_key,
                parent_key.into_range_iter(range.clone()),
                range,
            );
        }

        /// tests that reverse iteration does not go past first elem in range
        #[test]
        pub fn double_ended_iterator_to_first_elem() {
            let parent_key = helper::make_parent_key();

            let range = 10..20;
            worker::double_ended_iterator_to_first_elem(
                parent_key,
                parent_key.into_range_iter(range.clone()),
                range,
            );
        }

        // tests that reverse iteration can reach 0 elem, and stops after
        #[test]
        pub fn double_ended_iterator_to_zero_elem() {
            let parent_key = helper::make_parent_key();

            let range = 0..20;
            worker::double_ended_iterator_to_first_elem(
                parent_key,
                parent_key.into_range_iter(range.clone()),
                range,
            );
        }

        mod worker {
            use std::ops::Range;

            use super::*;

            // derives 5 keys and verifies that:
            //  1. derive_nth(n) matches Iterator::next() for each
            //  2. derive_nth() works (from parent_key) even after iteration has begun.
            pub fn derive_nth_matches_iter() {
                let mut iter = helper::make_iter();

                for n in 0..5 {
                    assert_eq!(Some(iter.parent_key.derive_child(n)), iter.next());
                }
            }

            // derives 5 keys and verifies that iteration results match SpendingKey::derive_child() results
            pub fn iterator(parent_key: SpendingKey, mut iter: impl Iterator<Item = SpendingKey>) {
                for n in 0..5 {
                    assert_eq!(Some(parent_key.derive_child(n)), iter.next());
                }
            }

            // verifies that Iterator::nth() works and does not rewind the iterator
            #[allow(clippy::iter_nth_zero)]
            pub fn iterator_nth(
                parent_key: SpendingKey,
                mut iter: impl Iterator<Item = SpendingKey>,
            ) {
                assert_eq!(Some(parent_key.derive_child(5)), iter.nth(5));

                // verify that nth() does not rewind iterator.
                assert_eq!(Some(parent_key.derive_child(6)), iter.nth(0));
            }

            // tests that iteration reaches last elem in range and then stops.
            pub fn iterator_to_last_elem(
                parent_key: SpendingKey,
                mut iter: impl Iterator<Item = SpendingKey>,
                range: RangeInclusive<DerivationIndex>,
            ) {
                let len = range.end() - range.start();
                assert_eq!(
                    Some(parent_key.derive_child(range.start() + len - 1)),
                    iter.nth((len - 1) as usize)
                );

                assert_eq!(None, iter.next());
            }

            // tests that backwards iteration works
            pub fn double_ended_iterator(
                parent_key: SpendingKey,
                mut iter: impl DoubleEndedIterator<Item = SpendingKey>,
                range: Range<DerivationIndex>,
            ) {
                assert_eq!(range.start, 0);
                let len = helper::range_len(&range);

                for n in 0..5 {
                    assert_eq!(Some(parent_key.derive_child(n)), iter.next());
                }
                for n in (len - 5..len).rev() {
                    assert_eq!(Some(parent_key.derive_child(n)), iter.next_back());
                }
            }

            // tests that forward and backwards iteration meets in the middle
            // and do not pass eachother
            pub fn double_ended_iterator_meet_middle(
                parent_key: SpendingKey,
                mut iter: impl DoubleEndedIterator<Item = SpendingKey>,
                range: Range<DerivationIndex>,
            ) {
                assert_eq!(range.start, 0);
                let len = helper::range_len(&range);

                for n in 0..5 {
                    assert_eq!(Some(parent_key.derive_child(n)), iter.next());
                }
                assert_eq!(
                    Some(parent_key.derive_child(10)),
                    iter.nth_back((len - 1 - 10) as usize)
                );

                for n in (5..10).rev() {
                    assert_eq!(Some(parent_key.derive_child(n)), iter.next_back());
                }

                assert_eq!(None, iter.next_back());
                assert_eq!(None, iter.next());
            }

            // tests that backwards iteration can reach the first element in a range.
            pub fn double_ended_iterator_to_first_elem(
                parent_key: SpendingKey,
                mut iter: impl DoubleEndedIterator<Item = SpendingKey>,
                range: Range<DerivationIndex>,
            ) {
                let len = helper::range_len(&range);
                assert!(len >= 2);

                assert_eq!(
                    Some(parent_key.derive_child(range.start + 1)),
                    iter.nth_back((len - 2) as usize)
                );

                assert_eq!(Some(parent_key.derive_child(range.start)), iter.next_back());
                assert_eq!(None, iter.next_back());
            }
        }
    }

    mod par_iter_tests {
        use super::*;

        // tests iteration over entire range, comparing with SpendingKey::derive_child()
        #[test]
        pub fn range_iterator_entire_range() {
            worker::iterator_all_in_range(10..=500);
            worker::iterator_all_in_range(10..500);
            worker::iterator_all_in_range(..500);
            worker::iterator_all_in_range(DerivationIndex::MAX - 500..);
        }

        mod worker {
            use std::collections::HashSet;

            use rayon::iter::IndexedParallelIterator;
            use rayon::iter::ParallelIterator;

            use super::*;

            // compares parallel range iter results to non-parallel range iter results.
            pub fn iterator_all_in_range(range: impl RangeBounds<DerivationIndex> + Clone) {
                let parent_key = helper::make_parent_key();
                let set1: HashSet<SpendingKey> =
                    parent_key.into_range_iter(range.clone()).collect();

                // test by collect() and set equality.
                let set2: HashSet<SpendingKey> =
                    parent_key.into_par_range_iter(range.clone()).collect();
                assert_eq!(set1, set2);

                // test without collect(), by comparing len, and ensuring all elems are in the set.
                let par_iter = parent_key.into_par_range_iter(range);
                assert!(par_iter.len() == set1.len());
                assert!(par_iter.all(|k| set1.contains(&k)));
            }
        }
    }

    mod range_bounds {
        use super::*;

        #[test]
        fn range() {
            worker::validate_range(0..1);
            worker::validate_range(0..0);
            worker::validate_range(1..10);
            worker::validate_range(1..usize::MAX as DerivationIndex);
            worker::validate_range(1..DerivationIndex::MAX);
        }

        #[test]
        fn range_from() {
            worker::validate_range_from(1..);
            worker::validate_range_from(0..);
            worker::validate_range_from(10..);
            worker::validate_range_from(usize::MAX as DerivationIndex + 5..);
        }

        #[test]
        fn range_to() {
            worker::validate_range_to(..1);
            worker::validate_range_to(..0);
            worker::validate_range_to(..10);
            worker::validate_range_to(..usize::MAX as DerivationIndex);
        }

        #[test]
        fn range_full() {
            worker::validate_range_full(..);
        }

        mod worker {
            use std::ops;

            use super::*;

            pub fn validate_range(r: ops::Range<DerivationIndex>) {
                println!("testing {:?}", r);
                let ri = SpendingKeyIter::range_bounds_to_inclusive(r.clone());
                assert_eq!(r.start, *ri.start());
                assert_eq!(if r.end == 0 { 0 } else { r.end - 1 }, *ri.end());
            }

            pub fn validate_range_from(r: ops::RangeFrom<DerivationIndex>) {
                println!("testing {:?}", r);
                let ri = SpendingKeyIter::range_bounds_to_inclusive(r.clone());
                assert_eq!(r.start, *ri.start());

                let end = match r.start.checked_add(usize::MAX as DerivationIndex) {
                    Some(v) => v,
                    None => DerivationIndex::MAX,
                };
                assert_eq!(end, *ri.end());
            }

            pub fn validate_range_to(r: ops::RangeTo<DerivationIndex>) {
                println!("testing {:?}", r);
                let ri = SpendingKeyIter::range_bounds_to_inclusive(r);
                assert_eq!(0, *ri.start());
                assert_eq!(if r.end == 0 { 0 } else { r.end - 1 }, *ri.end());
            }

            pub fn validate_range_full(r: ops::RangeFull) {
                println!("testing {:?}", r);
                let ri = SpendingKeyIter::range_bounds_to_inclusive(r);
                assert_eq!(0, *ri.start());
                assert_eq!(usize::MAX as DerivationIndex, *ri.end());
            }
        }
    }

    mod helper {
        use super::*;
        use crate::models::state::wallet::address::KeyType;

        // generates a random SpendingKey.
        //
        // note: we use a SymmetricKey because it is faster to derive and uses
        // less memory than GenerationSpendingKey.  For purposes of testing iterator
        // logic, the key-type does not matter.
        pub fn make_parent_key() -> SpendingKey {
            SpendingKey::from_seed(rand::random(), KeyType::Symmetric)
        }

        // generates an iterator for a random SpendingKey::SymmetricKey
        pub fn make_iter() -> SpendingKeyIter {
            make_parent_key().into_iter()
        }

        pub fn range_len(r: &std::ops::Range<DerivationIndex>) -> DerivationIndex {
            if r.end < 1 {
                0
            } else {
                r.end - 1 - r.start
            }
        }
    }
}
