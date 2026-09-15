//! The set of standing swap orders currently open on one asset pair.
//!
//! The book is a container, not a chain consumer. Its entries are the
//! end-product of a long chain of events: finding the announcement, decoding it
//! under the schema `pair_id` names, rebuilding the lock script, deriving the
//! order UTXO's addition record and finding that record in the AOCL, whose
//! position is the leaf index that identifies the order. Every [`Order`] in
//! the book has therefore already been verified, and no method below performs
//! a lookup of any kind.
//!
//! The order book is *driven*, never driving. It is told what a block
//! changed through [`OrderBook::apply`], and told to forget a branch through
//! [`OrderBook::roll_back_to`]. Whether those calls come from a local archival
//! state or from a subscription to a remote node is not visible from here.

use std::collections::HashMap;
use std::fmt;

use neptune_primitives::block_height::BlockHeight;
use tasm_lib::prelude::Digest;

use super::AssetPair;
use super::StandingSwapOrder;
use super::Swappable;

/// Identity of an order: the AOCL leaf index of the order UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OrderId(pub u64);

/// One order, as the book knows it: open, or closed recently enough that a
/// reorganization could still reopen it.
///
/// What the [`Order`] adds over [`StandingSwapOrder`] is information relating
/// it to the blockchain it came from.
#[derive(Debug, Clone)]
pub struct Order<C: Swappable> {
    pub id: OrderId,

    /// The block that confirmed the order.
    pub opened_in: BlockId,

    /// The block that spent the order UTXO, whether via `Fill` or `Cancel`, or
    /// `None` while the order is open.
    pub closed_in: Option<BlockId>,

    /// The order's terms and its configuration's parameters.
    pub order: StandingSwapOrder<C>,
}

/// A block identifier: its height and its hash.
///
/// The height orders blocks, which rollback and pruning need. The hash
/// distinguishes blocks at the same height on different branches, which is how
/// the order book knows it's on the wrong branch (or its update is).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockId {
    pub height: BlockHeight,
    pub hash: Digest,
}

/// What one block did to the book, as the feeder observed it.
#[derive(Debug, Clone)]
pub struct BlockUpdate<C: Swappable> {
    pub block: BlockId,
    pub parent: Digest,
    pub opened: Vec<Order<C>>,
    pub closed: Vec<OrderId>,
}

/// An update that does not extend the book's tip.
///
/// The usual cause is a feeder that observed a reorganization but did not call
/// [`OrderBook::roll_back_to`] before applying blocks from the new branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discontinuity {
    pub book_tip: BlockId,
    pub update_block: BlockId,
    pub update_parent: Digest,
}

impl fmt::Display for Discontinuity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block {:?} at height {} with parent {:?} does not extend tip {:?} at height {}",
            self.update_block.hash,
            self.update_block.height,
            self.update_parent,
            self.book_tip.hash,
            self.book_tip.height,
        )
    }
}

impl std::error::Error for Discontinuity {}

#[derive(Debug, Clone)]
pub struct OrderBook<C: Swappable> {
    pair: AssetPair,
    entries: HashMap<OrderId, Order<C>>,
    tip: Option<BlockId>,
}

impl<C: Swappable> OrderBook<C> {
    pub fn new(pair: AssetPair) -> Self {
        Self {
            pair,
            entries: HashMap::new(),
            tip: None,
        }
    }

    /// The assets every order in this book offers and demands.
    pub fn pair(&self) -> &AssetPair {
        &self.pair
    }

    /// The block this book reflects, or `None` if it has seen no blocks.
    pub fn tip(&self) -> Option<BlockId> {
        self.tip
    }

    /// The entry for `id`, whether open or closed but not yet pruned.
    /// Check [`Order::closed_in`] to tell which.
    pub fn get(&self, id: OrderId) -> Option<&Order<C>> {
        self.entries.get(&id)
    }

    /// The number of open orders.
    pub fn len(&self) -> usize {
        self.open_orders().count()
    }

    /// Whether no order is open.
    pub fn is_empty(&self) -> bool {
        self.open_orders().next().is_none()
    }

    /// Every open order, in no particular order.
    ///
    /// Queries that depend on what an order means live with the configuration
    /// that gives it that meaning, as `demanding` does on
    /// `OrderBook<Sofun>`, and build on this.
    pub fn open_orders(&self) -> impl Iterator<Item = &Order<C>> {
        self.entries
            .values()
            .filter(|entry| entry.closed_in.is_none())
    }

    /// Admit and retire orders.
    ///
    /// The update must extend the tip: its parent is the tip's hash and its
    /// height is one more. This is what keeps the book on a single branch, and
    /// that in turn is what lets rollback compare entries by height alone. The
    /// first update a fresh book receives is accepted as is.
    ///
    /// Re-applying the tip itself is a no-op. Any other update that does not
    /// extend the tip is rejected, older blocks included: without history the
    /// book cannot tell a replay of an ancestor from a block on another branch.
    pub fn apply(&mut self, update: BlockUpdate<C>) -> Result<(), Discontinuity> {
        if let Some(tip) = self.tip {
            if update.block == tip {
                return Ok(());
            }
            if update.parent != tip.hash || update.block.height != tip.height.next() {
                return Err(Discontinuity {
                    book_tip: tip,
                    update_block: update.block,
                    update_parent: update.parent,
                });
            }
        }

        for mut entry in update.opened {
            entry.opened_in = update.block;
            entry.closed_in = None;
            self.entries.insert(entry.id, entry);
        }

        for id in update.closed {
            if let Some(entry) = self.entries.get_mut(&id) {
                if entry.closed_in.is_none() {
                    entry.closed_in = Some(update.block);
                }
            }
        }

        self.tip = Some(update.block);
        Ok(())
    }

    /// Undo every change above `luca`, reopen whatever closed on the way
    /// there, and make `luca` the tip.
    ///
    /// `luca` is the last block the abandoned branch shares with the new
    /// one. Its hash is what the first block of the new branch will name as
    /// its parent, so the book needs it to accept that block.
    pub fn roll_back_to(&mut self, luca: BlockId) {
        let height = luca.height;

        // Open and closed entries share one map, so an entry opened above the
        // luca is removed here whether or not it also closed there.
        self.entries
            .retain(|_, entry| entry.opened_in.height <= height);
        for entry in self.entries.values_mut() {
            if entry.closed_in.is_some_and(|closed| closed.height > height) {
                entry.closed_in = None;
            }
        }

        self.tip = Some(luca);
    }

    /// Remove every order, open or closed, for which `prune` returns true.
    ///
    /// Removal can make the book incomplete but never wrong: an order that is
    /// not in the book is never listed. So any predicate is safe to pass.
    ///
    /// A pruned order cannot come back through reorgs or rollbacks.
    pub fn prune(&mut self, mut prune: impl FnMut(&Order<C>) -> bool) {
        self.entries.retain(|_, order| !prune(order));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
    use tasm_lib::triton_vm::prelude::BFieldElement;

    use super::*;
    use crate::standing_swap_order::v1::Generic;

    const A: u64 = 0;
    const B: u64 = 1;

    fn block(height: u64, branch: u64) -> BlockId {
        BlockId {
            height: BlockHeight::from(height),
            hash: Digest::new([height, branch, 0, 0, 0].map(BFieldElement::new)),
        }
    }

    fn update(block: BlockId, parent: BlockId) -> BlockUpdate<Generic> {
        BlockUpdate {
            block,
            parent: parent.hash,
            opened: vec![],
            closed: vec![],
        }
    }

    fn pair() -> AssetPair {
        AssetPair {
            offered: HashSet::new(),
            demanded: HashSet::new(),
        }
    }

    fn entry(id: u64, opened_at: u64) -> Order<Generic> {
        Order {
            id: OrderId(id),
            opened_in: BlockId {
                height: BlockHeight::from(opened_at),
                hash: Digest::default(),
            },
            closed_in: None,
            order: StandingSwapOrder::<Generic>::new(
                NativeCurrencyAmount::coins(7),
                NativeCurrencyAmount::coins(11),
                Digest::default(),
                Digest::default(),
                Digest::default(),
                Digest::default(),
            ),
        }
    }

    #[test]
    fn a_missed_rollback_is_rejected_and_a_performed_one_is_accepted() {
        let mut book = OrderBook::new(pair());
        book.apply(update(block(98, A), block(97, A))).unwrap();
        book.apply(update(block(99, A), block(98, A))).unwrap();
        book.apply(update(block(100, A), block(99, A))).unwrap();

        // Re-applying the tip changes nothing.
        book.apply(update(block(100, A), block(99, A))).unwrap();
        assert_eq!(Some(block(100, A)), book.tip());

        // Branch B forks after block 98. Without a rollback its first block
        // does not extend the tip.
        assert!(book.apply(update(block(99, B), block(98, A))).is_err());

        book.roll_back_to(block(98, A));
        book.apply(update(block(99, B), block(98, A))).unwrap();
        book.apply(update(block(100, B), block(99, B))).unwrap();
        book.apply(update(block(101, B), block(100, B))).unwrap();
        assert_eq!(Some(block(101, B)), book.tip());
    }

    /// Regression: rollback used to restore closed entries after filtering the
    /// open ones, so an order both opened and closed on the abandoned branch
    /// came back as open although the surviving branch never confirmed it.
    #[test]
    fn rollback_reopens_only_orders_confirmed_on_the_surviving_branch() {
        let mut book = OrderBook::new(pair());

        let mut at_98 = update(block(98, A), block(97, A));
        at_98.opened.push(entry(1, 98));
        book.apply(at_98).unwrap();

        let mut at_99 = update(block(99, A), block(98, A));
        at_99.opened.push(entry(2, 99));
        book.apply(at_99).unwrap();

        let mut at_100 = update(block(100, A), block(99, A));
        at_100.closed.extend([OrderId(1), OrderId(2)]);
        book.apply(at_100).unwrap();
        assert!(book.is_empty());

        book.roll_back_to(block(98, A));

        // Order 1 was confirmed at the ancestor and closed above it.
        assert!(book.get(OrderId(1)).unwrap().closed_in.is_none());
        // Order 2 was confirmed and closed above the ancestor.
        assert!(book.get(OrderId(2)).is_none());
        assert_eq!(1, book.len());
    }

    /// Regression: `apply` used to trust the feeder's confirming height, so an entry
    /// carrying the wrong height survived a rollback that should remove it.
    #[test]
    fn apply_records_the_block_that_opened_the_order() {
        let mut book = OrderBook::new(pair());
        book.apply(update(block(98, A), block(97, A))).unwrap();

        let mut at_99 = update(block(99, A), block(98, A));
        at_99.opened.push(entry(3, 0));
        book.apply(at_99).unwrap();
        let opened = book.get(OrderId(3)).unwrap();
        assert_eq!(block(99, A), opened.opened_in);

        book.roll_back_to(block(98, A));
        assert!(book.is_empty());
    }

    #[test]
    fn a_closed_entry_is_retained_until_pruned() {
        let mut book = OrderBook::new(pair());

        let mut at_98 = update(block(98, A), block(97, A));
        at_98.opened.push(entry(4, 98));
        book.apply(at_98).unwrap();

        let mut at_99 = update(block(99, A), block(98, A));
        at_99.closed.push(OrderId(4));
        book.apply(at_99).unwrap();

        assert!(book.is_empty());
        assert_eq!(Some(block(99, A)), book.get(OrderId(4)).unwrap().closed_in);

        let closed_below = |height: u64| {
            move |order: &Order<Generic>| {
                order
                    .closed_in
                    .is_some_and(|closed| closed.height < BlockHeight::from(height))
            }
        };

        book.prune(closed_below(99));
        assert!(book.get(OrderId(4)).is_some());

        book.prune(closed_below(100));
        assert!(book.get(OrderId(4)).is_none());
    }
}
