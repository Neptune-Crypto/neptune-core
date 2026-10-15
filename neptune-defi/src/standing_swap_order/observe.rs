//! Routines for maintaining an [`OrderBook`] from blocks.
//!
//! [`OrderBook::observe`] computes which orders one block opens and closes: it
//! opens an order for every announcement of an order on the book's pair whose
//! UTXO is among the block's outputs, and closes every open order whose UTXO
//! the block spends. Applying its result with [`OrderBook::apply`] moves the
//! book to that block.

use std::collections::HashSet;

use super::order_book::BlockUpdate;
use super::order_book::Order;
use super::order_book::OrderBook;
use super::order_book::OrderId;
use super::Swappable;
use crate::chain::BlockId;
use crate::chain::ObservedBlock;
use crate::driver::ChainState;

impl<C: Swappable> OrderBook<C> {
    /// What `block` did to the book.
    ///
    /// An announcement opens an order if and only if it decodes as an order of
    /// configuration `C` on the book's pair and the order's UTXO is among the
    /// outputs of the same block. The order's identity is the leaf index that
    /// output became. An open order of the book is closed if and only if the
    /// block's transaction spends its UTXO.
    ///
    /// The book is read only for its open orders, so it must reflect the
    /// block's parent.
    //
    // ponytail: recomputes the index set of every open order on every block, one
    // hash per order. Store the set on the row when a template build measurably
    // notices.
    pub fn observe(&self, block: &ObservedBlock) -> BlockUpdate<C> {
        let pair_id = self.pair().pair_id();
        let mut claimed = HashSet::new();
        let opened = block
            .announcements
            .iter()
            // ponytail: an order under an unknown schema version is dropped like
            // any other non-order. Report it when the driver has somewhere to put
            // the report.
            .filter_map(|announcement| C::recognize(pair_id, &announcement.message).ok())
            .filter_map(|order| {
                let record = order.order_utxo().addition_record();

                // Two announcements of the same order need two outputs to be two
                // orders, so each output backs at most one of them.
                let position = (0..block.outputs.len())
                    .find(|&i| block.outputs[i] == record && !claimed.contains(&i))?;
                claimed.insert(position);

                Some(Order {
                    id: OrderId(block.first_leaf_index + position as u64),
                    opened_in: block.id,
                    closed_in: None,
                    order,
                })
            })
            .collect();

        let spent = block.spent.iter().collect::<HashSet<_>>();
        let closed = self
            .open_orders()
            .filter(|order| spent.contains(&order.order.absolute_index_set(order.id)))
            .map(|order| order.id)
            .collect();

        BlockUpdate {
            block: block.id,
            parent: block.parent,
            opened,
            closed,
        }
    }
}

/// A driver keeps the book in step with the chain by observing each block and
/// applying the result.
impl<C: Swappable> ChainState for OrderBook<C> {
    fn apply(&mut self, block: &ObservedBlock) {
        let update = self.observe(block);
        OrderBook::apply(self, update).expect("a driver applies each block on top of its parent");
    }

    fn roll_back_to(&mut self, ancestor: BlockId) {
        OrderBook::roll_back_to(self, ancestor);
    }
}

#[cfg(test)]
mod tests {
    use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
    use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::removal_record::RemovalRecord;
    use proptest::collection::vec;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::prelude::Digest;
    use test_strategy::proptest;

    use super::*;
    use crate::chain::BlockId;
    use crate::standing_swap_order::sofun::Sofun;
    use crate::standing_swap_order::StandingSwapOrder;

    fn book() -> OrderBook<Sofun> {
        OrderBook::new(Sofun::asset_pair(), u64::MAX)
    }

    fn kernel_with(
        kernel: &TransactionKernel,
        inputs: Vec<RemovalRecord>,
        outputs: Vec<AdditionRecord>,
        orders: &[StandingSwapOrder<Sofun>],
    ) -> TransactionKernel {
        TransactionKernelModifier::default()
            .inputs(inputs)
            .outputs(outputs)
            .announcements(
                orders
                    .iter()
                    .map(|order| order.announce(&Sofun::asset_pair()))
                    .collect(),
            )
            .modify(kernel.clone())
    }

    /// An order is identified by the AOCL leaf its UTXO became, which is its
    /// position among the block's outputs, counted from the block's first
    /// leaf.
    #[proptest(cases = 20)]
    fn announced_order_with_its_utxo_opens_at_its_leaf(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(vec(arb::<AdditionRecord>(), 0..4))] before: Vec<AdditionRecord>,
        #[strategy(vec(arb::<AdditionRecord>(), 0..4))] after: Vec<AdditionRecord>,
        #[strategy(0..u64::MAX / 2)] first_leaf_index: u64,
        #[strategy(arb())] block: BlockId,
        #[strategy(arb())] parent: Digest,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let outputs = [
            before.clone(),
            vec![order.order_utxo().addition_record()],
            after,
        ]
        .concat();
        let kernel = kernel_with(&kernel, vec![], outputs, &[order]);

        let update = book().observe(&ObservedBlock::new(
            block,
            parent,
            first_leaf_index,
            &kernel,
        ));
        prop_assert_eq!(1, update.opened.len());
        prop_assert_eq!(
            OrderId(first_leaf_index + before.len() as u64),
            update.opened[0].id
        );
        prop_assert!(update.closed.is_empty());
    }

    /// An announcement names a UTXO in its own block. One whose UTXO is not
    /// there is not an order.
    #[proptest(cases = 20)]
    fn announced_order_without_its_utxo_is_not_an_order(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(vec(arb::<AdditionRecord>(), 0..4))] outputs: Vec<AdditionRecord>,
        #[strategy(arb())] block: BlockId,
        #[strategy(arb())] parent: Digest,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let kernel = kernel_with(&kernel, vec![], outputs, &[order]);
        let update = book().observe(&ObservedBlock::new(block, parent, 0, &kernel));
        prop_assert!(update.opened.is_empty());
    }

    /// An order announced several times is as many orders as the block has
    /// outputs for it, each at its own leaf.
    #[proptest(cases = 20)]
    fn each_output_backs_one_order(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(1..3usize)] num_outputs: usize,
        #[strategy(arb())] block: BlockId,
        #[strategy(arb())] parent: Digest,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let outputs = vec![order.order_utxo().addition_record(); num_outputs];
        let kernel = kernel_with(&kernel, vec![], outputs, &[order, order, order]);

        let update = book().observe(&ObservedBlock::new(block, parent, 0, &kernel));
        let ids = update.opened.iter().map(|o| o.id.0).collect::<Vec<_>>();
        prop_assert_eq!((0..num_outputs as u64).collect::<Vec<_>>(), ids);
    }

    /// An open order closes on the block that spends its UTXO, and an order
    /// whose UTXO the block does not spend stays open.
    #[proptest(cases = 10)]
    fn spending_the_order_utxo_closes_the_order(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(arb())] bystander: StandingSwapOrder<Sofun>,
        #[strategy(arb())] mut input: RemovalRecord,
        #[strategy(arb())] opening_block: BlockId,
        #[strategy(arb())] closing_block: BlockId,
        #[strategy(arb())] kernel: TransactionKernel,
    ) {
        let outputs = vec![
            order.order_utxo().addition_record(),
            bystander.order_utxo().addition_record(),
        ];
        let opening = kernel_with(&kernel, vec![], outputs, &[order, bystander]);
        let mut book = book();
        let update = book.observe(&ObservedBlock::new(
            opening_block,
            Digest::default(),
            0,
            &opening,
        ));
        book.apply(update)?;

        input.absolute_indices = order.absolute_index_set(OrderId(0));
        let closing = kernel_with(&kernel, vec![input], vec![], &[]);
        let update = book.observe(&ObservedBlock::new(
            closing_block,
            opening_block.hash,
            2,
            &closing,
        ));
        prop_assert_eq!(vec![OrderId(0)], update.closed);
    }

    /// As a driver's state, the book opens an order on the block that carries
    /// it, closes it on the block that spends it, and reopens it when rolled
    /// back to a block before that.
    #[proptest(cases = 5)]
    fn as_chain_state_the_book_opens_closes_and_reopens_orders(
        #[strategy(arb())] order: StandingSwapOrder<Sofun>,
        #[strategy(arb())] mut input: RemovalRecord,
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(arb())] genesis_hash: Digest,
        #[strategy(arb())] opening_hash: Digest,
        #[strategy(arb())] closing_hash: Digest,
    ) {
        use neptune_primitives::block_height::BlockHeight;

        let id = |height: u64, hash| BlockId {
            height: BlockHeight::new(height.into()),
            hash,
        };
        let opening = id(1, opening_hash);
        let closing = id(2, closing_hash);
        let opening_kernel = kernel_with(
            &kernel,
            vec![],
            vec![order.order_utxo().addition_record()],
            &[order],
        );
        input.absolute_indices = order.absolute_index_set(OrderId(0));
        let closing_kernel = kernel_with(&kernel, vec![input], vec![], &[]);

        let mut book = book();
        let is_open =
            |book: &OrderBook<Sofun>| book.open_orders().any(|open| open.id == OrderId(0));
        ChainState::apply(
            &mut book,
            &ObservedBlock::new(opening, genesis_hash, 0, &opening_kernel),
        );
        prop_assert!(is_open(&book));

        ChainState::apply(
            &mut book,
            &ObservedBlock::new(closing, opening.hash, 1, &closing_kernel),
        );
        prop_assert!(!is_open(&book));

        ChainState::roll_back_to(&mut book, opening);
        prop_assert!(is_open(&book));
        prop_assert_eq!(Some(opening), book.tip());
    }
}
