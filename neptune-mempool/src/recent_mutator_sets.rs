//! The mutator set at the tip and at its nearest ancestors.
//!
//! Lets the node admit a transaction built against a block that is no longer
//! the tip: its removal records are checked against the mutator set they were
//! built for, then brought forward to the tip to confirm that no input was
//! spent in between.
//!
//! Derived from blocks as they become the tip, so it needs no archive. A
//! reorganization reduces the window to the new tip.

use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;

use neptune_consensus::block::Block;
use neptune_consensus::block::mutator_set_update::MutatorSetUpdate;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::network::Network;
use tasm_lib::prelude::Digest;

/// How many blocks behind the tip a transaction's mutator set may be for the
/// transaction to be judged against it. Policy, not consensus.
///
/// Memory grows with the depth: each block held keeps its removal records
/// unpacked, tens of kilobytes per input.
pub const MAX_TX_SYNC_DEPTH: usize = 3;

/// A block's mutator set update and the mutator set that resulted.
#[derive(Debug, Clone)]
struct Entry {
    block_hash: Digest,
    mutator_set_hash: Digest,
    mutator_set: MutatorSetAccumulator,

    /// `None` for the oldest entry, whose update is never read. Also `None`
    /// if it could not be derived from the block, which validation rules out;
    /// records cannot be brought forward across such an entry.
    update: Option<MutatorSetUpdate>,
}

/// The mutator set at the tip and at up to [`MAX_TX_SYNC_DEPTH`] of its
/// nearest ancestors, with the updates between them.
///
/// Cheap to clone: entries are shared, so a caller can take a snapshot and
/// release the chain-state lock before verifying a proof.
#[derive(Debug, Clone)]
pub struct RecentMutatorSets {
    /// Oldest first, tip last. Never empty.
    entries: VecDeque<Arc<Entry>>,
}

/// Why removal records could not be brought forward to the tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUpError {
    /// Neither the tip's mutator set nor a held ancestor's.
    UnknownMutatorSet,

    /// The input at this index was spent by a block since.
    SpentSince(usize),

    /// A held update did not apply. Indicates a bug in the window.
    Inconsistent,
}

impl RecentMutatorSets {
    /// A window holding only the given tip.
    ///
    /// # Panics
    ///
    /// Panics if the block has no mutator set after.
    pub fn new(tip: &Block, network: Network) -> Self {
        let entry = Self::entry_for(tip, network);
        Self {
            entries: VecDeque::from([Arc::new(entry)]),
        }
    }

    fn entry_for(block: &Block, network: Network) -> Entry {
        let mutator_set = block
            .mutator_set_accumulator_after()
            .expect("Block held as tip must have mutator set after");
        let update = block.mutator_set_update(network).ok();
        Entry {
            block_hash: block.hash(),
            mutator_set_hash: mutator_set.hash(),
            mutator_set,
            update,
        }
    }

    /// Record a new tip. If it does not extend the current tip, the chain
    /// reorganized, and the window is reduced to the new tip.
    ///
    /// # Panics
    ///
    /// Panics if the block has no mutator set after.
    pub fn update(&mut self, new_tip: &Block, network: Network) {
        let entry = Self::entry_for(new_tip, network);
        if new_tip.header().prev_block_digest != self.tip_block_hash() {
            self.entries.clear();
        }
        self.push(entry);
    }

    fn push(&mut self, entry: Entry) {
        self.entries.push_back(Arc::new(entry));
        while self.entries.len() > MAX_TX_SYNC_DEPTH + 1 {
            self.entries.pop_front();
        }

        // Records are only ever brought forward across the entries after the
        // oldest, so its update is dead weight, and the bulk of the entry.
        let oldest = self
            .entries
            .front_mut()
            .expect("Window always holds at least the tip");
        if oldest.update.is_some() {
            *oldest = Arc::new(Entry {
                block_hash: oldest.block_hash,
                mutator_set_hash: oldest.mutator_set_hash,
                mutator_set: oldest.mutator_set.clone(),
                update: None,
            });
        }
    }

    fn tip_entry(&self) -> &Entry {
        self.entries
            .back()
            .expect("Window must hold at least the tip")
    }

    pub fn tip_block_hash(&self) -> Digest {
        self.tip_entry().block_hash
    }

    pub fn tip_mutator_set(&self) -> &MutatorSetAccumulator {
        &self.tip_entry().mutator_set
    }

    pub fn tip_mutator_set_hash(&self) -> Digest {
        self.tip_entry().mutator_set_hash
    }

    /// Not counting the tip.
    pub fn num_ancestors(&self) -> usize {
        self.entries.len() - 1
    }

    /// Oldest first.
    fn position(&self, mutator_set_hash: Digest) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.mutator_set_hash == mutator_set_hash)
    }

    /// Blocks behind the tip. Zero for the tip itself.
    pub fn depth_of(&self, mutator_set_hash: Digest) -> Option<usize> {
        self.position(mutator_set_hash)
            .map(|position| self.entries.len() - 1 - position)
    }

    pub fn contains(&self, mutator_set_hash: Digest) -> bool {
        self.position(mutator_set_hash).is_some()
    }

    pub fn mutator_set(&self, mutator_set_hash: Digest) -> Option<&MutatorSetAccumulator> {
        self.position(mutator_set_hash)
            .map(|position| &self.entries[position].mutator_set)
    }

    /// Bring removal records forward from the mutator set with the given
    /// hash to the tip. The caller must have validated them against the
    /// former. The returned records validate against the tip and are all
    /// removable there.
    pub fn catch_up(
        &self,
        mutator_set_hash: Digest,
        removal_records: &[RemovalRecord],
    ) -> Result<Vec<RemovalRecord>, CatchUpError> {
        let Some(position) = self.position(mutator_set_hash) else {
            return Err(CatchUpError::UnknownMutatorSet);
        };

        let Some(updates_since) = self
            .entries
            .iter()
            .skip(position + 1)
            .map(|entry| entry.update.as_ref())
            .collect::<Option<Vec<_>>>()
        else {
            return Err(CatchUpError::Inconsistent);
        };

        let spent_indices: HashSet<u128> = updates_since
            .iter()
            .flat_map(|update| update.removals.iter())
            .flat_map(|removal_record| removal_record.absolute_indices.to_array())
            .collect();
        let spent_since = removal_records.iter().position(|removal_record| {
            removal_record
                .absolute_indices
                .to_array()
                .iter()
                .all(|index| spent_indices.contains(index))
        });
        if let Some(index) = spent_since {
            return Err(CatchUpError::SpentSince(index));
        }

        let mut mutator_set = self.entries[position].mutator_set.clone();
        let mut removal_records = removal_records.to_vec();
        for update in updates_since {
            let mut records = removal_records.iter_mut().collect::<Vec<_>>();
            if update
                .apply_to_accumulator_and_records(&mut mutator_set, &mut records, &mut [])
                .is_err()
            {
                return Err(CatchUpError::Inconsistent);
            }
        }

        if mutator_set.hash() != self.tip_mutator_set_hash() {
            return Err(CatchUpError::Inconsistent);
        }

        // The exact test: indices set before the transaction's block may
        // combine with those set since to cover an input.
        if let Some(index) = removal_records
            .iter()
            .position(|removal_record| !mutator_set.can_remove(removal_record))
        {
            return Err(CatchUpError::SpentSince(index));
        }

        Ok(removal_records)
    }
}

#[cfg(any(test, feature = "test-helpers"))]
use tasm_lib::prelude::Tip5;

#[cfg(any(test, feature = "test-helpers"))]
impl RecentMutatorSets {
    /// A window holding only the given mutator set, for tests without blocks.
    pub fn for_mutator_set(mutator_set: MutatorSetAccumulator) -> Self {
        let entry = Entry {
            block_hash: Digest::default(),
            mutator_set_hash: mutator_set.hash(),
            mutator_set,
            update: None,
        };
        Self {
            entries: VecDeque::from([Arc::new(entry)]),
        }
    }

    /// Extend the window by one block applying `update`, without a [`Block`].
    pub fn push_update(&mut self, update: MutatorSetUpdate) {
        let mut mutator_set = self.tip_mutator_set().clone();
        update
            .apply_to_accumulator(&mut mutator_set)
            .expect("Test update must apply to tip mutator set");
        let entry = Entry {
            block_hash: Tip5::hash_pair(self.tip_block_hash(), mutator_set.hash()),
            mutator_set_hash: mutator_set.hash(),
            mutator_set,
            update: Some(update),
        };
        self.push(entry);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_consensus::block::test_helpers::invalid_empty_block;
    use neptune_consensus::block::test_helpers::invalid_empty_block_with_num_outputs;
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use proptest::arbitrary::Arbitrary;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use super::*;

    const _: () = assert!(
        MAX_TX_SYNC_DEPTH >= 1,
        "these tests need at least one ancestor in the window"
    );

    fn chain(network: Network, length: usize) -> Vec<Block> {
        let mut blocks = vec![Block::genesis(network)];
        for _ in 0..length {
            let next = invalid_empty_block_with_num_outputs(blocks.last().unwrap(), network, 3);
            blocks.push(next);
        }
        blocks
    }

    #[test]
    fn new_window_holds_only_the_tip() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let window = RecentMutatorSets::new(&genesis, network);
        let genesis_msh = genesis.mutator_set_accumulator_after().unwrap().hash();

        assert_eq!(0, window.num_ancestors());
        assert_eq!(genesis.hash(), window.tip_block_hash());
        assert_eq!(genesis_msh, window.tip_mutator_set_hash());
        assert_eq!(Some(0), window.depth_of(genesis_msh));
        assert!(window.contains(genesis_msh));
        assert!(!window.contains(Digest::default()));
        assert_eq!(None, window.depth_of(Digest::default()));
    }

    #[test]
    fn window_keeps_at_most_max_depth_ancestors() {
        let network = Network::Main;
        let blocks = chain(network, MAX_TX_SYNC_DEPTH + 3);
        let mut window = RecentMutatorSets::new(&blocks[0], network);
        let msh = |block: &Block| block.mutator_set_accumulator_after().unwrap().hash();

        for (i, block) in blocks.iter().enumerate().skip(1) {
            window.update(block, network);
            assert_eq!(block.hash(), window.tip_block_hash());
            assert_eq!(msh(block), window.tip_mutator_set_hash());
            assert_eq!(i.min(MAX_TX_SYNC_DEPTH), window.num_ancestors());
        }

        // The last MAX_TX_SYNC_DEPTH + 1 blocks are held, at the right depths.
        let tip_index = blocks.len() - 1;
        for (i, block) in blocks.iter().enumerate() {
            let expected = (tip_index - i <= MAX_TX_SYNC_DEPTH).then_some(tip_index - i);
            assert_eq!(expected, window.depth_of(msh(block)), "block {i}");
            assert_eq!(expected.is_some(), window.contains(msh(block)));
            assert_eq!(expected.is_some(), window.mutator_set(msh(block)).is_some());
        }
    }

    #[test]
    fn reorganization_reduces_window_to_new_tip() {
        let network = Network::Main;
        let blocks = chain(network, 3);
        let mut window = RecentMutatorSets::new(&blocks[0], network);
        for block in &blocks[1..] {
            window.update(block, network);
        }
        assert_eq!(3.min(MAX_TX_SYNC_DEPTH), window.num_ancestors());

        // A competing block 2, not extending the current tip (block 3).
        let block_2b = invalid_empty_block(&blocks[1], network);
        assert_ne!(block_2b.hash(), blocks[2].hash());
        window.update(&block_2b, network);

        assert_eq!(0, window.num_ancestors());
        assert_eq!(block_2b.hash(), window.tip_block_hash());
        let old_tip_msh = blocks[3].mutator_set_accumulator_after().unwrap().hash();
        assert!(!window.contains(old_tip_msh));
    }

    #[test]
    fn duplicate_tip_update_is_a_reorganization() {
        // Feeding the tip again does not extend the chain, so the window
        // must not grow.
        let network = Network::Main;
        let blocks = chain(network, 2);
        let mut window = RecentMutatorSets::new(&blocks[0], network);
        window.update(&blocks[1], network);
        window.update(&blocks[2], network);
        window.update(&blocks[2], network);
        assert_eq!(0, window.num_ancestors());
    }

    /// A mutator set with removal records valid against it.
    fn msa_with_records(num_records: usize) -> MsaAndRecords {
        let removables =
            vec![(Digest::default(), Digest::default(), Digest::default()); num_records];
        let mut test_runner = TestRunner::deterministic();
        MsaAndRecords::arbitrary_with((removables, 1u64 << 20))
            .new_tree(&mut test_runner)
            .unwrap()
            .current()
    }

    #[test]
    fn catch_up_through_additions_only() {
        let msa_and_records = msa_with_records(2);
        let old_msh = msa_and_records.mutator_set_accumulator.hash();
        let records = msa_and_records.unpacked_removal_records();
        let mut window =
            RecentMutatorSets::for_mutator_set(msa_and_records.mutator_set_accumulator);

        // Enough additions to slide the window a few times.
        let additions = (0..40u64)
            .map(|i| AdditionRecord::new(Digest::new([i.into(); 5])))
            .collect::<Vec<_>>();
        window.push_update(MutatorSetUpdate::new(vec![], additions));
        assert_eq!(1, window.num_ancestors());
        assert_ne!(old_msh, window.tip_mutator_set_hash());

        let caught_up = window.catch_up(old_msh, &records).unwrap();
        let tip = window.tip_mutator_set();
        for record in &caught_up {
            assert!(record.validate(tip));
            assert!(tip.can_remove(record));
        }
    }

    #[test]
    fn catch_up_reports_input_spent_since() {
        let msa_and_records = msa_with_records(3);
        let old_msh = msa_and_records.mutator_set_accumulator.hash();
        let records = msa_and_records.unpacked_removal_records();
        let mut window =
            RecentMutatorSets::for_mutator_set(msa_and_records.mutator_set_accumulator);

        // A block spends the second record.
        window.push_update(MutatorSetUpdate::new(vec![records[1].clone()], vec![]));

        assert_eq!(
            Err(CatchUpError::SpentSince(1)),
            window.catch_up(old_msh, &records)
        );

        // The other two, on their own, come through fine.
        let others = [records[0].clone(), records[2].clone()];
        let caught_up = window.catch_up(old_msh, &others).unwrap();
        let tip = window.tip_mutator_set();
        for record in &caught_up {
            assert!(record.validate(tip));
            assert!(tip.can_remove(record));
        }
    }

    #[test]
    fn catch_up_at_tip_is_identity() {
        let msa_and_records = msa_with_records(2);
        let msh = msa_and_records.mutator_set_accumulator.hash();
        let records = msa_and_records.unpacked_removal_records();
        let window = RecentMutatorSets::for_mutator_set(msa_and_records.mutator_set_accumulator);

        let caught_up = window.catch_up(msh, &records).unwrap();
        assert_eq!(records, caught_up);
    }

    #[test]
    fn catch_up_rejects_unknown_mutator_set() {
        let msa_and_records = msa_with_records(1);
        let records = msa_and_records.unpacked_removal_records();
        let window = RecentMutatorSets::for_mutator_set(msa_and_records.mutator_set_accumulator);

        assert_eq!(
            Err(CatchUpError::UnknownMutatorSet),
            window.catch_up(Digest::default(), &records)
        );
    }

    #[test]
    fn catch_up_across_the_whole_window() {
        let msa_and_records = msa_with_records(4);
        let old_msh = msa_and_records.mutator_set_accumulator.hash();
        let records = msa_and_records.unpacked_removal_records();
        let mut window =
            RecentMutatorSets::for_mutator_set(msa_and_records.mutator_set_accumulator);

        // Additions in every block. The last block also spends the last record.
        let additions = |seed: u64, n: u64| {
            (0..n)
                .map(|i| AdditionRecord::new(Digest::new([(seed * 1000 + i).into(); 5])))
                .collect::<Vec<_>>()
        };
        let depth = MAX_TX_SYNC_DEPTH as u64;
        for seed in 1..depth {
            window.push_update(MutatorSetUpdate::new(vec![], additions(seed, 9)));
        }
        // The spent record must be synced to the state it is applied to.
        let spent = window
            .catch_up(old_msh, std::slice::from_ref(&records[3]))
            .unwrap()
            .remove(0);
        window.push_update(MutatorSetUpdate::new(vec![spent], additions(depth, 17)));
        assert_eq!(Some(MAX_TX_SYNC_DEPTH), window.depth_of(old_msh));

        assert_eq!(
            Err(CatchUpError::SpentSince(3)),
            window.catch_up(old_msh, &records)
        );

        let caught_up = window.catch_up(old_msh, &records[..3]).unwrap();
        let tip = window.tip_mutator_set();
        for record in &caught_up {
            assert!(record.validate(tip));
            assert!(tip.can_remove(record));
        }
    }
}
