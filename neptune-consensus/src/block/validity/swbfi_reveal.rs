//! The guesser's reveal of the inactive SWBF after the parent block: a leaf
//! of its first Merkle tree with the authentication path, in the
//! proof-of-work field, at the position sampled by the parent's hash and the
//! guesser's receiver data. The guesser holds that state before any proposal
//! arrives, and the composer cannot fill the field for them. A tree taller
//! than the field holds is revealed from the node as far below the root as
//! the field reaches, on the sampled leaf's path.

use tasm_lib::arithmetic::u64::log_2_floor::Log2Floor;
use tasm_lib::arithmetic::u64::shift_right::ShiftRight;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::prelude::*;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::block::block_header::BlockHeader;
use crate::block::block_header::BlockPow;
use crate::block::block_validation_error::BlockValidationRule;
use crate::block::guesser_receiver_data::GuesserReceiverData;
use crate::block::validity::knows_mutator_set::sample_digest;

/// The node of the inactive SWBF's first Merkle tree the guesser must
/// reveal, with the levels from it to the root, for an inactive SWBF with
/// this many leafs: the sampled leaf, or where the tree is taller than the
/// field holds, the node above it as far down as the field reaches. None
/// when the SWBF has no leafs.
pub fn guesser_node_index(
    prev_block_digest: Digest,
    receiver_data: &GuesserReceiverData,
    leaf_count: u64,
) -> Option<(u64, u32)> {
    let height = leaf_count.checked_ilog2()?;
    let levels = height.min(BlockPow::SWBFI_REVEAL_MAX_HEIGHT as u32);
    let sample = sample_digest(prev_block_digest, Tip5::hash(receiver_data)).values()[0];
    let index = (sample.value() >> (height - levels)) & ((1 << levels) - 1);
    Some((index, levels))
}

/// The root of a path from the node with this index, this many levels up.
fn root_of_path(index: u64, node: Digest, path: &[Digest]) -> Digest {
    path.iter()
        .enumerate()
        .fold(node, |node, (level, &sibling)| {
            if (index >> level) & 1 == 0 {
                Tip5::hash_pair(node, sibling)
            } else {
                Tip5::hash_pair(sibling, node)
            }
        })
}

/// Whether the header's proof-of-work field reveals the sampled node of this
/// inactive SWBF's first Merkle tree. Vacuous for an empty SWBF.
pub fn guesser_reveal_is_valid(header: &BlockHeader, swbfi: &MmrAccumulator) -> bool {
    let Some((index, levels)) = guesser_node_index(
        header.prev_block_digest,
        &header.guesser_receiver_data,
        swbfi.num_leafs(),
    ) else {
        return true;
    };
    let (node, path) = header.pow.swbfi_reveal(levels as usize);
    swbfi.peaks().first() == Some(&root_of_path(index, node, &path))
}

/// Crashes unless the header's proof-of-work field reveals the sampled node
/// of the inactive SWBF's first Merkle tree, as [`guesser_reveal_is_valid`]
/// decides.
///
/// ```text
/// BEFORE: _ *header *swbfi
/// AFTER:  _
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct GuesserSwbfiReveal;

impl GuesserSwbfiReveal {
    /// The levels of the tree one `merkle_step_mem` walk covers: a node
    /// index at the top of the walk must be a u32.
    const LOW_LEVELS: usize = 31;
}

impl BasicSnippet for GuesserSwbfiReveal {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*header".to_string()),
            (DataType::VoidPointer, "*swbfi".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_guesser_swbfi_reveal".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let log2_floor = library.import(Box::new(Log2Floor));
        let shift_right = library.import(Box::new(ShiftRight));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let error_id = BlockValidationRule::GuesserSwbfiReveal.error_id();
        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let read_leaf_count = triton_asm!(
            {&field!(MmrAccumulator::leaf_count)} addi 1 read_mem 2 pop 1
        );
        let path = triton_asm!({&field!(BlockHeader::pow)} {&field!(BlockPow::path_b)});
        let leaf = triton_asm!(
            {&field!(BlockHeader::pow)} {&field!(BlockPow::path_a)}
            addi {Digest::LEN * (BlockPow::SWBFI_REVEAL_MAX_HEIGHT - BlockPow::MERKLE_TREE_HEIGHT)}
            {&read_digest}
        );
        let entrypoint = self.entrypoint();
        let check = format!("{entrypoint}_check");
        let walk = format!("{entrypoint}_walk");
        let high_levels = format!("{entrypoint}_high_levels");
        triton_asm!(
            {entrypoint}:
                // _ *header *swbfi
                dup 0 {&read_leaf_count}
                // _ *header *swbfi lc_hi lc_lo
                dup 1 dup 1 add push 0 eq push 0 eq
                skiz call {check}
                pop 4
                return

            // The levels walked are the tree's height, at most what the
            // field holds; the sample loses as many low bits as levels are
            // left out. The walk splits at the low levels: the node index
            // above them is the sample shifted down by as many bits.
            // BEFORE: _ *header *swbfi lc_hi lc_lo
            // AFTER:  _ *header *swbfi x y
            {check}:
                call {log2_floor}
                // _ *header *swbfi height
                dup 2 {&field_with_size!(BlockHeader::guesser_receiver_data)} call {hash_varlen}
                dup 7 {&field!(BlockHeader::prev_block_digest)} {&read_digest}
                hash place 4 pop 4 split
                // _ *header *swbfi height w_hi w_lo
                dup 2 push {BlockPow::SWBFI_REVEAL_MAX_HEIGHT} lt
                dup 3 addi {-(BlockPow::SWBFI_REVEAL_MAX_HEIGHT as i32)} mul
                // _ *header *swbfi height w_hi w_lo left_out
                dup 0 push -1 mul pick 4 add place 3
                call {shift_right}
                // _ *header *swbfi levels w_hi w_lo
                dup 2 push {Self::LOW_LEVELS} lt
                dup 3 addi {-(Self::LOW_LEVELS as i32)} mul
                // _ *header *swbfi levels w_hi w_lo high_levels
                dup 3 dup 1 push -1 mul add
                // _ *header *swbfi levels w_hi w_lo high_levels low_levels
                push 2 pow dup 0 dup 3 div_mod pick 1 pop 1 add
                // _ *header *swbfi levels w_hi w_lo high_levels low_node
                dup 6 {&path} push 1 pick 2
                // _ *header *swbfi levels w_hi w_lo high_levels *path 1 low_node
                dup 8 {&leaf}
                // _ *header *swbfi levels w_hi w_lo high_levels *path 1 low_node [leaf]
                dup 5 push 1 eq push 0 eq skiz call {walk}
                // _ *header *swbfi levels w_hi w_lo high_levels *path' 1 1 [node]
                dup 8 push 0 eq push 0 eq skiz call {high_levels}
                // _ *header *swbfi levels w_hi w_lo high_levels *path'' 1 1 [root]
                dup 12 {&field!(MmrAccumulator::peaks)} addi 1 {&read_digest}
                assert_vector error_id {error_id}
                pop 5 pop 5
                return

            // INVARIANT: _ *path 1 node_index [node]
            {walk}:
                merkle_step_mem
                recurse_or_return

            // BEFORE: _ *header *swbfi levels w_hi w_lo high_levels *path 1 1 [node]
            // AFTER:  _ *header *swbfi levels w_hi w_lo high_levels *path' 1 1 [root]
            {high_levels}:
                dup 10 dup 10 push {Self::LOW_LEVELS} call {shift_right}
                pick 1 pop 1
                // _ *header *swbfi levels w_hi w_lo high_levels *path 1 1 [node] shifted_lo
                dup 9 push 2 pow dup 0 pick 2 div_mod pick 1 pop 1 add
                // _ *header *swbfi levels w_hi w_lo high_levels *path 1 1 [node] high_node
                place 5 pick 6 pop 1
                // _ *header *swbfi levels w_hi w_lo high_levels *path 1 high_node [node]
                call {walk}
                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(in crate::block) mod tests {
    use std::collections::HashMap;

    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::test_helpers::test_assertion_failure;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;

    use super::*;

    /// A random header revealing a random node, in a first Merkle tree of
    /// this height made up around the node's path, and the inactive SWBF
    /// whose first peak it is, with this many leafs.
    pub(in crate::block) fn revealing_header_and_swbfi(
        rng: &mut StdRng,
        height: u32,
        leaf_count: u64,
    ) -> (BlockHeader, MmrAccumulator) {
        assert_eq!(height, leaf_count.ilog2());
        let mut header: BlockHeader = rng.random();
        let (index, levels) = guesser_node_index(
            header.prev_block_digest,
            &header.guesser_receiver_data,
            leaf_count,
        )
        .unwrap();
        let node: Digest = rng.random();
        let path = (0..levels).map(|_| rng.random()).collect::<Vec<Digest>>();
        let root = root_of_path(index, node, &path);
        header.pow.set_swbfi_reveal(node, &path);
        let other_peaks = (1..leaf_count.count_ones()).map(|_| rng.random());
        let peaks = [root].into_iter().chain(other_peaks).collect();
        (header, MmrAccumulator::init(peaks, leaf_count))
    }

    /// A leaf count whose first tree has this height.
    fn leaf_count_of_height(rng: &mut StdRng, height: u32) -> u64 {
        (1 << height) | rng.random_range(0..1u64 << height)
    }

    impl Function for GuesserSwbfiReveal {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let swbfi_pointer = stack.pop().unwrap();
            let header_pointer = stack.pop().unwrap();
            let swbfi = *MmrAccumulator::decode_from_memory(memory, swbfi_pointer).unwrap();
            let header = *BlockHeader::decode_from_memory(memory, header_pointer).unwrap();
            if guesser_reveal_is_valid(&header, &swbfi) {
                Ok(())
            } else {
                Err(RustShadowError::AssertionError(
                    BlockValidationRule::GuesserSwbfiReveal.error_id(),
                ))
            }
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let height = match bench_case {
                Some(BenchmarkCase::CommonCase) => 20,
                Some(BenchmarkCase::WorstCase) => 63,
                None => rng.random_range(0..=63),
            };
            let leaf_count = leaf_count_of_height(&mut rng, height);
            let (header, swbfi) = revealing_header_and_swbfi(&mut rng, height, leaf_count);
            self.initial_state(&header, &swbfi)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            let empty = MmrAccumulator::init(vec![], 0);
            let vacuous = self.initial_state(&rng.random(), &empty);
            let heights = [0, 1, 30, 31, 32, 33, 54, 55, 63];
            let revealing = heights.map(|height| {
                let leaf_count = leaf_count_of_height(&mut rng, height);
                let (header, swbfi) = revealing_header_and_swbfi(&mut rng, height, leaf_count);
                self.initial_state(&header, &swbfi)
            });
            [vec![vacuous], revealing.to_vec()].concat()
        }
    }

    impl GuesserSwbfiReveal {
        fn initial_state(
            &self,
            header: &BlockHeader,
            swbfi: &MmrAccumulator,
        ) -> FunctionInitialState {
            let header_pointer = bfe!(1 << 20);
            let swbfi_pointer = bfe!(1 << 21);
            let mut memory = HashMap::new();
            encode_to_memory(&mut memory, header_pointer, header);
            encode_to_memory(&mut memory, swbfi_pointer, swbfi);
            let stack = [
                self.init_stack_for_isolated_run(),
                vec![header_pointer, swbfi_pointer],
            ]
            .concat();
            FunctionInitialState { stack, memory }
        }
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(GuesserSwbfiReveal).test();
    }

    fn assert_rejects(header: &BlockHeader, swbfi: &MmrAccumulator) {
        assert!(!guesser_reveal_is_valid(header, swbfi));
        test_assertion_failure(
            &ShadowedFunction::new(GuesserSwbfiReveal),
            GuesserSwbfiReveal.initial_state(header, swbfi).into(),
            &[BlockValidationRule::GuesserSwbfiReveal.error_id()],
        );
    }

    #[test]
    fn tampered_reveal_is_rejected_at_every_height() {
        let mut rng = StdRng::seed_from_u64(1);
        for height in 0..=63 {
            let leaf_count = leaf_count_of_height(&mut rng, height);
            let (header, swbfi) = revealing_header_and_swbfi(&mut rng, height, leaf_count);
            assert!(guesser_reveal_is_valid(&header, &swbfi));

            let levels = height.min(BlockPow::SWBFI_REVEAL_MAX_HEIGHT as u32);
            let (leaf, path) = header.pow.swbfi_reveal(levels as usize);
            let mut other_leaf = header;
            other_leaf.pow.set_swbfi_reveal(rng.random(), &path);
            assert_rejects(&other_leaf, &swbfi);

            if height > 0 {
                let mut other_sibling = header;
                let mut path = path.clone();
                let level = rng.random_range(0..path.len());
                path[level] = rng.random();
                other_sibling.pow.set_swbfi_reveal(leaf, &path);
                assert_rejects(&other_sibling, &swbfi);
            }

            let mut other_guesser = header;
            other_guesser.guesser_receiver_data = rng.random();
            let same_index = guesser_node_index(
                header.prev_block_digest,
                &header.guesser_receiver_data,
                leaf_count,
            ) == guesser_node_index(
                other_guesser.prev_block_digest,
                &other_guesser.guesser_receiver_data,
                leaf_count,
            );
            if !same_index {
                assert_rejects(&other_guesser, &swbfi);
            }
        }
    }

    /// A tree taller than the field holds is revealed from the node as far
    /// below the root as the field reaches; the leaf's path below that node
    /// is not in the field, so no reveal of it can be checked.
    #[test]
    fn tree_taller_than_the_field_is_revealed_from_a_node() {
        let mut rng = StdRng::seed_from_u64(2);
        let field = BlockPow::SWBFI_REVEAL_MAX_HEIGHT as u32;
        for height in [field + 1, 63] {
            let leaf_count = leaf_count_of_height(&mut rng, height);
            let (header, swbfi) = revealing_header_and_swbfi(&mut rng, height, leaf_count);
            let (_, levels) = guesser_node_index(
                header.prev_block_digest,
                &header.guesser_receiver_data,
                leaf_count,
            )
            .unwrap();
            assert_eq!(field, levels);
            assert!(guesser_reveal_is_valid(&header, &swbfi));
        }
    }

    /// The walk covers the tree's height, at most the field's 54 levels:
    /// the node and every path element up to the root are checked.
    #[test]
    fn every_path_element_is_checked_at_every_height() {
        let mut rng = StdRng::seed_from_u64(5);
        let tasm_heights = [0, 1, 31, 32, 53, 54, 55, 63];
        for height in 0..=63 {
            let leaf_count = leaf_count_of_height(&mut rng, height);
            let (header, swbfi) = revealing_header_and_swbfi(&mut rng, height, leaf_count);
            let levels = height.min(BlockPow::SWBFI_REVEAL_MAX_HEIGHT as u32) as usize;
            let (node, path) = header.pow.swbfi_reveal(levels);
            assert_eq!(levels, path.len());
            for level in 0..levels {
                let mut path = path.clone();
                path[level] = rng.random();
                let mut tampered = header;
                tampered.pow.set_swbfi_reveal(node, &path);
                assert!(
                    !guesser_reveal_is_valid(&tampered, &swbfi),
                    "height {height} level {level}"
                );
                if tasm_heights.contains(&height) {
                    assert_rejects(&tampered, &swbfi);
                }
            }
        }
    }

    /// The root in the node's place reveals nothing, whatever the path.
    #[test]
    fn revealing_the_root_alone_is_rejected() {
        let mut rng = StdRng::seed_from_u64(6);
        for height in [1, 2, 31, 32, 54, 55, 63] {
            let leaf_count = leaf_count_of_height(&mut rng, height);
            let (header, swbfi) = revealing_header_and_swbfi(&mut rng, height, leaf_count);
            let levels = height.min(BlockPow::SWBFI_REVEAL_MAX_HEIGHT as u32) as usize;
            let root = swbfi.peaks()[0];

            let (_, path) = header.pow.swbfi_reveal(levels);
            let mut with_the_path = header;
            with_the_path.pow.set_swbfi_reveal(root, &path);
            assert_rejects(&with_the_path, &swbfi);

            let mut with_itself = header;
            with_itself.pow.set_swbfi_reveal(root, &vec![root; levels]);
            assert_rejects(&with_itself, &swbfi);

            let mut with_random_words: BlockHeader = rng.random();
            with_random_words.prev_block_digest = header.prev_block_digest;
            with_random_words.guesser_receiver_data = header.guesser_receiver_data;
            with_random_words.pow.set_swbfi_reveal(root, &[]);
            assert_rejects(&with_random_words, &swbfi);
        }
    }

    #[test]
    fn empty_swbfi_needs_no_reveal() {
        let mut rng = StdRng::seed_from_u64(3);
        let header: BlockHeader = rng.random();
        assert!(guesser_reveal_is_valid(
            &header,
            &MmrAccumulator::init(vec![], 0)
        ));
    }

    #[test]
    fn sample_is_the_first_word_of_the_salted_parent_hash() {
        let mut rng = StdRng::seed_from_u64(4);
        let prev_block_digest: Digest = rng.random();
        let receiver_data: GuesserReceiverData = rng.random();
        let expected = Tip5::hash_pair(prev_block_digest, Tip5::hash(&receiver_data)).values()[0];
        for height in [0, 3, 40, 54] {
            let leaf_count = leaf_count_of_height(&mut rng, height);
            let (index, levels) =
                guesser_node_index(prev_block_digest, &receiver_data, leaf_count).unwrap();
            assert_eq!(height, levels);
            assert_eq!(expected.value() % (1 << height), index);
        }
        for height in [55, 63] {
            let leaf_count = leaf_count_of_height(&mut rng, height);
            let (index, levels) =
                guesser_node_index(prev_block_digest, &receiver_data, leaf_count).unwrap();
            assert_eq!(54, levels);
            assert_eq!((expected.value() >> (height - 54)) % (1 << 54), index);
        }
        assert!(guesser_node_index(prev_block_digest, &receiver_data, 0).is_none());
    }
}
