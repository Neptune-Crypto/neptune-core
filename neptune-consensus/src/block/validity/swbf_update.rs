//! The SWBF update claims: a block's removals proven piecewise and bound
//! by one root claim in its appendix.
//!
//! A [`leaf`] applies one segment of the block's inputs to the mutator
//! set the segment starts from, and an [`aggregation`] joins two
//! adjacent claims, leaves or aggregations, into one over both their
//! segments. Both have the same claim layout, defined by the leaf, so the
//! root alone says what the whole tree proved: from the mutator set the
//! block's transaction is built on, removing all its inputs yields the
//! mutator set the root outputs. The leaves are numbered from the first,
//! and an aggregation's children must be adjacent in that numbering, so
//! that no leaf, and no proof, serves twice.
//!
//! The aggregation reads each leaf proof's padded height and sums them up
//! the tree; `PredecessorIsValid` holds the sum at the root to the epoch's
//! floor, so that an empty block costs its composer as much proving work as
//! one with inputs. A leaf short of its height idles up to it.
//!
//! The snippets the leaf is built from live here as well.

mod absorb_blocks;
pub mod aggregation;
mod chunk_insertions;
pub(super) mod chunk_witness;
mod copy_words;
// The chunk form of proposal f), kept to measure a window slide; no program
// uses it.
#[cfg(test)]
mod counter_tree_leaf;
#[cfg(test)]
mod counter_tree_removals;
#[cfg(test)]
mod counter_tree_root;
mod divined_chunk_indices;
mod hash_blocks;
mod hash_chunk_with_insertions;
mod insert_into_window;
pub mod leaf;
mod mutate_swbfi_peaks;
mod mutator_set_hash_after_removals;
pub(in crate::block) mod removal_index_commitment;
mod removal_records_are_unspent;
// Kept for the benchmark in `update_tree_leaf`; no program uses it.
#[cfg(test)]
mod roots_from_authentication_struct;
mod sorted_window_indices;
pub(in crate::block) mod swbfi_peaks_after_removals;
mod update_tree_leaf;
pub(super) mod window_after_removals;
mod witness_lists;

use tasm_lib::triton_vm::prelude::*;

/// Where in an SWBF update claim's input each part lies; see
/// [`leaf::CorrectSwbfUpdate`] for what each part means.
pub(super) const INPUT_MUTATOR_SET_HASH: usize = 0;
pub(super) const INPUT_FIRST_LEAF_INDEX: usize = INPUT_MUTATOR_SET_HASH + Digest::LEN;
pub(super) const INPUT_LEN: usize = INPUT_FIRST_LEAF_INDEX + 1;

/// Where in an SWBF update claim's output each part lies; see
/// [`leaf::CorrectSwbfUpdate`] for what each part means.
pub(super) const OUTPUT_PADDED_ROWS: usize = 0;
pub(super) const OUTPUT_COUNT: usize = 1;
pub(super) const OUTPUT_MUTATOR_SET_HASH: usize = 2;
pub(super) const OUTPUT_LAST_LEAF_INDEX: usize = OUTPUT_MUTATOR_SET_HASH + Digest::LEN;
pub(super) const OUTPUT_NUM_PEAKS: usize = OUTPUT_LAST_LEAF_INDEX + 1;
pub(super) const OUTPUT_PEAKS: usize = OUTPUT_NUM_PEAKS + 1;

/// An SWBF update claim's output taken apart; the same for a leaf and an
/// aggregation. See [`leaf::CorrectSwbfUpdate`] for the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::block) struct ClaimOutput {
    /// The padded heights of the leaf proofs beneath the claim, summed. A
    /// leaf cannot attest its own proof's height and writes zero; see
    /// [`leaf::CorrectSwbfUpdate::ATTESTED_PADDED_ROWS`].
    pub(in crate::block) padded_rows: BFieldElement,

    /// The number of inputs removed, which the peaks below commit to.
    pub(in crate::block) count: usize,

    /// The hash of the mutator set after the removals.
    pub(in crate::block) mutator_set_hash: Digest,

    /// The index of the last leaf beneath the claim: a leaf's own, an
    /// aggregation's right child's.
    pub(in crate::block) last_leaf_index: BFieldElement,

    /// The peaks of the MMR over the inputs' index sets.
    pub(in crate::block) peaks: Vec<Digest>,
}

impl ClaimOutput {
    /// # Panics
    ///
    /// - If the output's length does not fit its number of peaks.
    /// - If output does not match the output format of the SWBF update tree
    pub(super) fn parse(output: &[BFieldElement]) -> Self {
        Self::try_parse(output).expect("output must have the SWBF update claim's layout")
    }

    /// The output taken apart, if it has the layout.
    pub(in crate::block) fn try_parse(output: &[BFieldElement]) -> Option<Self> {
        let num_peaks = usize::try_from(output.get(OUTPUT_NUM_PEAKS)?.value()).ok()?;
        let expected_len = Digest::LEN
            .checked_mul(num_peaks)
            .and_then(|num_words| num_words.checked_add(OUTPUT_PEAKS))?;
        if output.len() != expected_len {
            return None;
        }
        let count = u32::try_from(output[OUTPUT_COUNT].value()).ok()?;
        Some(Self {
            padded_rows: output[OUTPUT_PADDED_ROWS],
            count: usize::try_from(count).ok()?,
            mutator_set_hash: Digest::new(
                output[OUTPUT_MUTATOR_SET_HASH..OUTPUT_LAST_LEAF_INDEX]
                    .try_into()
                    .unwrap(),
            ),
            last_leaf_index: output[OUTPUT_LAST_LEAF_INDEX],
            peaks: output[OUTPUT_PEAKS..]
                .chunks(Digest::LEN)
                .map(|words| Digest::new(words.try_into().unwrap()))
                .collect(),
        })
    }

    pub(in crate::block) fn encode(&self) -> Vec<BFieldElement> {
        [
            // Measure of proof complexity in leaf-proofs below this node. 0 if
            // the program is the leaf program, the sum of the leaf program's
            // execution's padded height otherwise.
            vec![self.padded_rows],
            // Number of inputs removed by this program execution.
            vec![bfe!(self.count as u64)],
            // Mutator set hash after the application of the absolute indices
            // to the mutator set.
            self.mutator_set_hash.values().to_vec(),
            // The last leaf index verified in the leafs below this node. The
            // leaf index itself if the program is a leaf program.
            vec![self.last_leaf_index],
            // Number of peaks in the MMR of the absolute indices applied by
            // this execution.
            vec![bfe!(self.peaks.len() as u64)],
            // Those peaks.
            self.peaks.iter().flat_map(|peak| peak.values()).collect(),
        ]
        .concat()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn disallow_wrap_on_length_check() {
        let honest = ClaimOutput {
            padded_rows: bfe!(0),
            count: 3,
            mutator_set_hash: Digest::default(),
            last_leaf_index: bfe!(7),
            peaks: vec![],
        };
        assert_eq!(
            Some(honest.clone()),
            ClaimOutput::try_parse(&honest.encode())
        );

        // 5 * num_peaks == 1 mod 2^64, so a one-word tail passes an
        // unchecked length check.
        let mut output = honest.encode();
        output[OUTPUT_NUM_PEAKS] = bfe!(0xCCCC_CCCC_CCCC_CCCD_u64);
        output.push(bfe!(0));
        assert_eq!(None, ClaimOutput::try_parse(&output));
    }
}
