//! The packed list's chunk dictionaries as the leaf's witness is built
//! from them on the host machine: the chunks, the trees' heights and the
//! trees' digest lists they hold, in the list's order.

use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
use neptune_mutator_set::removal_record::RemovalRecord;
use tasm_lib::triton_vm::prelude::*;

/// Reads the chunks and the trees' digest lists out of a packed list of
/// removal records, the way [`RemovalRecordList::try_unpack`] reads it,
/// without unpacking the records.
///
/// The list stores its chunks and one digest list per tree of the inactive
/// SWBF in the chunk dictionaries of its records, as entries of a tree
/// height and a pair of a digest list and a chunk. A height below the
/// offset means both are used; a height offset by
/// [`RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET`] means only the digest
/// list; the delimiter [`RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT`]
/// means only the chunk. The chunks come in ascending chunk index, the
/// trees in ascending height.
#[derive(Debug, Copy, Clone)]
pub(in crate::block::validity) struct ChunkWitness;

impl ChunkWitness {
    /// The tree heights and chunks the packed list's dictionaries hold, in
    /// order: the height of each tree entry, and whether each entry carries
    /// a chunk. Entries with a height that does not classify are skipped;
    /// the snippet rejects them.
    fn entries(removal_records: &[RemovalRecord]) -> Vec<(Option<u64>, bool)> {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        removal_records
            .iter()
            .flat_map(|record| record.target_chunks.iter())
            .filter_map(|(tree_height, _)| {
                if *tree_height < 2 * offset {
                    Some((Some(tree_height % offset), *tree_height < offset))
                } else if *tree_height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT {
                    Some((None, true))
                } else {
                    None
                }
            })
            .collect()
    }

    /// The heights of the trees the packed list holds digest lists for,
    /// in order.
    pub(in crate::block::validity) fn tree_heights(removal_records: &[RemovalRecord]) -> Vec<u32> {
        Self::entries(removal_records)
            .into_iter()
            .filter_map(|(height, _)| height)
            .map(|height| u32::try_from(height).expect("tree heights are small"))
            .collect()
    }

    /// A packed list with its chunks' contents unpacked, the form a witness
    /// is built from.
    pub(in crate::block::validity) fn with_unpacked_chunks(
        mut removal_records: Vec<RemovalRecord>,
        allow_big_chunks: bool,
    ) -> Vec<RemovalRecord> {
        for record in &mut removal_records {
            for (_, (_, chunk)) in record.target_chunks.iter_mut() {
                *chunk = chunk
                    .try_unpack(allow_big_chunks)
                    .expect("packed chunk must unpack");
            }
        }
        removal_records
    }

    /// The digest lists of the tree entries, in their order, which is
    /// ascending tree height: the trees' path lists in the witness's form,
    /// their authentication structures in the packed list's form.
    pub(crate) fn tree_paths(removal_records: &[RemovalRecord]) -> Vec<Vec<Digest>> {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        removal_records
            .iter()
            .flat_map(|record| record.target_chunks.iter())
            .filter(|(tree_height, _)| *tree_height < 2 * offset)
            .map(|(_, (membership_proof, _))| membership_proof.authentication_path.clone())
            .collect()
    }

    /// The chunks the packed list carries, in its order.
    pub(crate) fn chunks(removal_records: &[RemovalRecord]) -> Vec<Vec<u32>> {
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        removal_records
            .iter()
            .flat_map(|record| record.target_chunks.iter())
            .filter(|(tree_height, _)| {
                *tree_height < offset
                    || *tree_height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT
            })
            .map(|(_, (_, chunk))| chunk.relative_indices.clone())
            .collect()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(in crate::block::validity) mod tests {
    use neptune_mutator_set::msa_and_records::MsaAndRecords;
    use proptest::arbitrary::Arbitrary;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use rand::rngs::StdRng;
    use rand::RngExt;

    use super::*;

    /// A mutator set accumulator with this many removable items among this
    /// many AOCL leafs, and the records that remove them.
    pub(in crate::block::validity) fn random_msa_and_records(
        rng: &mut StdRng,
        num_records: usize,
        aocl_size: u64,
    ) -> MsaAndRecords {
        let removables = (0..num_records)
            .map(|_| (rng.random(), rng.random(), rng.random()))
            .collect::<Vec<(Digest, Digest, Digest)>>();
        let mut runner = TestRunner::deterministic();
        MsaAndRecords::arbitrary_with((removables, aocl_size))
            .new_tree(&mut runner)
            .unwrap()
            .current()
    }
}
