use std::collections::HashMap;
use std::collections::HashSet;

use ::twenty_first::prelude::MerkleTree;
use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_peak_heights;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use thiserror::Error;
use twenty_first::util_types::merkle_tree::MerkleTreeHeight;
use twenty_first::util_types::merkle_tree::MerkleTreeNodeIndex;

use super::chunk::Chunk;
use super::chunk::ChunkUnpackError;
use super::chunk_dictionary::ChunkDictionary;
use super::dense_absolute_index_set::AbsoluteIndexSetUnpackError;
use super::dense_absolute_index_set::DenseAbsoluteIndexSet;
use super::AbsoluteIndexSet;
use super::RemovalRecord;
use crate::util_types::mutator_set::shared::BATCH_SIZE;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;

/// A list of [`RemovalRecords`]s without redundant Merkle authentication data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemovalRecordList {
    index_sets: Vec<AbsoluteIndexSet>,
    authentication_structures: Vec<Vec<Digest>>,

    /// ascending order by chunk index
    chunks: Vec<Chunk>,

    num_leafs_aocl: u64,
}

#[derive(Debug, Error)]
pub(super) enum RemovalRecordListUnpackError {
    #[error("inner decoding error: {0}")]
    InnerDecodingFailure(#[from] Box<dyn core::error::Error + Send + Sync>),
    #[error("Absolute index value cannot exceed 74 bits")]
    AbsoluteIndexTooBig,
}

impl RemovalRecordList {
    /// Convert a `Vec` of [`RemovalRecord`]s to a [`RemovalRecordList`].
    ///
    /// The difference between this method and [`Self::convert_from_vec`] is the
    /// second argument, the number of leafs in the AOCL. The `From`
    /// implementation calls this one after estimating this argument. Producing
    /// this estimate is time-consuming and error-prone (tests notwithstanding),
    /// so it is better to avoid that step if possible.
    pub(crate) fn from_removal_records(
        removal_records: Vec<RemovalRecord>,
        num_leafs_aocl: u64,
    ) -> Self {
        let num_leafs_swbfi = num_leafs_aocl / u64::from(BATCH_SIZE);
        let all_tree_heights = get_peak_heights(num_leafs_swbfi);
        let index_sets = removal_records
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect_vec();

        // compute (good enough approximation of) MMR num leafs
        let mut mmr_leaf_indices = HashSet::<(u32, u64)>::new();
        let mut chunks = HashMap::<u64, Chunk>::new();
        for removal_record in &removal_records {
            for target_chunk in removal_record.target_chunks.iter() {
                let (chunk_index, (chunk_mmr_mp, chunk)) = target_chunk;
                if let Some(chunk_already_present) = chunks.insert(*chunk_index, chunk.clone()) {
                    assert_eq!(chunk_already_present, chunk.clone());
                }
                let tree_height = chunk_mmr_mp.authentication_path.len() as u32;
                mmr_leaf_indices.insert((tree_height, *chunk_index));
            }
        }

        // compile sparse view of MMR
        let mut sparse_mmr = HashMap::<(MerkleTreeHeight, MerkleTreeNodeIndex), Digest>::new();
        for removal_record in removal_records {
            for target_chunk in removal_record.target_chunks {
                let (chunk_index, (chunk_mmr_mp, chunk)) = target_chunk;
                let tree_height = chunk_mmr_mp.authentication_path.len() as u32;

                assert!(all_tree_heights.contains(&tree_height));

                let mut running_digest = Tip5::hash(&chunk);
                let (mut merkle_node_index, _) =
                    leaf_index_to_mt_index_and_peak_index(chunk_index, num_leafs_swbfi);
                sparse_mmr.insert((tree_height, merkle_node_index), running_digest);

                for sibling_digest in chunk_mmr_mp.authentication_path {
                    sparse_mmr.insert((tree_height, merkle_node_index ^ 1), sibling_digest);

                    if merkle_node_index & 1 == 0 {
                        running_digest = Tip5::hash_pair(running_digest, sibling_digest);
                    } else {
                        running_digest = Tip5::hash_pair(sibling_digest, running_digest);
                    }
                    merkle_node_index >>= 1;
                }
                sparse_mmr.insert((tree_height, merkle_node_index), running_digest);
            }
        }

        // extract authentication structures
        let mut authentication_structures = vec![];
        for tree_height in all_tree_heights.into_iter().sorted() {
            let mmr_leaf_indices_for_this_tree = mmr_leaf_indices
                .iter()
                .filter(|(height, _index)| *height == tree_height)
                .map(|(_height, index)| *index)
                .collect_vec();
            let merkle_leaf_indices_for_this_tree = mmr_leaf_indices_for_this_tree
                .iter()
                .map(|&li| {
                    let (merkle_node_index, _peak_index) =
                        leaf_index_to_mt_index_and_peak_index(li, num_leafs_swbfi);
                    merkle_node_index ^ (1 << tree_height)
                })
                .collect_vec();
            let node_indices_in_authentication_structure =
                MerkleTree::authentication_structure_node_indices(
                    1_u64 << tree_height,
                    &merkle_leaf_indices_for_this_tree,
                )
                .expect("tree height is guaranteed to be larger than log of biggest index")
                .collect_vec();

            let mut authentication_structure = vec![];
            for node_index in node_indices_in_authentication_structure {
                let digest = *sparse_mmr.get(&(tree_height, node_index)).unwrap();
                authentication_structure.push(digest);
            }
            authentication_structures.push(authentication_structure);
        }

        // coalesce all chunks, in order
        let chunks = chunks
            .into_iter()
            .sorted_by_key(|(chunk_index, _chunk)| *chunk_index)
            .coalesce(|previous, current| {
                if previous.0 == current.0 {
                    assert_eq!(previous.1.clone(), current.1.clone());
                    Ok(previous)
                } else {
                    Err((previous, current))
                }
            })
            .map(|(_index, chunk)| chunk)
            .collect_vec();

        Self {
            index_sets,
            authentication_structures,
            chunks,
            num_leafs_aocl,
        }
    }

    /// Compute a minimum viable lower bound on the number of leafs in the AOCL
    /// given context inferred from removal records.
    ///
    /// The lower bound is *viable*: it suffices to "explain" why the given
    /// chunks are present and why the authentiation paths have the lengths they
    /// do.
    ///
    /// The lower bound is *minimal*: no smaller number satisfies the above
    /// criteria.
    ///
    /// # Panics
    ///
    ///  - If the observed authentication path lengths is not sorted in
    ///    descending order (*i.e.*, largest first).
    ///  - If the observed authentication path lengths contains duplicates.
    fn estimate_num_leafs_aocl(
        observed_chunk_indices: &[u64],
        observed_authentication_path_lengths: &[usize],
    ) -> u64 {
        let largest_observed_chunk_index =
            observed_chunk_indices.iter().copied().max().unwrap_or(0);
        let mut aocl_len = largest_observed_chunk_index * u64::from(BATCH_SIZE);

        assert!(
            observed_authentication_path_lengths
                .iter()
                .rev()
                .is_sorted(),
            "observed authentication path lengths were not sorted: {}",
            observed_authentication_path_lengths.iter().join(", ")
        );
        assert_eq!(
            observed_authentication_path_lengths.iter().dedup().count(),
            observed_authentication_path_lengths.len()
        );
        for tree_height in observed_authentication_path_lengths {
            let effective_tree_height = (1u64 << tree_height) * u64::from(BATCH_SIZE);
            if aocl_len & effective_tree_height == 0 {
                // set the bit in question
                aocl_len |= effective_tree_height;

                // zero all subsequent bits
                aocl_len &= u64::MAX - (effective_tree_height - 1);
            }
        }

        aocl_len
    }

    fn compressed_chunk_dictionary(&self) -> ChunkDictionary {
        let window_start =
            u128::from(self.num_leafs_aocl) / u128::from(BATCH_SIZE) * u128::from(CHUNK_SIZE);
        let chunk_indices = self
            .index_sets
            .iter()
            .flat_map(|ais| ais.to_vec())
            .filter(|absolute_index| *absolute_index < window_start)
            .map(|absolute_index| absolute_index / u128::from(CHUNK_SIZE))
            .map(u64::try_from)
            .map(std::result::Result::unwrap)
            .sorted()
            .dedup()
            .collect_vec();

        let tree_heights = get_peak_heights(self.num_leafs_aocl / u64::from(BATCH_SIZE))
            .into_iter()
            .map(u64::from)
            .rev()
            .collect_vec();

        assert_eq!(chunk_indices.len(), self.chunks.len());

        let authentication_structures = self
            .authentication_structures
            .iter()
            .cloned()
            .chain(std::iter::repeat(vec![]));
        let chunk_dictionary = tree_heights
            .iter()
            .copied()
            .chain(std::iter::repeat(0))
            .zip(
                authentication_structures
                    .map(|ap| MmrMembershipProof {
                        authentication_path: ap,
                    })
                    .zip(self.chunks.iter().map(Chunk::pack)),
            )
            .collect_vec();
        ChunkDictionary {
            dictionary: chunk_dictionary,
        }
    }

    /// Encodes a [`RemovalRecordList`] as a `Vec` of [`RemovalRecord`].
    ///
    /// For use in combination with [`BFieldCodec`].
    ///
    /// The encoding follows the following rules:
    ///  - The absolute index sets are identical. (See the comment on
    ///    [`DenseAbsoluteIndexSet`] for an explanation why there is no packing
    ///    of absolute index sets.)
    ///  - The first removal record is the only one that contains a non-empty
    ///    chunks dictionary. This dictionary contains tuples of the form
    ///    ```notest
    ///     (
    ///         tree_height: u64,
    ///         (
    ///             authentication_structure: Vec<Digest>,
    ///             chunk: Chunk
    ///         )
    ///     )
    ///     ```
    ///     .
    ///  - All chunks of the `RemovalRecordList` are present exactly once, in
    ///    the same order in this dictionary.
    ///  - The authentication structures in this dictionary are the same as
    ///    those from the like-named field of `RemovalRecordList`. The number of
    ///    authentication structures is guaranteed to be less than or equal to
    ///    the number of chunks. When all authentication structures are used,
    ///    the empty vector is used for padding. The authentication structures
    ///    do not correlate with the chunks.
    ///  - The tree heights *do* correlate with the authentication structures:
    ///    they indicate the height of the tree that the authentication
    ///    structure is for. When all tree heights have been used, 0 is used for
    ///    padding.
    fn encode_as_vec(&self) -> Vec<RemovalRecord> {
        let chunk_dictionaries = vec![self.compressed_chunk_dictionary()]
            .into_iter()
            .chain(std::iter::repeat(ChunkDictionary::empty()));

        self.index_sets
            .iter()
            .copied()
            .zip(chunk_dictionaries)
            .map(|(absolute_indices, target_chunks)| RemovalRecord {
                absolute_indices,
                target_chunks,
            })
            .collect_vec()
    }

    /// Inverse of [`Self::encode_as_vec`].
    fn decode_from_vec(
        removal_records: Vec<RemovalRecord>,
    ) -> Result<RemovalRecordList, RemovalRecordListUnpackError> {
        let mut index_sets = vec![];
        let mut authentication_structures = vec![];
        let mut chunks = vec![];

        let mut tree_heights = vec![];
        for removal_record in removal_records {
            index_sets.push(removal_record.absolute_indices);
            for (tree_height, (mmr_authentication_path, chunk)) in
                removal_record.target_chunks.iter()
            {
                authentication_structures.push(mmr_authentication_path.authentication_path.clone());
                let unpacked_chunk =
                    chunk
                        .try_unpack()
                        .map_err(Box::new)
                        .map_err(|e: Box<ChunkUnpackError>| {
                            RemovalRecordListUnpackError::InnerDecodingFailure(e)
                        })?;
                chunks.push(unpacked_chunk);

                if *tree_height != 0 {
                    tree_heights.push(*tree_height);
                }
            }
        }

        authentication_structures = authentication_structures[0..tree_heights.len()].to_vec();

        let observed_chunk_indices =
            Self::observed_chunk_indices_from_index_sets(&index_sets, chunks.len())?;

        let num_leafs_aocl = Self::estimate_num_leafs_aocl(
            &observed_chunk_indices,
            &tree_heights.iter().map(|u| *u as usize).rev().collect_vec(),
        );

        Ok(Self {
            index_sets,
            authentication_structures,
            chunks,
            num_leafs_aocl,
        })
    }

    fn observed_chunk_indices_from_index_sets(
        index_sets: &[AbsoluteIndexSet],
        number: usize,
    ) -> Result<Vec<u64>, RemovalRecordListUnpackError> {
        let mut chunk_indices: Vec<u64> = vec![];

        for index_set in index_sets {
            for abs_index in index_set.to_array() {
                let chunk_index = abs_index / u128::from(CHUNK_SIZE);
                let Ok(chunk_index) = u64::try_from(chunk_index) else {
                    return Err(RemovalRecordListUnpackError::AbsoluteIndexTooBig);
                };

                chunk_indices.push(chunk_index);
            }
        }

        chunk_indices.sort_unstable();
        chunk_indices.dedup();
        Ok(chunk_indices.into_iter().take(number).collect_vec())
    }

    /// Compress a [`Vec`] of [`RemovalRecord`]s densely by packing the same
    /// information into another, *smaller*, [`Vec`] of [`RemovalRecord`]s.
    pub(super) fn pack(removal_records: Vec<RemovalRecord>) -> Vec<RemovalRecord> {
        Self::convert_from_vec(removal_records).encode_as_vec()
    }

    /// Decompress a [`Vec`] of [`RemovalRecord`]s as packed by [`Self::pack`].
    /// Returns an error if the packing is invalid.
    pub(super) fn try_unpack(
        removal_records: Vec<RemovalRecord>,
    ) -> Result<Vec<RemovalRecord>, RemovalRecordListUnpackError> {
        let as_removal_record_list = RemovalRecordList::decode_from_vec(removal_records)?;
        Ok(as_removal_record_list.convert_to_vec())
    }

    /// Convert a [`Vec`] of [`RemovalRecord`]s into a [`RemovalRecordList`],
    /// which is a denser representation of the same object. In particular,
    /// there is no loss of information (unless the input is malicious, but that
    /// is assumed not to be the case).
    fn convert_from_vec(removal_records: Vec<RemovalRecord>) -> Self {
        let observed_chunk_indices = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.indices_and_leafs())
            .map(|(idx, _leaf)| idx)
            .sorted()
            .dedup()
            .collect_vec();
        let authentication_path_lengths = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.authentication_paths())
            .map(|ap| ap.authentication_path.len())
            .sorted()
            .rev()
            .dedup()
            .collect_vec();
        let num_leafs_aocl = RemovalRecordList::estimate_num_leafs_aocl(
            &observed_chunk_indices,
            &authentication_path_lengths,
        );

        RemovalRecordList::from_removal_records(removal_records, num_leafs_aocl)
    }

    /// Inverse of [`Self::convert_from_vec`].
    fn convert_to_vec(self) -> Vec<RemovalRecord> {
        {
            let num_leafs_swbfi = self.num_leafs_aocl / u64::from(BATCH_SIZE);
            let all_tree_heights = get_peak_heights(num_leafs_swbfi);
            assert_eq!(
                all_tree_heights.len(),
                self.authentication_structures.len(),
                "expected one (possibly empty) authentication structure for each \
                tree in the MMR but got {} authentication structures and {} trees",
                self.authentication_structures.len(),
                all_tree_heights.len()
            );

            // populate sparse MMR with chunk hashes
            let mut sparse_mmr = HashMap::<(MerkleTreeHeight, MerkleTreeNodeIndex), Digest>::new();
            let active_window_start = u128::from(num_leafs_swbfi) * u128::from(CHUNK_SIZE);
            let all_inactive_indices = self
                .index_sets
                .iter()
                .flat_map(|absolute_index_set| absolute_index_set.to_vec())
                .filter(|&absolute_index| absolute_index < active_window_start);
            let all_chunk_indices = all_inactive_indices
                .map(|absolute_index| {
                    u64::try_from(absolute_index / u128::from(CHUNK_SIZE))
                        .expect("absolute indices can never be more than 76 bits")
                })
                .sorted()
                .dedup()
                .take(self.chunks.len())
                .collect_vec();
            let master_chunks_dictionary = all_chunk_indices
                .iter()
                .copied()
                .zip(self.chunks.iter().cloned())
                .collect::<HashMap<_, _>>();
            for (&chunk_index, chunk) in all_chunk_indices.iter().zip(self.chunks.iter()) {
                let chunk_hash = Tip5::hash(chunk);
                let (merkle_tree_node_index, peak_index) =
                    leaf_index_to_mt_index_and_peak_index(chunk_index, num_leafs_swbfi);
                let height = all_tree_heights[peak_index as usize];
                sparse_mmr.insert((height, merkle_tree_node_index), chunk_hash);
            }

            // populate sparse MMR with authentication structures
            for (tree_height, authentication_structure) in all_tree_heights
                .iter()
                .sorted()
                .zip_eq(&self.authentication_structures)
            {
                let leaf_indices_for_this_tree = sparse_mmr
                    .keys()
                    .filter(|(height, _node_index)| *height == *tree_height)
                    .map(|(_height, node_index)| *node_index ^ (1 << *tree_height))
                    .collect_vec();

                let node_indices_for_authentication_structure =
                    MerkleTree::authentication_structure_node_indices(
                        1 << *tree_height,
                        &leaf_indices_for_this_tree,
                    )
                    .expect(
                        "all leaf indices are guaranteed to be smaller (in log terms) than tree height",
                    )
                    .collect_vec();
                assert_eq!(
                    authentication_structure.len(),
                    node_indices_for_authentication_structure.len(),
                    "Have authentication structure of len {} but node indices of len {}",
                    authentication_structure.len(),
                    node_indices_for_authentication_structure.len()
                );
                for (node_index, node_hash) in node_indices_for_authentication_structure
                    .into_iter()
                    .zip_eq(authentication_structure.iter())
                {
                    sparse_mmr.insert((*tree_height, node_index), *node_hash);
                }
            }

            assert!(sparse_mmr
                .values()
                .all(|v| v.to_hex().chars().take(8).collect::<String>() != "be450642"));

            // populate sparse MMR by completing families with parents whenever both
            // children are already present
            for &tree_height in &all_tree_heights {
                loop {
                    let current_tree_indices = sparse_mmr
                        .keys()
                        .filter(|(height, _node_index)| *height == tree_height)
                        .map(|(_height, node_index)| *node_index)
                        .sorted()
                        .collect_vec();
                    let absent_parent_nodes = current_tree_indices
                        .iter()
                        .tuple_windows()
                        .filter(|(nil, nir)| **nil == **nir ^ 1)
                        .map(|(nil, _nir)| *nil >> 1)
                        .filter(|ni| !current_tree_indices.contains(ni))
                        .collect_vec();
                    if absent_parent_nodes.is_empty() {
                        break;
                    }
                    for parent in absent_parent_nodes {
                        let left_child = parent << 1;
                        let right_child = left_child ^ 1;
                        let left_digest = *sparse_mmr
                            .get(&(tree_height, left_child))
                            .expect("presence of left child was verified already");
                        let right_digest = *sparse_mmr
                            .get(&(tree_height, right_child))
                            .expect("presence of right child was verified already");
                        let parent_digest = Tip5::hash_pair(left_digest, right_digest);
                        sparse_mmr.insert((tree_height, parent), parent_digest);
                    }
                }
            }

            // Create removal records one by one
            let mut removal_records = vec![];
            for index_set in &self.index_sets {
                let chunk_indices = index_set
                    .to_vec()
                    .into_iter()
                    .map(|absolute_index| absolute_index / u128::from(CHUNK_SIZE))
                    .map(|u| {
                        u64::try_from(u).expect("absolute index can never be more than 72 bits")
                    })
                    .sorted()
                    .dedup()
                    .collect_vec();
                let mut target_chunks = vec![];
                for chunk_index in chunk_indices {
                    let chunk = master_chunks_dictionary.get(&chunk_index).expect("master chunks dictionary should contain entries for all possible chunk indices");
                    let (mut merkle_node_index, peak_index) =
                        leaf_index_to_mt_index_and_peak_index(chunk_index, num_leafs_swbfi);
                    let tree_height = all_tree_heights[peak_index as usize];
                    let mut authentication_path = vec![];
                    while merkle_node_index != 1 {
                        let digest = sparse_mmr
                            .get(&(tree_height, merkle_node_index ^ 1))
                            .copied()
                            .unwrap_or_else(|| {
                                panic!(
                                    "node with node index {} on authentication \
                                    path for tree of height {} must live in sparse \
                                    mmr dictionary, but that dicitonary only has \
                                    nodes with indices {} for that height",
                                    merkle_node_index ^ 1,
                                    tree_height,
                                    sparse_mmr
                                        .iter()
                                        .filter(|((height, _node_index), _)| *height == tree_height)
                                        .map(|((_height, node_index), _)| *node_index)
                                        .sorted()
                                        .join(", ")
                                );
                            });
                        authentication_path.push(digest);
                        merkle_node_index >>= 1;
                    }
                    target_chunks.push((
                        chunk_index,
                        (
                            MmrMembershipProof {
                                authentication_path,
                            },
                            chunk.clone(),
                        ),
                    ));
                }
                removal_records.push(RemovalRecord {
                    absolute_indices: *index_set,
                    target_chunks: ChunkDictionary::new(target_chunks),
                });
            }

            removal_records
        }
    }
}

impl BFieldCodec for RemovalRecordList {
    type Error = BFieldCodecError;

    fn decode(sequence: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        Ok(Box::new(
            Self::decode_from_vec(*Vec::<RemovalRecord>::decode(sequence)?)
                .map_err(Box::new)
                .map_err(|e: Box<RemovalRecordListUnpackError>| {
                    BFieldCodecError::InnerDecodingFailure(e)
                })?,
        ))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        self.encode_as_vec().encode()
    }

    fn static_length() -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {

    use proptest::collection::vec;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::prop_assert_ne;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::Config;
    use proptest::test_runner::RngAlgorithm;
    use proptest::test_runner::TestRng;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use rand::rng;
    use rand::Rng;
    use test_strategy::proptest;

    use super::RemovalRecordList;
    use super::*;
    use crate::util_types::mutator_set::shared::WINDOW_SIZE;
    use crate::util_types::mutator_set::NUM_TRIALS;

    impl RemovalRecord {
        fn arbitrary_synchronized_set(
            num_leafs_aocl: u64,
            num_records: usize,
        ) -> BoxedStrategy<Vec<RemovalRecord>> {
            const ROOT_INDEX: u64 = 1_u64;

            let num_leafs_swbfi = num_leafs_aocl / u64::from(BATCH_SIZE);
            let mmr_heights = get_peak_heights(num_leafs_swbfi);
            let mmr_max_height = mmr_heights
                .iter()
                .copied()
                .max()
                .map(i64::from)
                .unwrap_or(-1_i64);
            let active_window_start = u128::from(num_leafs_swbfi) * u128::from(CHUNK_SIZE);
            (
                vec(0..num_leafs_aocl, num_records),
                vec(vec(0u32..WINDOW_SIZE, NUM_TRIALS as usize), num_records),
            )
                .prop_flat_map(move |(aocl_indices, relative_index_sets)| {
                    let absolute_index_sets = aocl_indices
                        .into_iter()
                        .map(|aocl_index| {
                            u128::from(aocl_index) / u128::from(BATCH_SIZE) * u128::from(CHUNK_SIZE)
                        })
                        .zip(relative_index_sets)
                        .map(|(window_start, relative_index_set)| {
                            AbsoluteIndexSet::new(
                                &relative_index_set
                                    .into_iter()
                                    .map(|ri| window_start + u128::from(ri))
                                    .collect_vec()
                                    .try_into()
                                    .unwrap(),
                            )
                        })
                        .collect_vec();

                    let all_absolute_indices =
                        absolute_index_sets.iter().flat_map(|ais| ais.to_vec());
                    let all_chunk_indices = all_absolute_indices
                        .filter(|ai| *ai < active_window_start)
                        .map(|ai| ai / u128::from(CHUNK_SIZE))
                        .map(u64::try_from)
                        .map(Result::<_, _>::unwrap)
                        .sorted()
                        .dedup()
                        .collect_vec();

                    let mmr_heights = mmr_heights.clone(); // avoid move/ownership issue
                    (
                        vec(vec(0..CHUNK_SIZE, 0..51), all_chunk_indices.len()),
                        vec(
                            arb::<Digest>(),
                            usize::try_from(mmr_max_height+1).unwrap_or(usize::MAX)
                                * all_chunk_indices.len(),
                        ),
                    )
                        .prop_map(move |(indices_for_chunks, mut digests)| {
                            // compile list of chunks with chunk indices
                            let indexed_chunks = indices_for_chunks
                                .iter()
                                .zip(&all_chunk_indices)
                                .map(|(indices_within_chunk, index_of_chunk)| {
                                    (
                                        *index_of_chunk,
                                        Chunk {
                                            relative_indices: indices_within_chunk.clone(),
                                        },
                                    )
                                })
                                .collect_vec();

                            // populate sparse mmr with enough digests,
                            // overwriting if necessary
                            let mut sparse_mmr = HashMap::new();
                            for (chunk_index, chunk) in &indexed_chunks {
                                let (merkle_tree_node_index, peak_index) =
                                    leaf_index_to_mt_index_and_peak_index(
                                        *chunk_index,
                                        num_leafs_swbfi,
                                    );
                                let tree_height = mmr_heights[peak_index as usize];
                                sparse_mmr.insert(
                                    (tree_height, merkle_tree_node_index),
                                    Tip5::hash(chunk),
                                );

                                sparse_mmr.entry((tree_height, merkle_tree_node_index ^ 1)).or_insert_with(|| digests.pop().unwrap());
                            }

                            // complete paths to roots
                            for &tree_height in &mmr_heights {
                                loop {
                                    let current_tree_all_node_indices = sparse_mmr
                                        .keys()
                                        .filter(|(height, _node_index)| tree_height == *height)
                                        .map(|(_height, node_index)| *node_index)
                                        .collect_vec();
                                    let single_childs = current_tree_all_node_indices
                                        .iter()
                                        .copied()
                                        .filter(|idx| !current_tree_all_node_indices.contains(&((*idx)^1)))
                                        .collect_vec();

                                    let mut absent_parents = current_tree_all_node_indices
                                        .iter()
                                        .copied()
                                        .sorted()
                                        .tuple_windows()
                                        .filter(|(nil, nir)| *nil ^ 1 == *nir)
                                        .map(|(nil, _)| nil >> 1)
                                        .filter(|ni| !current_tree_all_node_indices.contains(ni))
                                        .collect_vec();

                                    for single_child in single_childs {
                                        if single_child == ROOT_INDEX {
                                            continue;
                                        }
                                        let sibling = digests.pop().unwrap();
                                        sparse_mmr.insert((tree_height, single_child^1), sibling);
                                        absent_parents.push(single_child >> 1);

                                    }


                                    if absent_parents.is_empty() {
                                        break;
                                    }

                                    for parent in absent_parents {
                                        let left_digest = *sparse_mmr.get(&(tree_height, (parent << 1))).unwrap();
                                        let right_digest = *sparse_mmr.get(&(tree_height, (parent << 1) ^ 1)).unwrap();
                                        let parent_digest = Tip5::hash_pair(left_digest, right_digest);
                                        sparse_mmr.insert((tree_height, parent), parent_digest);
                                    }
                                }
                            }

                            // decorate chunks with authentication paths
                            let master_chunk_dictionary = indexed_chunks
                                .into_iter()
                                .map(|(chunk_index, chunk)| {
                                    let (mut merkle_tree_node_index, peak_index) =
                                        leaf_index_to_mt_index_and_peak_index(
                                            chunk_index,
                                            num_leafs_swbfi,
                                        );
                                    let tree_height = mmr_heights[peak_index as usize];
                                    let mut authentication_path = vec![];
                                    while merkle_tree_node_index != ROOT_INDEX {
                                        authentication_path.push(
                                            *sparse_mmr
                                                .get(&(tree_height, merkle_tree_node_index ^ 1))
                                                .unwrap_or_else(||panic!("sparse mmr must have digest at ({tree_height}/{})", merkle_tree_node_index ^ 1)),
                                        );
                                        merkle_tree_node_index >>= 1;
                                    }
                                    (chunk_index, (MmrMembershipProof::new(authentication_path), chunk))
                                })
                                .collect::<HashMap<_, _>>();

                            absolute_index_sets
                                .clone()
                                .into_iter()
                                .map(|ais| {
                                    (
                                        ais,
                                        ais.to_vec()
                                            .into_iter()
                                            .filter(|&absolute_index| {
                                                absolute_index < active_window_start
                                            })
                                            .map(|absolute_index| {
                                                u64::try_from(absolute_index / u128::from(CHUNK_SIZE)).expect("absolute indices can never be more than 76 bits")
                                            })
                                            .sorted()
                                            .dedup()
                                            .collect_vec(),
                                    )
                                }).map(|(ais, chunk_indices)| {
                                    (
                                        ais,
                                        chunk_indices
                                            .into_iter()
                                            .map(
                                                |chunk_index|
                                                    (
                                                        chunk_index,
                                                        master_chunk_dictionary.get(&chunk_index).unwrap().clone()
                                                    )
                                            )
                                            .collect_vec()
                                    )
                                })
                                .map(|(ais, chunk_dictionary)| RemovalRecord {
                                    absolute_indices: ais,
                                    target_chunks: ChunkDictionary::new(chunk_dictionary),
                                })
                                .collect_vec()
                        })
                })
                .boxed()
        }

        /// Test if the removal records are consistent.
        ///
        /// 1. The authentication paths end in the same root -- even across
        ///    different removal records.
        /// 2. If the same chunk is referenced by different removal records,
        ///    those chunks agree.
        fn are_mutually_consistent(batch: &[Self], num_leafs_aocl: u64) -> bool {
            let mut sparse_mmr = HashMap::<(usize, u64), Digest>::new();
            let mut chunks = HashMap::<u64, Chunk>::new();
            batch
                .iter()
                .all(|rr| rr.is_consistent_helper(num_leafs_aocl, &mut sparse_mmr, &mut chunks))
        }

        /// Test if the authentication paths are consistent: that they end in
        /// the same root.
        fn is_consistent(&self, num_leafs_aocl: u64) -> bool {
            let mut sparse_mmr = HashMap::<(usize, u64), Digest>::new();
            let mut empty = HashMap::<u64, Chunk>::new();
            self.is_consistent_helper(num_leafs_aocl, &mut sparse_mmr, &mut empty)
        }

        fn is_consistent_helper(
            &self,
            num_leafs_aocl: u64,
            sparse_mmr: &mut HashMap<(usize, u64), Digest>,
            chunks: &mut HashMap<u64, Chunk>,
        ) -> bool {
            let num_leafs_swbfi = num_leafs_aocl / u64::from(BATCH_SIZE);

            let mut consistent_mmr = true;
            let mut insert_new_digest_or_test_equality =
                |dict: &mut HashMap<_, _>, h: usize, ni: u64, d: Digest| {
                    if let Some(old) = dict.insert((h, ni), d) {
                        if old != d {
                            consistent_mmr = false;
                        }
                    }
                };
            let mut consistent_chunks = true;
            let mut insert_new_chunk_or_test_equality =
                |dict: &mut HashMap<_, _>, chunk_index: u64, chunk: Chunk| {
                    if let Some(old) = dict.insert(chunk_index, chunk.clone()) {
                        if old != chunk {
                            consistent_chunks = false;
                        }
                    }
                };
            for (chunk_index, (mmr_membership_proof, chunk)) in self.target_chunks.iter() {
                insert_new_chunk_or_test_equality(chunks, *chunk_index, chunk.clone());
                let chunk_hash = Tip5::hash(chunk);
                let (mut merkle_node_index, _) =
                    leaf_index_to_mt_index_and_peak_index(*chunk_index, num_leafs_swbfi);
                let height = mmr_membership_proof.authentication_path.len();

                let mut running_digest = chunk_hash;
                insert_new_digest_or_test_equality(
                    sparse_mmr,
                    height,
                    merkle_node_index,
                    running_digest,
                );

                for sibling in mmr_membership_proof.authentication_path.iter().copied() {
                    insert_new_digest_or_test_equality(
                        sparse_mmr,
                        height,
                        merkle_node_index ^ 1,
                        sibling,
                    );

                    running_digest = if merkle_node_index & 1 == 0 {
                        Tip5::hash_pair(running_digest, sibling)
                    } else {
                        Tip5::hash_pair(sibling, running_digest)
                    };
                    merkle_node_index >>= 1;
                    insert_new_digest_or_test_equality(
                        sparse_mmr,
                        height,
                        merkle_node_index,
                        running_digest,
                    );
                }
            }

            consistent_mmr && consistent_chunks
        }
    }

    #[proptest]
    fn convert_empty(#[strategy(arb::<u64>())] num_leafs_aocl: u64) {
        let removal_records = Vec::<RemovalRecord>::new();
        let as_list =
            RemovalRecordList::from_removal_records(removal_records.clone(), num_leafs_aocl);
        let as_vec_again = as_list.convert_to_vec();
        prop_assert_eq!(removal_records, as_vec_again);
    }

    /// `RemovalRecord::arbitrary_synchronized_set` is rather involved; let's
    /// test its sanity in a standalone test.
    #[proptest]
    fn arbitrary_synchronized_set_of_removal_records_sanity(
        #[strategy(arb::<u64>())] _num_aocl_leafs: u64,
        #[strategy(0usize..10)] _num_records: usize,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_aocl_leafs, #_num_records))]
        _removal_records: Vec<RemovalRecord>,
    ) {
    }

    #[proptest]
    fn arbitrary_synchronized_set_of_removal_records_consistency(
        #[strategy(arb::<u64>())] num_leafs_aocl: u64,
        #[strategy(0usize..10)] _num_records: usize,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        prop_assert!(removal_records
            .iter()
            .all(|rr| rr.is_consistent(num_leafs_aocl)));
        prop_assert!(RemovalRecord::are_mutually_consistent(
            &removal_records,
            num_leafs_aocl
        ));
    }

    #[test]
    fn arbitrary_synchronized_set_of_removal_records_consistency_unit() {
        let mut test_runner = TestRunner::deterministic();
        let num_leafs_aocl = arb::<u64>().new_tree(&mut test_runner).unwrap().current() & 0xfff;
        let removal_records = RemovalRecord::arbitrary_synchronized_set(num_leafs_aocl, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        assert!(removal_records
            .into_iter()
            .all(|rr| rr.is_consistent(num_leafs_aocl)));
    }

    #[proptest]
    fn convert_single_record(
        #[strategy(arb::<u64>())] num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#num_leafs_aocl, 1))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let as_list =
            RemovalRecordList::from_removal_records(removal_records.clone(), num_leafs_aocl);
        let as_vec_again = as_list.convert_to_vec();
        prop_assert_eq!(removal_records, as_vec_again);
    }

    #[test]
    fn convert_single_record_unit() {
        let mut test_runner = TestRunner::deterministic();
        let num_leafs_aocl = arb::<u64>().new_tree(&mut test_runner).unwrap().current();
        let removal_records = RemovalRecord::arbitrary_synchronized_set(num_leafs_aocl, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        let as_list =
            RemovalRecordList::from_removal_records(removal_records.clone(), num_leafs_aocl);
        let as_vec_again = as_list.convert_to_vec();
        for (left, right) in removal_records.iter().zip(as_vec_again.iter()) {
            assert_eq!(left.absolute_indices, right.absolute_indices);
            assert_eq!(
                left.target_chunks.all_chunk_indices(),
                right.target_chunks.all_chunk_indices()
            );
            assert_eq!(
                left.target_chunks.authentication_paths(),
                right.target_chunks.authentication_paths()
            );
            assert_eq!(left.clone(), right.clone());
        }
        assert_eq!(removal_records, as_vec_again);
    }

    #[proptest]
    fn convert_many_records(
        #[strategy(0usize..10)] _num_records: usize,
        #[strategy(arb::<u64>())] num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let as_list =
            RemovalRecordList::from_removal_records(removal_records.clone(), num_leafs_aocl);
        let as_vec_again = as_list.convert_to_vec();
        prop_assert_eq!(removal_records, as_vec_again);
    }

    #[test]
    fn convert_many_records_unit() {
        let mut test_runner = TestRunner::deterministic();
        let num_records = (0usize..10).new_tree(&mut test_runner).unwrap().current();
        let num_leafs_aocl = arb::<u64>().new_tree(&mut test_runner).unwrap().current();
        let removal_records =
            RemovalRecord::arbitrary_synchronized_set(num_leafs_aocl, num_records)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

        let as_list =
            RemovalRecordList::from_removal_records(removal_records.clone(), num_leafs_aocl);
        let as_vec_again = as_list.convert_to_vec();
        assert_eq!(removal_records, as_vec_again);
    }

    #[proptest]
    fn convert_many_records_without_knowledge_of_aocl(
        #[strategy(0usize..10)] _num_records: usize,
        #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let as_list = RemovalRecordList::convert_from_vec(removal_records.clone());
        let as_vec_again = as_list.convert_to_vec();
        prop_assert_eq!(removal_records, as_vec_again);
    }

    #[proptest]
    fn estimate_of_num_leafs_aocl_is_lower_bound(
        #[strategy(0usize..10)] _num_records: usize,
        #[strategy(arb::<u64>())] num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let chunk_indices = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.indices_and_leafs())
            .map(|(idx, _leaf)| idx)
            .collect_vec();
        let authentication_path_lengths = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.authentication_paths())
            .map(|mp| mp.authentication_path.len())
            .sorted()
            .rev()
            .dedup()
            .collect_vec();
        let estimate_num_leafs_aocl = RemovalRecordList::estimate_num_leafs_aocl(
            &chunk_indices,
            &authentication_path_lengths,
        );

        prop_assert!(estimate_num_leafs_aocl <= num_leafs_aocl);
    }

    #[proptest]
    fn estimate_of_num_leafs_aocl_is_viable(
        #[strategy(0usize..10)] _num_records: usize,
        #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let chunk_indices = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.indices_and_leafs())
            .map(|(idx, _leaf)| idx)
            .collect_vec();
        let authentication_path_lengths = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.authentication_paths())
            .map(|mp| mp.authentication_path.len())
            .sorted()
            .rev()
            .dedup()
            .collect_vec();
        let estimate_num_leafs_aocl = RemovalRecordList::estimate_num_leafs_aocl(
            &chunk_indices,
            &authentication_path_lengths,
        );

        // the estimate explains all authentication path lengths
        let num_leafs_swbfi = estimate_num_leafs_aocl / u64::from(BATCH_SIZE);
        for removal_record in &removal_records {
            for mp in removal_record.target_chunks.authentication_paths() {
                prop_assert_ne!(
                    num_leafs_swbfi & (1 << mp.authentication_path.len()),
                    0,
                    "num leafs swbfi: {}, authentication path length: {}",
                    num_leafs_swbfi,
                    mp.authentication_path.len()
                );
            }
        }

        // the estimate explains all chunks
        let window_start =
            u128::from(estimate_num_leafs_aocl) / u128::from(BATCH_SIZE) * u128::from(CHUNK_SIZE);
        let would_be_observed_chunk_indices = removal_records
            .iter()
            .flat_map(|rr| rr.absolute_indices.to_array())
            .filter(|absolute_index| *absolute_index < window_start)
            .map(|absolute_index| absolute_index / u128::from(CHUNK_SIZE))
            .map(u64::try_from)
            .map(std::result::Result::<_, _>::unwrap)
            .sorted()
            .dedup()
            .collect::<HashSet<_>>();
        for removal_record in &removal_records {
            for (chunk_index, _leaf) in removal_record.target_chunks.indices_and_leafs() {
                prop_assert!(
                    would_be_observed_chunk_indices.contains(&chunk_index),
                    "missing chunk index: {}",
                    chunk_index
                );
            }
        }
    }

    #[test]
    fn estimate_of_num_leafs_aocl_is_viable_unit() {
        let mut runner = TestRunner::deterministic();
        let num_records = (0usize..10).new_tree(&mut runner).unwrap().current();
        let num_leafs_aocl = arb::<u64>().new_tree(&mut runner).unwrap().current();
        let removal_records =
            RemovalRecord::arbitrary_synchronized_set(num_leafs_aocl, num_records)
                .new_tree(&mut runner)
                .unwrap()
                .current();

        let chunk_indices = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.indices_and_leafs())
            .map(|(idx, _leaf)| idx)
            .collect_vec();
        let authentication_path_lengths = removal_records
            .iter()
            .flat_map(|rr| rr.target_chunks.authentication_paths())
            .map(|mp| mp.authentication_path.len())
            .sorted()
            .rev()
            .dedup()
            .collect_vec();
        let estimate_num_leafs_aocl = RemovalRecordList::estimate_num_leafs_aocl(
            &chunk_indices,
            &authentication_path_lengths,
        );

        // the estimate explains all authentication path lengths
        let num_leafs_swbfi = estimate_num_leafs_aocl / u64::from(BATCH_SIZE);
        for removal_record in &removal_records {
            for mp in removal_record.target_chunks.authentication_paths() {
                assert_ne!(
                    num_leafs_swbfi & (1 << mp.authentication_path.len()),
                    0,
                    "num leafs swbfi: {num_leafs_swbfi}, authentication path length: {}",
                    mp.authentication_path.len()
                );
            }
        }

        // the estimate explains all chunks
        let window_start =
            u128::from(estimate_num_leafs_aocl) / u128::from(BATCH_SIZE) * u128::from(CHUNK_SIZE);
        let would_be_observed_chunk_indices = removal_records
            .iter()
            .flat_map(|rr| rr.absolute_indices.to_array())
            .filter(|absolute_index| *absolute_index < window_start)
            .map(|absolute_index| absolute_index / u128::from(CHUNK_SIZE))
            .map(u64::try_from)
            .map(std::result::Result::<_, _>::unwrap)
            .sorted()
            .dedup()
            .collect::<HashSet<_>>();
        for removal_record in &removal_records {
            for (chunk_index, _leaf) in removal_record.target_chunks.indices_and_leafs() {
                assert!(
                    would_be_observed_chunk_indices.contains(&chunk_index),
                    "missing chunk index: {}",
                    chunk_index
                );
            }
        }
    }

    #[proptest(cases = 10)]
    fn encoding_happy_path(
        #[strategy(0usize..20)] _num_records: usize,
        #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let rrl = RemovalRecordList::convert_from_vec(removal_records);
        prop_assert_eq!(
            &rrl,
            &RemovalRecordList::decode_from_vec(rrl.encode_as_vec()).unwrap()
        );
    }

    #[proptest(cases = 10)]
    fn decode_cannot_crash(
        #[strategy(1usize..20)] _num_records: usize,
        #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
        #[strategy(0usize..NUM_TRIALS as usize)] abs_index_mutated: usize,
        #[strategy(arb::<usize>())] index_of_change: usize,
    ) {
        let rrl = RemovalRecordList::convert_from_vec(removal_records);
        let mut received_over_wire = rrl.encode_as_vec();
        let length = received_over_wire.len();
        received_over_wire[index_of_change % length]
            .absolute_indices
            .set_bloom_filter_index(abs_index_mutated, u128::MAX);
        let _ = RemovalRecordList::decode_from_vec(received_over_wire); // no crash
    }

    #[proptest(cases = 10)]
    fn pack_unpack_happy_path(
        #[strategy(0usize..20)] _num_records: usize,
        #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();
        prop_assert_eq!(removal_records, unpacked);
    }

    #[proptest(cases = 10)]
    fn unpack_cannot_crash(
        #[strategy(1usize..20)] _num_records: usize,
        #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let _ = RemovalRecordList::try_unpack(removal_records); // no crash
    }

    #[test]
    fn too_big_absolute_index_cannot_crash_decoder() {
        let mut runner = TestRunner::deterministic();
        let removal_records = RemovalRecord::arbitrary_synchronized_set(100, 2)
            .new_tree(&mut runner)
            .unwrap()
            .current();

        let rrl = RemovalRecordList::convert_from_vec(removal_records);
        let mut received_over_wire = rrl.encode_as_vec();
        for i in 0..NUM_TRIALS {
            received_over_wire[0]
                .absolute_indices
                .set_bloom_filter_index(i as usize, u128::MAX);
        }
        let result = RemovalRecordList::decode_from_vec(received_over_wire);
        assert!(matches!(
            result.unwrap_err(),
            RemovalRecordListUnpackError::AbsoluteIndexTooBig
        ));
    }

    #[proptest]
    fn bfieldcodec_encoding(
        #[strategy(0usize..10)] _num_records: usize,
        #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
        #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
        removal_records: Vec<RemovalRecord>,
    ) {
        let as_list = RemovalRecordList::convert_from_vec(removal_records);
        let encoded = as_list.encode_as_vec().encode();
        let decoded =
            RemovalRecordList::decode_from_vec(*Vec::<RemovalRecord>::decode(&encoded).unwrap())
                .unwrap();

        prop_assert_eq!(as_list, decoded);
    }

    #[test]
    fn bfieldcodec_encoding_unit() {
        let mut test_runner = TestRunner::deterministic();
        let num_records = (0usize..10).new_tree(&mut test_runner).unwrap().current();
        let num_leafs_aocl = arb::<u64>().new_tree(&mut test_runner).unwrap().current();
        let removal_records =
            RemovalRecord::arbitrary_synchronized_set(num_leafs_aocl, num_records)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

        let as_list = RemovalRecordList::convert_from_vec(removal_records.clone());
        let encoded = as_list.encode_as_vec().encode();
        let decoded =
            RemovalRecordList::decode_from_vec(*Vec::<RemovalRecord>::decode(&encoded).unwrap())
                .unwrap();

        assert_eq!(as_list, decoded);
    }

    #[test]
    #[ignore = "statistics"]
    fn bfieldcodec_encoding_size_statistics() {
        let config = Config::default();
        let mut test_runner = TestRunner::new_with_rng(
            config,
            TestRng::from_seed(RngAlgorithm::ChaCha, &rng().random::<[u8; 32]>()),
        );

        let num_trials = 10;
        let mut total_size_naive = 0.0_f64;
        let mut total_size_smart = 0.0_f64;

        for _ in 0..num_trials {
            let num_records = (1usize..=100).new_tree(&mut test_runner).unwrap().current();
            let num_leafs_aocl = arb::<u64>().new_tree(&mut test_runner).unwrap().current();
            let removal_records =
                RemovalRecord::arbitrary_synchronized_set(num_leafs_aocl, num_records)
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();

            let encoded_directly = removal_records.encode();
            total_size_naive += (encoded_directly.len() as f64) / (num_records as f64);

            let as_list = RemovalRecordList::convert_from_vec(removal_records.clone());
            let list_encoded = as_list.encode_as_vec().encode();
            total_size_smart += (list_encoded.len() as f64) / (num_records as f64);
        }

        let average_size_naive = total_size_naive / f64::from(num_trials);
        let average_size_smart = total_size_smart / f64::from(num_trials);

        println!(
            "average size of removal record with current (naïve) representation: {} BFieldElements",
            average_size_naive
        );
        println!(
            "average size of removal record with irredundant representation: {} BFieldElements",
            average_size_smart
        );
        println!(
            "{:.2}% reduction",
            (1.0 - (average_size_smart / average_size_naive)) * 100.0
        );
    }
}
