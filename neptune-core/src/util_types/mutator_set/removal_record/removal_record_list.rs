use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::twenty_first::prelude::MerkleTree;
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_peak_heights;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use thiserror::Error;

use super::chunk::Chunk;
use super::chunk::ChunkUnpackError;
use super::chunk_dictionary::ChunkDictionary;
use super::AbsoluteIndexSet;
use super::RemovalRecord;
use crate::util_types::mutator_set::aocl_to_swbfi_leaf_counts;
use crate::util_types::mutator_set::shared::BATCH_SIZE;
use crate::util_types::mutator_set::shared::CHUNK_SIZE;

/// A list of [`RemovalRecords`](crate::util_types::mutator_set::removal_record::RemovalRecord)s
/// without redundant Merkle authentication data.
///
/// This is considered a trusted data structure as it's never transmitted over
/// the network and is only ever used internally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemovalRecordList {
    /// The unchanged absolute indices of the (unpacked) removal records.
    index_sets: Vec<AbsoluteIndexSet>,

    /// One authentication structure for each tree in the MMR.
    /// If tree has no chunks, the empty list is inserted as element.
    /// The empty list is *also* inserted for the tree of height 0, if it
    /// exists. The list is sorted by ascending tree height, *i.e.*, smallest
    /// tree first.
    authentication_structures: Vec<Vec<Digest>>,

    /// ascending order by chunk index
    chunks: Vec<Chunk>,

    /// The number of leafs in the AOCL at the point in time when the removal
    /// records are supposed to be valid. If the number is not known exactly,
    /// this field is populated with a viable estimate, meaning that the number
    /// is set such that the algorithm should work. More precisely, viable means
    /// that it explains why the SWBF authentication structures have the lengths
    /// they do. If the removal records are correct, it is a lower bound on the
    /// number of AOCL leafs in the mutator set.
    num_leafs_aocl: u64,
}

#[derive(Debug, Error)]
pub(crate) enum RemovalRecordListUnpackError {
    #[error("inner decoding error: {0}")]
    InnerDecodingFailure(#[from] Box<dyn core::error::Error + Send + Sync>),
    #[error("Absolute index value cannot exceed 74 bits")]
    AbsoluteIndexTooBig,
    #[error("Illegal tree height: {tree_height}")]
    IllegalTreeHeight { tree_height: u64 },
    #[error("List of tree heights contains duplicates.")]
    DuplicateTreeHeights,
    #[error("removal records are mutually inconsistent: {0}")]
    Inconsistency(RemovalRecordListInconsistency),
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub(crate) enum RemovalRecordListInconsistency {
    #[error("number of chunks ({num_chunks}) is inconsistent with number of chunk indices ({num_chunk_indices})")]
    Chunks {
        num_chunk_indices: usize,
        num_chunks: usize,
    },
    #[error("number of authentication structures {num_authentication_structures} is inconsistent with the number of trees {total_num_trees}")]
    AuthenticationStructureCount {
        num_authentication_structures: usize,
        total_num_trees: usize,
    },
    #[error(
        "observed lengths of authentication structures ([{}]) does not match with expectation ([{}])",
        observed_authentication_structure_lengths.iter().join(", "),
        expected_authentication_structure_lengths.iter().join(", ")
    )]
    AuthenticationStructureLength {
        expected_authentication_structure_lengths: Vec<usize>,
        observed_authentication_structure_lengths: Vec<usize>,
    },
}

impl RemovalRecordList {
    /// When there are more Chunks than trees, this value is used for the tree
    /// height to indicate it (tree height and authentication structure) should
    /// be ignored.
    const ENCODING_DELIMITER_IGNORE_TREE_HEIGHT: u64 = u64::MAX;

    /// When there are more trees than Chunks, the tree heights are offset by
    /// this value to indicate that the associated Chunk should be ignored. Note
    /// that the associated authentication structure must be empty in this case.
    const ENCODING_TREE_HEIGHT_OFFSET: u64 = 64;

    /// Convert a `Vec` of [`RemovalRecord`]s to a [`RemovalRecordList`].
    ///
    /// The difference between this method and [`Self::convert_from_vec`] is the
    /// second argument, the number of leafs in the AOCL. Producing
    /// this estimate is time-consuming and error-prone (tests notwithstanding),
    /// so it is better to avoid that step if possible.
    ///
    /// This function runs on trusted inputs. It is the caller's responsibility
    /// to ensure that all removal records are valid and mutually consistent.
    ///
    /// # Panics
    ///
    ///  - May (probably) panic if removal records are invalid or mutually
    ///    inconsistent.
    pub(crate) fn from_removal_records(
        removal_records: Vec<RemovalRecord>,
        num_leafs_aocl: u64,
    ) -> Self {
        let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(num_leafs_aocl);
        let all_tree_heights = get_peak_heights(num_leafs_swbfi);
        let index_sets = removal_records
            .iter()
            .map(|rr| rr.absolute_indices)
            .collect_vec();

        let mut mmr_leaf_indices = HashSet::<(u32, u64)>::new();
        let mut chunks = HashMap::<u64, Chunk>::new();
        for removal_record in &removal_records {
            for target_chunk in removal_record.target_chunks.iter() {
                let (chunk_index, (chunk_mmr_mp, chunk)) = target_chunk;
                if let Some(chunk_already_present) = chunks.insert(*chunk_index, chunk.clone()) {
                    assert_eq!(
                        chunk_already_present,
                        chunk.clone(),
                        "removal records are inconsistent: they have distinct chunks for the same chunk index"
                    );
                }
                let tree_height_according_to_authentication_path =
                    chunk_mmr_mp.authentication_path.len() as u32;
                let (_, peak_index) =
                    leaf_index_to_mt_index_and_peak_index(*chunk_index, num_leafs_swbfi);
                let tree_height_according_to_num_leafs = all_tree_heights[peak_index as usize];
                assert_eq!(
                    tree_height_according_to_num_leafs,
                    tree_height_according_to_authentication_path,
                    "removal records are inconsistent: authentication path length disagrees with tree heights according to num leafs"
                );
                mmr_leaf_indices
                    .insert((tree_height_according_to_authentication_path, *chunk_index));
            }
        }

        // compile sparse view of MMR
        let mut sparse_mmr: HashMap<_, Digest> = HashMap::new();
        for removal_record in removal_records {
            for target_chunk in removal_record.target_chunks {
                let (chunk_index, (chunk_mmr_mp, chunk)) = target_chunk;

                // Because of previous assert, we can trust this value for the
                // tree height.
                let tree_height = chunk_mmr_mp.authentication_path.len() as u32;

                let mut running_digest = Tip5::hash(&chunk);
                let (mut merkle_node_index, _) =
                    leaf_index_to_mt_index_and_peak_index(chunk_index, num_leafs_swbfi);

                for sibling_digest in chunk_mmr_mp.authentication_path {
                    if let Some(kickout) =
                        sparse_mmr.insert((tree_height, merkle_node_index), running_digest)
                    {
                        assert_eq!(
                            kickout,
                            running_digest,
                            "removal records are inconsistent: they disagree about internal nodes in the SWBFI MMR"
                        );
                    }

                    if let Some(kickout) =
                        sparse_mmr.insert((tree_height, merkle_node_index ^ 1), sibling_digest)
                    {
                        assert_eq!(
                            kickout,
                            sibling_digest,
                            "removal records are inconsistent: they disagree about internal nodes in the SWBFI MMR"
                        );
                    }

                    if merkle_node_index & 1 == 0 {
                        running_digest = Tip5::hash_pair(running_digest, sibling_digest);
                    } else {
                        running_digest = Tip5::hash_pair(sibling_digest, running_digest);
                    }
                    merkle_node_index >>= 1;
                }

                if let Some(kickout) =
                    sparse_mmr.insert((tree_height, merkle_node_index), running_digest)
                {
                    assert_eq!(
                        kickout,
                        running_digest,
                        "removal records are inconsistent: they disagree about root nodes in the SWBFI MMR"
                    );
                }
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
                .map(|&li| li & ((1 << tree_height) - 1))
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
                    assert_eq!(
                        previous.1.clone(),
                        current.1.clone(),
                        "removal records are inconsistent: they disagree about chunks with the same index"
                    );
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

    /// Compute a minimum viable lower bound on the current number of leafs in
    /// the AOCL given context inferred from removal records, where "current"
    /// means the point in time when the removal records are supposed to be
    /// valid.
    ///
    /// The lower bound is *viable*: it suffices to "explain" why the given
    /// chunks are present and why the authentication paths have the lengths
    /// they do.
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
        let mut swbfi_leaf_count_estimate = largest_observed_chunk_index;

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
            observed_authentication_path_lengths.len(),
            "observed authentication path lengths contains duplicates."
        );
        for tree_height in observed_authentication_path_lengths {
            let tree_width = 1u64 << tree_height;
            if swbfi_leaf_count_estimate & tree_width == 0 {
                // set the bit in question
                swbfi_leaf_count_estimate |= tree_width;

                // zero all subsequent bits
                swbfi_leaf_count_estimate &= u64::MAX - (tree_width - 1);
            }
        }

        swbfi_leaf_count_estimate * u64::from(BATCH_SIZE) + 1
    }

    /// Compute a [`ChunkDictionary`], densely encoding all the data about
    /// Chunks, authentication structures, and tree heights. Phrased
    /// differently, compute a [`ChunkDictionary`] that densely encodes all the
    /// information contained in [`Self`] *except* the absolute index sets.
    ///
    /// Should only be used on locally derived [`RemovalRecordList`].
    ///
    /// # Panics
    ///
    ///  - If self is inconsistent.
    fn compressed_chunk_dictionary(&self) -> ChunkDictionary {
        use itertools::EitherOrBoth::Both;
        use itertools::EitherOrBoth::Left;
        use itertools::EitherOrBoth::Right;

        let num_swbf_leafs = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
        let tree_heights = get_peak_heights(num_swbf_leafs)
            .into_iter()
            .map(u64::from)
            .rev()
            .collect_vec();

        let chunk_indices = self.observed_chunk_indices();
        assert_eq!(chunk_indices.len(), self.chunks.len());

        let tree_heights_and_authentication_structures = tree_heights.into_iter().zip_eq(
            self.authentication_structures
                .iter()
                .cloned()
                .map(MmrMembershipProof::new),
        );

        let chunk_dictionary = tree_heights_and_authentication_structures
            .zip_longest(self.chunks.iter().map(Chunk::pack))
            .map(|x| match x {
                Both((tree_height, membership_proof), packed_chunk) => {
                    (tree_height, (membership_proof, packed_chunk))
                }
                Left((tree_height, membership_proof)) => (
                    tree_height + Self::ENCODING_TREE_HEIGHT_OFFSET,
                    (membership_proof, Chunk::empty_chunk()),
                ),
                Right(packed_chunk) => (
                    Self::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT,
                    (MmrMembershipProof::new(vec![]), packed_chunk),
                ),
            });
        ChunkDictionary {
            dictionary: chunk_dictionary.collect_vec(),
        }
    }

    /// Encodes a [`RemovalRecordList`] as a `Vec` of [`RemovalRecord`].
    ///
    /// The encoding follows the following rules:
    ///  - The absolute index sets are identical. There is no packing
    ///    of absolute index sets.
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
    ///  - If there are more Chunks than trees, tree height
    ///    [`Self::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT`] is used to indicate
    ///    that the associated authentication structure should be ignored. The
    ///    authentication structure will in this case be empty.
    ///  - If there are more trees than Chunks, the tree height is offset by
    ///    [`Self::ENCODING_TREE_HEIGHT_OFFSET`], and the Chunk is empty.
    ///  - All chunks of the [`RemovalRecordList`] are present exactly once. The
    ///    order is the same between self and this dictionary.
    ///  - The authentication structures in this dictionary are the same as
    ///    those from the like-named field of `Self`. The number of
    ///    authentication structures is guaranteed to be equal to the number of
    ///    trees inthe SWBFI MMR, except if there are more Chunks than trees.
    ///    The authentication structures do not correlate with the chunks.
    ///  - The tree heights *do* correlate with the authentication structures:
    ///    they indicate the height of the tree that the authentication
    ///    structure is for.
    ///
    /// See also: [`Self::decode_from_vec`], which computes the inverse of this
    /// function.
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

    /// Return the list of unique leaf indices into the SWBFI MMR, corresponding
    /// to Chunks referenced in the absolute index sets, in ascending order.
    fn observed_chunk_indices(&self) -> Vec<u64> {
        let swbfi_num_leafs = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
        let window_start = u128::from(swbfi_num_leafs) * u128::from(CHUNK_SIZE);
        self.index_sets
            .iter()
            .flat_map(|ais| ais.to_vec())
            .filter(|ai| *ai < window_start)
            .map(|ai| ai / u128::from(CHUNK_SIZE))
            .map(|u| u64::try_from(u).unwrap())
            .unique()
            .sorted()
            .collect_vec()
    }

    /// Computes consistency, with an error code in case of failure.
    ///
    /// Consistency is defined relative to a set of observed chunk indices,
    /// which itself is inferred from the set of all absolute indices after
    /// filtering for location outside of the active window. Relative to this
    /// set of observed chunk indices, consistency is defined as:
    ///  1. the cardinality of the set of observed chunk indices agrees with the
    ///     length of the `chunks` list; and
    ///  2. the number of authentication structures matches with the number of
    ///     peaks; and
    ///  3. for each tree in the MMR, the length of the authentication structure
    ///     matches with the given leaf indices.
    ///
    /// Error type [`RemovalRecordListInconsistency`] has one variant for every
    /// failure case.
    fn validate_consistency(&self) -> Result<(), RemovalRecordListInconsistency> {
        let observed_chunk_indices = self.observed_chunk_indices();

        // 1) cardinality must match
        if observed_chunk_indices.len() != self.chunks.len() {
            return Err(RemovalRecordListInconsistency::Chunks {
                num_chunk_indices: observed_chunk_indices.len(),
                num_chunks: self.chunks.len(),
            });
        }

        // compile a usable view of the MMR's known leafs
        let mut mmr_view = HashSet::new();
        let swbfi_num_leafs = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
        let all_peak_heights = get_peak_heights(swbfi_num_leafs);
        for chunk_index in observed_chunk_indices {
            let (merkle_leaf_index, peak_index) =
                leaf_index_to_mt_index_and_peak_index(chunk_index, swbfi_num_leafs);
            let merkle_leaf_index =
                merkle_leaf_index & (u64::MAX ^ (1 << all_peak_heights[peak_index as usize]));
            mmr_view.insert((peak_index, merkle_leaf_index));
        }
        let active_peak_indices = mmr_view.iter().map(|(pi, _mli)| *pi).unique().collect_vec();
        let merkle_leaf_indices_by_tree = all_peak_heights
            .iter()
            .enumerate()
            .map(|(peak_index, peak_height)| {
                let leaf_indices_for_this_tree = mmr_view
                    .iter()
                    .filter(|(pi, _mli)| *pi == u32::try_from(peak_index).unwrap())
                    .map(|(_pi, mli)| *mli)
                    .collect_vec();
                assert!(leaf_indices_for_this_tree
                    .iter()
                    .all(|li| *li < (1 << *peak_height)));
                leaf_indices_for_this_tree
            })
            .collect_vec();

        // Assert that number of active trees <= pop count of num leafs.
        // This fact follows from MMR code. (If not, we want to fail as quickly
        // as possible.)
        let total_num_trees = all_peak_heights.len();
        let num_active_trees = active_peak_indices.len();
        assert!(num_active_trees <= total_num_trees);

        // 2) correct number of authentication structures
        let num_authentication_structures = self.authentication_structures.len();
        if num_authentication_structures != total_num_trees {
            return Err(
                RemovalRecordListInconsistency::AuthenticationStructureCount {
                    num_authentication_structures,
                    total_num_trees,
                },
            );
        }

        // 3) for each tree, the authentication structure length is correct
        let expected_authentication_structure_lengths = all_peak_heights
            .into_iter()
            .zip(merkle_leaf_indices_by_tree)
            .map(|(ph, mlis)| {
                MerkleTree::authentication_structure_node_indices(1_u64 << ph, &mlis)
                    .unwrap_or_else(|_| {
                        panic!(
                            "tree height: {} / merkle leaf indices: [{}]",
                            ph,
                            mlis.iter().join(", ")
                        )
                    })
                    .len()
            })
            .sorted()
            .collect_vec();
        let observed_authentication_structure_lengths = self
            .authentication_structures
            .iter()
            .map(|auth_str| auth_str.len())
            .sorted()
            .collect_vec();
        if expected_authentication_structure_lengths != observed_authentication_structure_lengths {
            return Err(
                RemovalRecordListInconsistency::AuthenticationStructureLength {
                    expected_authentication_structure_lengths,
                    observed_authentication_structure_lengths,
                },
            );
        }

        Ok(())
    }

    /// Produce a [`RemovalRecordList`] by decoding a [`Vec`] of
    /// [`RemovalRecord`]. This function computes the inverse of
    /// [`Self::encode_as_vec`].
    fn decode_from_vec(
        removal_records: Vec<RemovalRecord>,
    ) -> Result<RemovalRecordList, RemovalRecordListUnpackError> {
        let mut index_sets = vec![];
        let mut authentication_structures = vec![];
        let mut chunks = vec![];

        let mut tree_heights = vec![];
        for removal_record in removal_records.clone() {
            index_sets.push(removal_record.absolute_indices);
            for (tree_height, (mmr_authentication_path, chunk)) in
                removal_record.target_chunks.iter()
            {
                if *tree_height < Self::ENCODING_TREE_HEIGHT_OFFSET {
                    // use both authentication structure and chunk
                    tree_heights.push(*tree_height);
                    authentication_structures
                        .push(mmr_authentication_path.authentication_path.clone());
                    let unpacked_chunk = chunk.try_unpack().map_err(Box::new).map_err(
                        |e: Box<ChunkUnpackError>| {
                            RemovalRecordListUnpackError::InnerDecodingFailure(e)
                        },
                    )?;
                    chunks.push(unpacked_chunk);
                } else if *tree_height < 2 * Self::ENCODING_TREE_HEIGHT_OFFSET {
                    // ignore chunk
                    let tree_height = *tree_height - Self::ENCODING_TREE_HEIGHT_OFFSET;
                    tree_heights.push(tree_height);
                    authentication_structures
                        .push(mmr_authentication_path.authentication_path.clone());
                } else if *tree_height == Self::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT {
                    // ignore tree
                    let unpacked_chunk = chunk.try_unpack().map_err(Box::new).map_err(
                        |e: Box<ChunkUnpackError>| {
                            RemovalRecordListUnpackError::InnerDecodingFailure(e)
                        },
                    )?;
                    chunks.push(unpacked_chunk);
                } else {
                    return Err(RemovalRecordListUnpackError::IllegalTreeHeight {
                        tree_height: *tree_height,
                    });
                }

                if tree_heights.len() != tree_heights.iter().unique().count() {
                    return Err(RemovalRecordListUnpackError::DuplicateTreeHeights);
                }
            }
        }

        let observed_chunk_indices =
            Self::observed_chunk_indices_from_index_sets(&index_sets, chunks.len())?;

        let num_leafs_aocl = Self::estimate_num_leafs_aocl(
            &observed_chunk_indices,
            &tree_heights.iter().map(|u| *u as usize).rev().collect_vec(),
        );

        let removal_record_list = Self {
            index_sets,
            authentication_structures,
            chunks,
            num_leafs_aocl,
        };

        removal_record_list
            .validate_consistency()
            .map_err(RemovalRecordListUnpackError::Inconsistency)?;

        Ok(removal_record_list)
    }

    /// Compute the first `number`-many chunk indices corresponding to the given
    /// absolute indices.
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
    pub(crate) fn pack(removal_records: Vec<RemovalRecord>) -> Vec<RemovalRecord> {
        let as_rr_list = Self::convert_from_vec(removal_records);
        as_rr_list.encode_as_vec()
    }

    /// Decompress a [`Vec`] of [`RemovalRecord`]s as packed by [`Self::pack`].
    /// Returns an error if the packing is invalid.
    pub(crate) fn try_unpack(
        removal_records: Vec<RemovalRecord>,
    ) -> Result<Vec<RemovalRecord>, RemovalRecordListUnpackError> {
        let as_removal_record_list = RemovalRecordList::decode_from_vec(removal_records)?;
        Ok(as_removal_record_list.convert_to_vec())
    }

    /// Convert a [`Vec`] of [`RemovalRecord`]s into a [`RemovalRecordList`],
    /// which is a denser representation of the same object. In particular,
    /// there is no loss of information (unless the input is malicious).
    ///
    /// This function assumes that the input is honest. Specifically, that the
    /// removal records are valid and mutually consistent.
    ///
    /// See also [`Self::convert_to_vec`], which computes the inverse of this
    /// function.
    ///
    /// # Panics
    ///
    ///  - May (probably) panic if the removal records are invalid or mutually
    ///    inconsistent.
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

    /// Convert a [`RemovalRecordList`] to a (redundant) [`Vec`] of
    /// [`RemovalRecord`]s. This function computes the inverse of
    /// [`Self::convert_from_vec`].
    ///
    /// # Panics
    ///
    ///  - if `self` is inconsistent.
    fn convert_to_vec(self) -> Vec<RemovalRecord> {
        let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(self.num_leafs_aocl);
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
        let mut sparse_mmr: HashMap<_, Digest> = HashMap::new();
        let active_window_start =
            u128::from(self.num_leafs_aocl) / u128::from(BATCH_SIZE) * u128::from(CHUNK_SIZE);
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
                "Have authentication structure of len {} but node indices of len {};\nnode indices are: [{}]",
                authentication_structure.len(),
                node_indices_for_authentication_structure.len(),
                node_indices_for_authentication_structure.iter().join(", ")
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
                .filter(|absolute_index| *absolute_index < active_window_start)
                .map(|absolute_index| absolute_index / u128::from(CHUNK_SIZE))
                .map(|u| u64::try_from(u).expect("absolute index can never be more than 72 bits"))
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

#[cfg(any(test, feature = "arbitrary-impls"))]
use std::hash::BuildHasherDefault;
#[cfg(any(test, feature = "arbitrary-impls"))]
use std::hash::Hasher;

#[cfg(any(test, feature = "arbitrary-impls"))]
use proptest::collection::vec;
#[cfg(any(test, feature = "arbitrary-impls"))]
use proptest::prelude::*;

#[cfg(any(test, feature = "arbitrary-impls"))]
use crate::util_types::mutator_set::shared::WINDOW_SIZE;

#[cfg(any(test, feature = "arbitrary-impls"))]
impl RemovalRecord {
    pub(crate) fn arbitrary_synchronized_set(
        num_leafs_aocl: u64,
        num_records: usize,
    ) -> BoxedStrategy<Vec<RemovalRecord>> {
        #[derive(Default)]
        struct SimpleHasher(u64);

        impl Hasher for SimpleHasher {
            fn write(&mut self, bytes: &[u8]) {
                for &b in bytes {
                    self.0 = self.0.wrapping_mul(31).wrapping_add(u64::from(b));
                }
            }

            fn finish(&self) -> u64 {
                self.0
            }
        }

        type HashMapWithHasher<K, V> = HashMap<K, V, BuildHasherDefault<SimpleHasher>>;

        const ROOT_INDEX: u64 = 1_u64;

        let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(num_leafs_aocl);
        let mmr_heights = get_peak_heights(num_leafs_swbfi);
        let mmr_max_height = mmr_heights
            .iter()
            .copied()
            .max()
            .map(i64::from)
            .unwrap_or(-1_i64);
        let active_window_start =
            u128::from(aocl_to_swbfi_leaf_counts(num_leafs_aocl)) * u128::from(CHUNK_SIZE);
        (
                vec(0..num_leafs_aocl, num_records),
                vec(vec(0u32..WINDOW_SIZE, crate::util_types::mutator_set::shared::NUM_TRIALS as usize), num_records),
            )
                .prop_flat_map(move |(aocl_indices, relative_index_sets)| {
                    let absolute_index_sets = aocl_indices
                        .into_iter()
                        .map(|aocl_index| {
                            u128::from(aocl_to_swbfi_leaf_counts(aocl_index)) * u128::from(CHUNK_SIZE)
                        })
                        .zip(relative_index_sets)
                        .map(|(window_start, relative_index_set)| {
                            AbsoluteIndexSet::new(
                                relative_index_set
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
                            proptest_arbitrary_interop::arb::<Digest>(),
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
                            // Use deterministic HashMap here for deterministic
                            // key/value iterations.
                            let deterministic_hash_map = || {
                                HashMapWithHasher::default()
                            };
                            let mut sparse_mmr = deterministic_hash_map();
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
}

#[cfg(test)]
mod tests {
    use std::mem;

    use proptest::collection::vec;
    use proptest::prelude::Arbitrary;
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
    use strum::IntoEnumIterator;
    use test_strategy::proptest;
    use tracing_test::traced_test;

    use super::RemovalRecordList;
    use super::*;
    use crate::util_types::mutator_set::msa_and_records::MsaAndRecords;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;

    impl RemovalRecord {
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
            let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(num_leafs_aocl);

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

    #[test]
    fn empty_with_implied_aocl_leaf_count() {
        let removal_records = Vec::<RemovalRecord>::default();
        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();
        assert_eq!(removal_records, unpacked);
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
    fn arbitrary_synchronized_set_of_removal_records_consistency_small_num_aocl_leafs(
        #[strategy(1u64..(u64::from(u8::MAX)))] num_leafs_aocl: u64,
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
    fn convert_many_records_prop(
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
        let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(estimate_num_leafs_aocl);
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
        let window_start = u128::from(num_leafs_swbfi) * u128::from(CHUNK_SIZE);
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
        let num_leafs_swbfi = aocl_to_swbfi_leaf_counts(estimate_num_leafs_aocl);
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
        #[strategy(0usize..NUM_TRIALS as usize)] distance_index_mutated: usize,
        #[strategy(arb::<usize>())] index_of_change: usize,
    ) {
        let rrl = RemovalRecordList::convert_from_vec(removal_records);
        let mut received_over_wire = rrl.encode_as_vec();
        let length = received_over_wire.len();
        received_over_wire[index_of_change % length]
            .absolute_indices
            .set_minimum(u128::MAX);
        let _ = RemovalRecordList::decode_from_vec(received_over_wire.clone()); // no crash

        received_over_wire[index_of_change % length]
            .absolute_indices
            .set_distance(distance_index_mutated, u32::MAX);
        let _ = RemovalRecordList::decode_from_vec(received_over_wire); // no crash
    }

    #[proptest]
    fn can_unpack_one_with_empty_chunk_dictionary_first_batch(
        #[strategy(arb())] item: Digest,
        #[strategy(arb())] sr: Digest,
        #[strategy(arb())] rp: Digest,
    ) {
        for i in 0..u64::from(BATCH_SIZE) {
            let absolute_indices = AbsoluteIndexSet::compute(item, sr, rp, i);
            let removal_record = RemovalRecord {
                absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            };
            let removal_records = vec![removal_record];
            prop_assert_eq!(
                removal_records.clone(),
                RemovalRecordList::try_unpack(removal_records).unwrap()
            );
        }
    }

    #[test]
    fn three_chunks_one_tree() {
        let absolute_indices = AbsoluteIndexSet::new_raw(
            0,
            [
                CHUNK_SIZE,
                CHUNK_SIZE * 2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        );

        // Build removal record as it'll look when window has slid exactly four
        // times. So implied num leafs AOCL is [33,40].
        let empty_chunk = Chunk::empty_chunk();
        let leaf = Tip5::hash(&empty_chunk);
        let node = Tip5::hash_pair(leaf, leaf);
        let removal_record = RemovalRecord {
            absolute_indices,
            target_chunks: ChunkDictionary {
                dictionary: vec![
                    (
                        0,
                        (
                            MmrMembershipProof {
                                authentication_path: vec![leaf, node],
                            },
                            empty_chunk.clone(),
                        ),
                    ),
                    (
                        1,
                        (
                            MmrMembershipProof {
                                authentication_path: vec![leaf, node],
                            },
                            empty_chunk.clone(),
                        ),
                    ),
                    (
                        2,
                        (
                            MmrMembershipProof {
                                authentication_path: vec![leaf, node],
                            },
                            empty_chunk.clone(),
                        ),
                    ),
                ],
            },
        };

        let removal_records = vec![removal_record];
        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();
        assert_eq!(removal_records, unpacked);
    }

    fn more_chunks_than_abs_index_sets() -> RemovalRecord {
        let absolute_indices = AbsoluteIndexSet::new_raw(
            0,
            [
                CHUNK_SIZE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );

        let empty_chunk = Chunk::empty_chunk();
        let node = Tip5::hash(&empty_chunk);
        let removal_record = RemovalRecord {
            absolute_indices,
            target_chunks: ChunkDictionary {
                dictionary: vec![
                    (
                        0,
                        (
                            MmrMembershipProof {
                                authentication_path: vec![node],
                            },
                            empty_chunk.clone(),
                        ),
                    ),
                    (
                        1,
                        (
                            MmrMembershipProof {
                                authentication_path: vec![node],
                            },
                            empty_chunk,
                        ),
                    ),
                ],
            },
        };

        assert!(removal_record.is_consistent(17));

        removal_record
    }

    #[traced_test]
    #[test]
    fn more_chunks_than_absolute_index_sets_multiple_steps() {
        let not_packed = vec![more_chunks_than_abs_index_sets()];
        let temp0 = RemovalRecordList::from_removal_records(not_packed.clone(), 17);
        let packed = temp0.encode_as_vec();
        let temp1 = RemovalRecordList::decode_from_vec(packed.clone()).unwrap();
        assert_eq!(temp0, temp1);
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();
        assert_eq!(not_packed, unpacked);
    }

    #[traced_test]
    #[test]
    fn more_chunks_than_absolute_index_sets_pack() {
        let not_packed = vec![more_chunks_than_abs_index_sets()];
        let packed = RemovalRecordList::pack(not_packed.clone());
        assert_eq!(not_packed, RemovalRecordList::try_unpack(packed).unwrap());
    }

    #[proptest]
    fn can_unpack_one_with_empty_chunk_dictionary_second_batch(
        #[strategy(arb())] item: Digest,
        #[strategy(arb())] sr: Digest,
        #[strategy(arb())] rp: Digest,
    ) {
        for i in BATCH_SIZE..(BATCH_SIZE + BATCH_SIZE) {
            let absolute_indices = AbsoluteIndexSet::compute(item, sr, rp, u64::from(i));
            let removal_record = RemovalRecord {
                absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            };
            let removal_records = vec![removal_record];
            prop_assert_eq!(
                removal_records.clone(),
                RemovalRecordList::try_unpack(removal_records).unwrap()
            );
        }
    }

    #[proptest]
    fn can_unpack_two_with_empty_chunk_dictionaries(
        #[strategy(arb())] item: Digest,
        #[strategy(arb())] sr: Digest,
        #[strategy(arb())] rp: Digest,
    ) {
        for i in 0..u64::from(BATCH_SIZE) {
            let absolute_indices = AbsoluteIndexSet::compute(item, sr, rp, i);
            let removal_record = RemovalRecord {
                absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            };
            let removal_records = vec![removal_record.clone(), removal_record];
            prop_assert_eq!(
                removal_records.clone(),
                RemovalRecordList::try_unpack(removal_records).unwrap()
            );
        }
    }

    #[test]
    fn regression_test_chunk_numbers() {
        let rr = RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new_raw(
                11025,
                [
                    303562, 438177, 630410, 897086, 85806, 902498, 711771, 83670, 172217, 229797,
                    913208, 115517, 811202, 378771, 604364, 0, 709430, 774335, 90225, 121482,
                    918330, 719083, 974418, 163557, 289791, 184841, 83269, 982037, 878174, 335870,
                    40256, 684211, 922441, 129233, 687963, 951374, 69446, 442643, 842572, 622324,
                    92335, 96421, 358327, 966649, 184166,
                ],
            ),
            target_chunks: ChunkDictionary {
                dictionary: vec![(2, (MmrMembershipProof::new(vec![]), Chunk::empty_chunk()))],
            },
        };

        let rrs = vec![rr];
        let packed = RemovalRecordList::pack(rrs.clone());
        assert_eq!(
            rrs.clone(),
            RemovalRecordList::try_unpack(packed)
                .unwrap_or_else(|err| panic!("rrs: {rrs:#?}\n. Error:\n{err}")),
            "rrs: {rrs:#?}\n"
        );
    }

    #[proptest(cases = 30)]
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

    #[test]
    fn can_pack_and_try_unpack_batch_size_many_removal_records() {
        let mut runner = TestRunner::deterministic();
        let mut absolute_index_sets = vec(arb::<AbsoluteIndexSet>(), BATCH_SIZE as usize)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        for ais in &mut absolute_index_sets {
            // Ensure at least one index lives in 1st chunk
            ais.set_minimum(0);
        }

        let removal_records = absolute_index_sets
            .into_iter()
            .map(|ais| RemovalRecord {
                absolute_indices: ais,
                target_chunks: ChunkDictionary::new(vec![(
                    0,
                    (
                        MmrMembershipProof {
                            authentication_path: vec![],
                        },
                        Chunk::empty_chunk(),
                    ),
                )]),
            })
            .collect_vec();

        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();
        assert_eq!(removal_records, unpacked);
    }

    #[proptest]
    fn pack_unpack_identity_from_msa_and_records_tiny(
        #[strategy(1usize..3)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=20)] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let removal_records = msa_and_records.unpacked_removal_records();
        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

        prop_assert_eq!(removal_records, unpacked);
    }

    #[proptest]
    fn pack_unpack_identity_from_msa_and_records_very_small(
        #[strategy(1usize..=4)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=30)] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let removal_records = msa_and_records.unpacked_removal_records();
        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

        prop_assert_eq!(removal_records, unpacked);
    }

    #[test]
    fn bug_hunt_auth_path_not_empty() {
        let num_leafs = 128;
        let mut test_runner = TestRunner::deterministic();
        let mut rng = rng();

        for _ in 0..1000 {
            let item: Digest = rng.random();
            let msa_and_records = MsaAndRecords::arbitrary_with((
                vec![(item, Digest::default(), Digest::default()); 2],
                num_leafs,
            ))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

            let removal_records = msa_and_records.unpacked_removal_records();

            for rr in &removal_records {
                assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
            }

            assert_eq!(
                removal_records.len(),
                removal_records
                    .iter()
                    .map(|x| x.absolute_indices)
                    .unique()
                    .count()
            );

            let packed = RemovalRecordList::pack(removal_records.clone());
            let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

            assert_eq!(removal_records, unpacked);
        }
    }

    #[proptest]
    fn pack_unpack_identity_from_msa_and_records_tie_down(
        #[strategy((2u64)..=(u64::from(u8::MAX)))] _num_leafs_aocl: u64,
        #[strategy(MsaAndRecords::arbitrary_with((vec![(Digest::default(), Digest::default(), Digest::default()); 2], #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let removal_records = msa_and_records.unpacked_removal_records();

        for rr in &removal_records {
            assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
        }

        assert_eq!(
            removal_records.len(),
            removal_records
                .iter()
                .map(|x| x.absolute_indices)
                .unique()
                .count()
        );

        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

        prop_assert_eq!(removal_records, unpacked);
    }

    #[proptest]
    fn pack_unpack_identity_from_msa_and_records_small_aocl(
        #[strategy(0usize..30)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=(u64::from(u8::MAX)))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let removal_records = msa_and_records.unpacked_removal_records();
        for rr in &removal_records {
            assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
        }

        assert_eq!(
            removal_records.len(),
            removal_records
                .iter()
                .map(|x| x.absolute_indices)
                .unique()
                .count()
        );

        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

        prop_assert_eq!(removal_records, unpacked);
    }

    #[proptest(cases = 30)]
    fn pack_unpack_identity_from_msa_and_records_midi_aocl(
        #[strategy(0usize..30)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=(u64::from(u16::MAX)))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let removal_records = msa_and_records.unpacked_removal_records();
        for rr in &removal_records {
            assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
        }

        assert_eq!(
            removal_records.len(),
            removal_records
                .iter()
                .map(|x| x.absolute_indices)
                .unique()
                .count()
        );

        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

        prop_assert_eq!(removal_records, unpacked);
    }

    #[proptest(cases = 30)]
    fn pack_unpack_identity_from_msa_and_records_medium_aocl(
        #[strategy(0usize..30)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=(u64::from(u32::MAX)))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let removal_records = msa_and_records.unpacked_removal_records();
        for rr in &removal_records {
            assert!(msa_and_records.mutator_set_accumulator.can_remove(rr));
        }

        assert_eq!(
            removal_records.len(),
            removal_records
                .iter()
                .map(|x| x.absolute_indices)
                .unique()
                .count()
        );

        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

        prop_assert_eq!(removal_records, unpacked);
    }

    #[proptest(cases = 30)]
    fn pack_unpack_identity_from_msa_and_records_big_aocl(
        #[strategy(0usize..10)] _num_removals: usize,
        #[strategy((#_num_removals as u64)..=(u64::MAX / 2))] _num_leafs_aocl: u64,
        #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
        _removables: Vec<(Digest, Digest, Digest)>,
        #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
        msa_and_records: MsaAndRecords,
    ) {
        let removal_records = msa_and_records.unpacked_removal_records();
        let packed = RemovalRecordList::pack(removal_records.clone());
        let unpacked = RemovalRecordList::try_unpack(packed).unwrap();

        prop_assert_eq!(removal_records, unpacked);
    }

    mod try_unpack_no_crash {
        use proptest::collection;
        use proptest::prop_assume;

        use super::*;

        #[test]
        fn try_unpack_big_ais() {
            let absolute_indices =
                AbsoluteIndexSet::new_raw(u128::MAX, [u32::MAX; NUM_TRIALS as usize]);
            let removal_record = RemovalRecord {
                absolute_indices,
                target_chunks: ChunkDictionary::empty(),
            };

            let removal_records = vec![removal_record];

            // Ensure no crash, and that an error is returned.
            assert!(RemovalRecordList::try_unpack(removal_records).is_err());
        }

        #[test]
        fn too_many_chunks() {
            let absolute_indices_with_one_chunk_idx =
                AbsoluteIndexSet::new_raw(0, [0; NUM_TRIALS as usize]);
            for num_rrs in 1..4 {
                for num_chunks in 2..5 {
                    let too_many_chunk_elements = (0..num_chunks)
                        .map(|i| {
                            (
                                i as u64,
                                (MmrMembershipProof::new(vec![]), Chunk::empty_chunk()),
                            )
                        })
                        .collect_vec();
                    let removal_record = RemovalRecord {
                        absolute_indices: absolute_indices_with_one_chunk_idx,
                        target_chunks: ChunkDictionary::new(too_many_chunk_elements),
                    };
                    let removal_records = vec![removal_record.clone(); num_rrs];

                    // Ensure no crash, and that an error is returned.
                    assert!(RemovalRecordList::try_unpack(removal_records).is_err());
                }
            }
        }

        #[proptest]
        fn arbitrary_chunk_dict(
            #[strategy(arb())] item: Digest,
            #[strategy(arb())] sr: Digest,
            #[strategy(arb())] rp: Digest,
            #[strategy(arb())] leaf_index_u16: u16,
            #[strategy(0usize..8)] num_removal_records: usize,
            #[strategy(1usize..20)] _num_chunk_dictionary_entries: usize,
            #[strategy(collection::vec(arb::<Digest>(), #_num_chunk_dictionary_entries))]
            auth_path_nodes: Vec<Digest>,
            #[strategy(collection::vec(arb::<u16>(), #_num_chunk_dictionary_entries))]
            chunk_indices: Vec<u16>,
            #[strategy(collection::vec(arb::<u16>(), #_num_chunk_dictionary_entries))]
            relative_indices: Vec<u16>,
        ) {
            let absolute_indices =
                AbsoluteIndexSet::compute(item, sr, rp, u64::from(leaf_index_u16));
            let chunk_dictionary = chunk_indices
                .into_iter()
                .map(|chk_idx| {
                    (
                        u64::from(chk_idx),
                        (
                            MmrMembershipProof::new(auth_path_nodes.clone()),
                            Chunk {
                                relative_indices: relative_indices
                                    .clone()
                                    .into_iter()
                                    .map(u32::from)
                                    .collect_vec(),
                            },
                        ),
                    )
                })
                .collect_vec();
            let chunk_dictionary = ChunkDictionary::new(chunk_dictionary);
            let removal_record = RemovalRecord {
                absolute_indices,
                target_chunks: chunk_dictionary,
            };
            let removal_records = vec![removal_record.clone(); num_removal_records];

            // Ensure no crash
            let _ = RemovalRecordList::try_unpack(removal_records);
        }

        #[proptest]
        fn repeated_tree_height(
            #[strategy(1usize..10)] _num_removals: usize,
            #[strategy(0usize..#_num_removals)] insert_index: usize,
            #[strategy((#_num_removals as u64)..=(u64::from(u16::MAX)))] _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
            _removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
        ) {
            let mut packed = msa_and_records.packed_removal_records();
            prop_assume!(packed[0].target_chunks.len() > insert_index);
            prop_assert!(RemovalRecordList::try_unpack(packed.clone()).is_ok());

            let cloned_entry = packed[0].target_chunks.dictionary[insert_index].clone();
            packed[0]
                .target_chunks
                .dictionary
                .insert(insert_index, cloned_entry);
            prop_assert!(RemovalRecordList::try_unpack(packed).is_err());
        }

        #[proptest(cases = 40)]
        fn missing_tree_height(
            #[strategy(2usize..10)] _num_removals: usize,
            #[strategy(0usize..#_num_removals)] remove_index: usize,
            #[strategy((#_num_removals as u64)..=(u64::from(u16::MAX)))] _num_leafs_aocl: u64,
            #[strategy(vec((arb::<Digest>(), arb::<Digest>(), arb::<Digest>()), #_num_removals))]
            _removables: Vec<(Digest, Digest, Digest)>,
            #[strategy(MsaAndRecords::arbitrary_with((#_removables, #_num_leafs_aocl)))]
            msa_and_records: MsaAndRecords,
        ) {
            let mut packed = msa_and_records.packed_removal_records();
            prop_assert!(RemovalRecordList::try_unpack(packed.clone()).is_ok());
            prop_assume!(packed[0].target_chunks.len() > remove_index);

            packed[0].target_chunks.dictionary.remove(remove_index);

            // Ensure no panic. We cannot guarantee that the unpacking will
            // fail since the removing of a chunk might correspond to a valid
            // packed removal record list for a smaller number of AOCL leafs. In
            // that case, though, the later `can_remove` must fail.
            let res = RemovalRecordList::try_unpack(packed);
            if let Ok(unpacked) = res {
                let mut all_can_be_removed = true;
                for rr in unpacked {
                    all_can_be_removed = all_can_be_removed
                        && msa_and_records.mutator_set_accumulator.can_remove(&rr);
                }
                assert!(!all_can_be_removed);
            }
        }

        #[proptest]
        fn unpack_doesnt_crash_with_missing_chunk_dictionary_elements_multiple_leaf_index_ranges(
            #[strategy(arb())] item: Digest,
            #[strategy(arb())] sr: Digest,
            #[strategy(arb())] rp: Digest,
            #[strategy(arb())] leaf_index_u8: u8,
            #[strategy(arb())] leaf_index_u16: u16,
            #[strategy(arb())] leaf_index_u32: u32,
            #[strategy(arb())] leaf_index_u64: u64,
            #[strategy(1usize..20)] num_removal_records: usize,
        ) {
            for leaf_index in [
                u64::from(leaf_index_u8),
                u64::from(leaf_index_u16),
                u64::from(leaf_index_u32),
                leaf_index_u64,
            ] {
                let absolute_indices = AbsoluteIndexSet::compute(item, sr, rp, leaf_index);
                let removal_record = RemovalRecord {
                    absolute_indices,
                    target_chunks: ChunkDictionary::empty(),
                };
                let removal_records = vec![removal_record.clone(); num_removal_records];

                // Ensure no crash
                let _ = RemovalRecordList::try_unpack(removal_records);
            }
        }

        #[test]
        fn regression_test_panic_in_try_unpack_1() {
            let removal_record = RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new_raw(
                    68472,
                    [
                        978335, 226333, 668833, 627770, 413862, 994662, 458634, 680471, 997337,
                        148763, 665905, 463593, 26385, 237585, 835622, 175521, 711544, 353972,
                        33811, 609715, 863269, 922136, 987473, 682901, 17409, 445788, 483752,
                        363860, 926460, 577500, 383384, 243946, 140714, 940568, 297642, 259922,
                        386140, 510946, 0, 956594, 420304, 1010108, 492536, 722694, 222513,
                    ],
                ),
                target_chunks: ChunkDictionary { dictionary: vec![] },
            };
            let _ = RemovalRecordList::try_unpack(vec![removal_record]); // no crash
        }

        #[test]
        fn regression_test_panic_in_try_unpack_2() {
            let removal_record = RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new_raw(
                    52520,
                    [
                        243715, 749021, 203233, 104747, 535122, 429290, 1016297, 185670, 125329,
                        208916, 477068, 341103, 39312, 911863, 972772, 52083, 0, 583734, 1022257,
                        621991, 402132, 474284, 981738, 443185, 769145, 451043, 888760, 871963,
                        698065, 557752, 118661, 534719, 633834, 566737, 621507, 124789, 848175,
                        647222, 532410, 693591, 312466, 766203, 730772, 876359, 367876,
                    ],
                ),
                target_chunks: ChunkDictionary {
                    dictionary: vec![(
                        12,
                        // 21,
                        (
                            MmrMembershipProof {
                                authentication_path: [].to_vec(),
                            },
                            Chunk {
                                relative_indices: [].to_vec(),
                            },
                        ),
                    )],
                },
            };
            let _ = RemovalRecordList::try_unpack(vec![removal_record]); // no crash
        }

        #[test]
        fn regression_test_panic_in_try_unpack_3() {
            let removal_record = RemovalRecord {
                absolute_indices: AbsoluteIndexSet::new_raw(
                    1u128 << 64,
                    [
                        978335, 226333, 668833, 627770, 413862, 994662, 458634, 680471, 997337,
                        148763, 665905, 463593, 26385, 237585, 835622, 175521, 711544, 353972,
                        33811, 609715, 863269, 922136, 987473, 682901, 17409, 445788, 483752,
                        363860, 926460, 577500, 383384, 243946, 140714, 940568, 297642, 259922,
                        386140, 510946, 0, 956594, 420304, 1010108, 492536, 722694, 222513,
                    ],
                ),
                target_chunks: ChunkDictionary { dictionary: vec![] },
            };
            let _ = RemovalRecordList::try_unpack(vec![removal_record]); // no crash
        }

        #[proptest(cases = 30)]
        fn unpack_cannot_crash(
            #[strategy(1usize..20)] _num_records: usize,
            #[strategy(arb::<u64>())] _num_leafs_aocl: u64,
            #[strategy(RemovalRecord::arbitrary_synchronized_set(#_num_leafs_aocl, #_num_records))]
            removal_records: Vec<RemovalRecord>,
        ) {
            // Attempt to unpack a list of removal records that are not packed.
            // Ensure no crash.
            let _ = RemovalRecordList::try_unpack(removal_records); // no crash
        }

        #[proptest]
        fn try_unpack_repeated_tree_height() {}

        #[proptest]
        fn removal_record_list_is_inconsistent_or_convert_to_vec_succeeds(
            #[strategy(vec(arb(), 0usize..10))] index_sets: Vec<AbsoluteIndexSet>,
            #[strategy(vec(vec(arb(), 0..32_usize), 0..{NUM_TRIALS as usize}))]
            authentication_structures: Vec<Vec<Digest>>,
            #[strategy(vec(arb(), 0usize..(NUM_TRIALS as usize)))] chunks: Vec<Chunk>,
            #[strategy(arb())] num_leafs_aocl: u64,
        ) {
            let removal_record_list = RemovalRecordList {
                index_sets,
                authentication_structures,
                chunks,
                num_leafs_aocl,
            };

            if removal_record_list.validate_consistency().is_ok() {
                RemovalRecordList::convert_to_vec(removal_record_list); // no crash
            }
        }

        fn removal_record_list_with_inconsistent_chunks() -> RemovalRecordList {
            let index_sets = vec![AbsoluteIndexSet::new([0_u128; NUM_TRIALS as usize])];
            let authentication_structures = vec![];
            let chunks = vec![Chunk::empty_chunk(); 2];
            let num_leafs_aocl = 2_u64;
            RemovalRecordList {
                index_sets,
                authentication_structures,
                chunks,
                num_leafs_aocl,
            }
        }

        fn removal_record_list_with_inconsistent_number_of_authentication_structures(
        ) -> RemovalRecordList {
            let index_sets = vec![AbsoluteIndexSet::new([0_u128; NUM_TRIALS as usize])];
            let authentication_structures = vec![vec![]; 10];
            let chunks = vec![Chunk::empty_chunk(); 1];
            let num_leafs_aocl = 9_u64;
            RemovalRecordList {
                index_sets,
                authentication_structures,
                chunks,
                num_leafs_aocl,
            }
        }

        fn removal_record_list_with_inconsistent_authentication_structure_lengths(
        ) -> RemovalRecordList {
            let mut rng = rng();
            let index_sets = vec![AbsoluteIndexSet::new([0_u128; NUM_TRIALS as usize])];
            let authentication_structures = vec![vec![rng.random::<Digest>(); 20]; 1];
            let chunks = vec![Chunk::empty_chunk(); 1];
            let num_leafs_aocl = 9_u64;
            RemovalRecordList {
                index_sets,
                authentication_structures,
                chunks,
                num_leafs_aocl,
            }
        }

        #[test]
        fn all_inconsistencies_can_be_triggered() {
            let mut observed_inconsistency_codes = vec![];
            for function in [
                removal_record_list_with_inconsistent_chunks,
                removal_record_list_with_inconsistent_number_of_authentication_structures,
                removal_record_list_with_inconsistent_authentication_structure_lengths,
            ] {
                observed_inconsistency_codes.push(function().validate_consistency().unwrap_err());
            }

            let all_inconsistency_codes = RemovalRecordListInconsistency::iter().collect_vec();

            assert_eq!(
                all_inconsistency_codes
                    .into_iter()
                    .map(|v| mem::discriminant(&v))
                    .collect_vec(),
                observed_inconsistency_codes
                    .into_iter()
                    .map(|v| mem::discriminant(&v))
                    .collect_vec()
            );
        }

        fn inconsistent_absolute_index_set() -> BoxedStrategy<AbsoluteIndexSet> {
            (arb::<u128>(), [arb::<u32>(); NUM_TRIALS as usize])
                .prop_map(|(minimum, distances)| AbsoluteIndexSet::new_raw(minimum, distances))
                .boxed()
        }

        #[proptest]
        fn removal_record_list_is_inconsistent_or_convert_to_vec_succeeds_inconsistent_ais(
            #[strategy(vec(inconsistent_absolute_index_set(), 0usize..10))] index_sets: Vec<
                AbsoluteIndexSet,
            >,
            #[strategy(vec(vec(arb(), 0..32_usize), 0..{NUM_TRIALS as usize}))]
            authentication_structures: Vec<Vec<Digest>>,
            #[strategy(vec(arb(), 0usize..(NUM_TRIALS as usize)))] chunks: Vec<Chunk>,
            #[strategy(arb())] num_leafs_aocl: u64,
        ) {
            let removal_record_list = RemovalRecordList {
                index_sets,
                authentication_structures,
                chunks,
                num_leafs_aocl,
            };

            if removal_record_list.validate_consistency().is_ok() {
                RemovalRecordList::convert_to_vec(removal_record_list); // no crash
            }
        }
    }
}
