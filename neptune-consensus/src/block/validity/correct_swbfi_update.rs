//! Rule 2.e for the current block, restricted to the removals: from the
//! mutator set the block's transaction is built on, setting the indices of
//! its inputs yields the mutator set with this hash. Rules 2.a, 2.b and 2.d
//! come along: the chunks the witness supplies are exactly what they are
//! about.
//!
//! The claim goes in the block's appendix, so its proof is consumed by the
//! block proof. Its public input binds the mutator set by hash and its
//! output the inputs by a commitment to their index sets, so that a verifier
//! that holds neither the chunks nor the mutator set can still tell what was
//! proven. Light nodes check the tip's update from it on the host machine,
//! and `PredecessorIsValid` checks the predecessor's from the predecessor's
//! copy. It is a leaf of the aggregation tree; the leaf count in its output
//! says so.

use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::RemovalRecord;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::field;
use tasm_lib::library::Library;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;

use super::mutator_set_hash::MutatorSetHash;
use super::mutator_set_hash_after_removals::MutatorSetHashAfterRemovals;
use super::removal_index_commitment::RemovalIndexCommitment;
use super::swbfi_peaks_after_removals::SwbfiPeaksAfterRemovals;
use crate::block::block_validation_error::BlockValidationRule;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
pub struct CorrectSwbfiUpdateWitness {
    /// The block transaction's inputs in the packed list's structure, with
    /// their chunks unpacked.
    inputs: Vec<RemovalRecord>,

    /// The mutator set the transaction is built on.
    mutator_set: MutatorSetAccumulator,
}

impl CorrectSwbfiUpdateWitness {
    /// The witness for these packed inputs.
    pub fn new(inputs: Vec<RemovalRecord>, mutator_set: MutatorSetAccumulator) -> Self {
        Self {
            inputs: SwbfiPeaksAfterRemovals::witness_form(inputs, &mutator_set),
            mutator_set,
        }
    }

    pub fn inputs(&self) -> &[RemovalRecord] {
        &self.inputs
    }

    /// The inputs in the packed list's form, which the host-side update
    /// takes.
    pub fn packed_inputs(&self) -> Vec<RemovalRecord> {
        SwbfiPeaksAfterRemovals::packed_form(self.inputs.clone(), &self.mutator_set)
    }

    pub fn mutator_set(&self) -> &MutatorSetAccumulator {
        &self.mutator_set
    }

    /// The claim about this witness, as a block's appendix carries it.
    pub fn versioned_claim(&self) -> Claim {
        self.claim().about_version(
            ConsensusRuleSet::HardforkDelta
                .triton_proof_version()
                .version(),
        )
    }
}

impl SecretWitness for CorrectSwbfiUpdateWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(CorrectSwbfiUpdate::claim_input(&self.mutator_set))
    }

    fn output(&self) -> Vec<BFieldElement> {
        let mutator_set_after =
            SwbfiPeaksAfterRemovals::apply_removals(&self.packed_inputs(), &self.mutator_set);
        let peaks = RemovalIndexCommitment::peaks(&self.inputs);
        [
            vec![
                bfe!(CorrectSwbfiUpdate::NUM_LEAVES),
                bfe!(self.inputs.len() as u64),
            ],
            mutator_set_after.hash().values().to_vec(),
            vec![bfe!(peaks.len() as u64)],
            peaks.iter().flat_map(|peak| peak.values()).collect(),
        ]
        .concat()
    }

    fn program(&self) -> Program {
        CorrectSwbfiUpdate.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );
        nondeterminism.individual_tokens =
            MutatorSetHashAfterRemovals::divined_tokens(&self.inputs, &self.mutator_set);

        nondeterminism
    }
}

/// Input: the hash of the mutator set the transaction is built on. Output:
/// the number of leaves and of index sets covered, the hash of the mutator
/// set after the inputs' removals, then the peaks of the MMR over the index
/// sets, as a list.
#[derive(
    Debug, Clone, Copy, Default, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct CorrectSwbfiUpdate;

impl CorrectSwbfiUpdate {
    /// The leaves of the aggregation tree this claim covers: itself.
    pub const NUM_LEAVES: u64 = 1;

    /// The claim for a block's inputs on this mutator set, as its appendix
    /// carries it.
    pub fn claim(inputs: &[RemovalRecord], mutator_set: &MutatorSetAccumulator) -> Claim {
        CorrectSwbfiUpdateWitness::new(inputs.to_vec(), mutator_set.clone()).versioned_claim()
    }

    /// The claim's input for this mutator set: what a block binds, without
    /// computing the output.
    pub fn claim_input(mutator_set: &MutatorSetAccumulator) -> Vec<BFieldElement> {
        mutator_set.hash().reversed().values().to_vec()
    }
}

impl TritonProgram for CorrectSwbfiUpdate {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_witness = library.import(Box::new(VerifyNdSiIntegrity::<
            CorrectSwbfiUpdateWitness,
        >::default()));
        let mutator_set_hash = library.import(Box::new(MutatorSetHash));
        let hash_after_removals = library.import(Box::new(MutatorSetHashAfterRemovals));
        let commitment = library.import(Box::new(RemovalIndexCommitment));

        let write_peaks = "correct_swbfi_update_write_peaks".to_string();

        let code = triton_asm!(
            read_io {Digest::LEN}
            // _ [mutator_set_hash]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            dup 0 call {audit_witness} pop 1
            // _ [mutator_set_hash] *w

            dup 0 {&field!(CorrectSwbfiUpdateWitness::mutator_set)}
            call {mutator_set_hash}
            // _ [mutator_set_hash] *w [witness_mutator_set_hash]

            pick 10 pick 10 pick 10 pick 10 pick 10
            // _ *w [witness_mutator_set_hash] [mutator_set_hash]

            assert_vector error_id {BlockValidationRule::TransactionMutatorSetMismatch.error_id()}
            pop {Digest::LEN}
            // _ *w

            dup 0 {&field!(CorrectSwbfiUpdateWitness::inputs)}
            call {commitment}
            place 1
            // _ *peaks *w

            dup 0 {&field!(CorrectSwbfiUpdateWitness::inputs)}
            dup 1 {&field!(CorrectSwbfiUpdateWitness::mutator_set)}
            call {hash_after_removals}
            // _ *peaks *w [mutator_set_after_removals_hash]

            push {Self::NUM_LEAVES} write_io 1
            dup 5 {&field!(CorrectSwbfiUpdateWitness::inputs)} read_mem 1 pop 1 write_io 1
            write_io {Digest::LEN}
            pop 1
            // _ *peaks

            dup 0 read_mem 1 pop 1
            dup 0 write_io 1
            push {Digest::LEN} mul dup 1 add
            // _ *peaks *peaks_end

            swap 1 call {write_peaks}
            // _ *peaks_end *peaks_end

            pop 2
            halt

            // INVARIANT: _ *end *peak[i]_previous_word
            {write_peaks}:
                dup 1 dup 1 eq skiz return
                addi {Digest::LEN} read_mem {Digest::LEN}
                // _ *end [peak[i]] *peak[i]_previous_word

                addi {Digest::LEN} place {Digest::LEN}
                // _ *end *peak[i + 1]_previous_word [peak[i]]

                write_io {Digest::LEN}
                recurse

            {&library.all_imports()}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(super) mod tests {
    use neptune_mutator_set::active_window::ActiveWindow;
    use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use neptune_mutator_set::removal_record::chunk::Chunk;
    use neptune_mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use neptune_mutator_set::removal_record::removal_record_list::RemovalRecordList;
    use neptune_mutator_set::shared::CHUNK_SIZE;
    use neptune_mutator_set::shared::WINDOW_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::twenty_first::prelude::Mmr;
    use tasm_lib::twenty_first::prelude::MmrMembershipProof;
    use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

    use super::super::chunk_insertions::ChunkInsertions;
    use super::super::chunk_witness::tests::random_msa_and_records;
    use super::super::chunk_witness::ChunkWitness;
    use super::super::mutate_swbfi_peaks::MutateSwbfiPeaks;
    use super::super::resolve_chunk_indices::ResolveChunkIndices;
    use super::super::window_after_removals::WindowAfterRemovals;
    use super::*;
    use crate::block::mutator_set_update::MutatorSetUpdate;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;

    impl TritonProgramSpecification for CorrectSwbfiUpdate {
        fn source(&self) {
            let mutator_set_hash = tasm::tasmlib_io_read_stdin___digest();
            let witness: CorrectSwbfiUpdateWitness =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);

            assert_eq!(mutator_set_hash, witness.mutator_set.hash());
            let index_set_peaks = RemovalIndexCommitment::peaks(&witness.inputs);

            let peaks = SwbfiPeaksAfterRemovals::verify(&witness.inputs, &witness.mutator_set);
            let window = WindowAfterRemovals::verify(&witness.inputs, &witness.mutator_set);
            let mut mutator_set_after = witness.mutator_set.clone();
            mutator_set_after.swbf_inactive =
                MmrAccumulator::init(peaks, witness.mutator_set.swbf_inactive.num_leafs());
            mutator_set_after.swbf_active = window;

            tasm::tasmlib_io_write_to_stdout___bfe(bfe!(Self::NUM_LEAVES));
            tasm::tasmlib_io_write_to_stdout___bfe(bfe!(witness.inputs.len() as u64));
            tasm::tasmlib_io_write_to_stdout___digest(mutator_set_after.hash());
            tasm::tasmlib_io_write_to_stdout___bfe(bfe!(index_set_peaks.len() as u64));
            for peak in index_set_peaks {
                tasm::tasmlib_io_write_to_stdout___digest(peak);
            }
        }
    }

    /// A witness with this many packed inputs, and the mutator set they
    /// remove from. The fixture's active window is random; the mutator set
    /// produces a sorted multiset of indices inside the window, so it is
    /// made one.
    fn witness(num_inputs: usize, seed: u64) -> CorrectSwbfiUpdateWitness {
        witness_on_aocl(num_inputs, seed, 1 << 20)
    }

    /// [witness] on an AOCL of this size: a small one keeps the inputs'
    /// index windows near the active window.
    fn witness_on_aocl(num_inputs: usize, seed: u64, aocl_size: u64) -> CorrectSwbfiUpdateWitness {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut msa_and_records = random_msa_and_records(&mut rng, num_inputs, aocl_size);
        let inputs = RemovalRecordList::pack(
            msa_and_records.unpacked_removal_records(),
            ConsensusRuleSet::HardforkDelta.allow_big_chunks(),
        );
        let window = &mut msa_and_records.mutator_set_accumulator.swbf_active;
        let mut sbf = window
            .sbf
            .iter()
            .map(|index| index % WINDOW_SIZE)
            .collect::<Vec<_>>();
        sbf.sort_unstable();
        *window = ActiveWindow::from_vec_u32(sbf);

        // The archival rules 2.a and 2.b must hold for the fixture.
        let mutator_set = msa_and_records.mutator_set_accumulator;
        let unpacked = RemovalRecordList::try_unpack(
            inputs.clone(),
            ConsensusRuleSet::HardforkDelta.allow_big_chunks(),
        )
        .expect("fixture inputs must unpack");
        assert!(
            unpacked.iter().all(|record| mutator_set.can_remove(record)),
            "fixture inputs must be removable"
        );

        CorrectSwbfiUpdateWitness::new(inputs, mutator_set)
    }

    /// The mutator set the archival update computes for the witness's
    /// inputs.
    pub(in crate::block::validity) fn archival_mutator_set_after(
        witness: &CorrectSwbfiUpdateWitness,
    ) -> MutatorSetAccumulator {
        let unpacked =
            SwbfiPeaksAfterRemovals::unpacked_records(&witness.inputs, &witness.mutator_set)
                .unwrap();
        let mut mutator_set = witness.mutator_set.clone();
        MutatorSetUpdate::new(unpacked, vec![])
            .apply_to_accumulator(&mut mutator_set)
            .expect("archival update must apply");
        mutator_set
    }

    #[test]
    fn honest_witness_is_accepted_and_outputs_the_mutator_set_hash() {
        for (num_inputs, seed) in [(1, 0), (2, 1), (5, 2)] {
            let witness = witness(num_inputs, seed);
            let input = witness.standard_input();
            let nondeterminism = witness.nondeterminism();

            let rust_output = CorrectSwbfiUpdate
                .run_rust(&input, nondeterminism.clone())
                .unwrap();
            let tasm_output = CorrectSwbfiUpdate.run_tasm(&input, nondeterminism).unwrap();
            assert_eq!(rust_output, tasm_output, "{num_inputs} inputs");
            assert_eq!(witness.output(), tasm_output, "{num_inputs} inputs");

            // The hash is that of the mutator set the archival update
            // computes.
            let expected_hash = archival_mutator_set_after(&witness).hash().values();
            assert_eq!(expected_hash, tasm_output[2..7], "{num_inputs} inputs");
        }
    }

    #[test]
    fn peaks_change_unless_no_index_lies_in_the_inactive_swbf() {
        let witness = witness(5, 3);
        let before = witness.mutator_set.swbf_inactive.peaks();
        let after =
            SwbfiPeaksAfterRemovals::apply_removals(&witness.packed_inputs(), &witness.mutator_set)
                .swbf_inactive
                .peaks();
        assert_ne!(before, after, "the fixture must touch the inactive SWBF");
    }

    #[test]
    fn other_mutator_set_hash_is_rejected() {
        let witness = witness(2, 4);
        let mut input = witness.standard_input();
        input.individual_tokens[0] += bfe!(1);

        CorrectSwbfiUpdate
            .test_assertion_failure(
                input,
                witness.nondeterminism(),
                &[BlockValidationRule::TransactionMutatorSetMismatch.error_id()],
            )
            .unwrap();
    }

    fn assert_rejects(witness: &CorrectSwbfiUpdateWitness, error_id: i128) {
        CorrectSwbfiUpdate
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[error_id],
            )
            .unwrap();
    }

    fn is_tree_with_chunk(entry: &(u64, (MmrMembershipProof, Chunk))) -> bool {
        entry.0 < RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET
    }

    /// A witness whose first input's chunk dictionary holds a chunk of the
    /// inactive SWBF.
    fn witness_with_chunks() -> CorrectSwbfiUpdateWitness {
        let witness = witness(3, 7);
        let entries = witness.inputs[0].target_chunks.clone().into_inner();
        assert!(
            entries.iter().any(is_tree_with_chunk),
            "the test data must exercise the rules on chunks"
        );
        witness
    }

    /// [witness_with_chunks] with its chunk dictionary entries modified.
    fn witness_with_modified_entries(
        modify: impl FnOnce(&mut Vec<(u64, (MmrMembershipProof, Chunk))>),
    ) -> CorrectSwbfiUpdateWitness {
        let mut witness = witness_with_chunks();
        let mut entries = witness.inputs[0].target_chunks.clone().into_inner();
        modify(&mut entries);
        witness.inputs[0].target_chunks = ChunkDictionary::new_in_given_order(entries);
        witness
    }

    #[test]
    fn input_carrying_a_tampered_chunk_is_rejected() {
        let witness = witness_with_modified_entries(|entries| {
            let position = entries.iter().position(is_tree_with_chunk).unwrap();
            entries[position].1 .1.insert(0);
        });
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// At most this many of the items, spread evenly, first and last
    /// included.
    fn spread<T: Clone>(items: Vec<T>, at_most: usize) -> Vec<T> {
        if items.len() <= at_most {
            return items;
        }
        (0..at_most)
            .map(|i| items[i * (items.len() - 1) / (at_most - 1)].clone())
            .collect()
    }

    /// The tree entries of the witness's inputs that hold a path list, as
    /// input and entry positions.
    fn tree_entries(witness: &CorrectSwbfiUpdateWitness) -> Vec<(usize, usize)> {
        witness
            .inputs
            .iter()
            .enumerate()
            .flat_map(|(input, record)| {
                record
                    .target_chunks
                    .iter()
                    .enumerate()
                    .filter(|(_, (height, _))| {
                        *height < 2 * RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET
                    })
                    .map(move |(entry, _)| (input, entry))
            })
            .collect()
    }

    /// The chunk dictionary entries of the witness's inputs that hold a
    /// chunk, as input and entry positions.
    fn chunk_entries(witness: &CorrectSwbfiUpdateWitness) -> Vec<(usize, usize)> {
        witness
            .inputs
            .iter()
            .enumerate()
            .flat_map(|(input, record)| {
                record
                    .target_chunks
                    .iter()
                    .enumerate()
                    .filter(|(_, (height, _))| {
                        *height < RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET
                            || *height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT
                    })
                    .map(move |(entry, _)| (input, entry))
            })
            .collect()
    }

    /// The witness with one chunk dictionary entry of one input modified.
    fn with_modified_entry(
        witness: &CorrectSwbfiUpdateWitness,
        input: usize,
        entry: usize,
        modify: impl FnOnce(&mut (u64, (MmrMembershipProof, Chunk))),
    ) -> CorrectSwbfiUpdateWitness {
        let mut witness = witness.clone();
        let mut entries = witness.inputs[input].target_chunks.clone().into_inner();
        modify(&mut entries[entry]);
        witness.inputs[input].target_chunks = ChunkDictionary::new_in_given_order(entries);
        witness
    }

    /// A tree entry's height is load-bearing: one higher or one lower, the
    /// tree is not a tree of the inactive SWBF, or the entries are out of
    /// order, or the estimate of the SWBF's shape is off. Rule 2.a or 2.b
    /// rejects, whichever comes first.
    #[test]
    fn every_tree_entry_height_is_checked() {
        let honest = witness_with_chunks();
        let offset = RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
        let entries = tree_entries(&honest);
        assert!(!entries.is_empty(), "the test data must hold trees");
        let mut checked = 0;
        for (input, entry) in entries {
            let height = honest.inputs[input]
                .target_chunks
                .iter()
                .nth(entry)
                .unwrap()
                .0;
            let same_kind = |other: u64| (other < offset) == (height < offset);
            for other in [height.wrapping_sub(1), height + 1] {
                if !same_kind(other) || other >= 2 * offset {
                    continue;
                }
                let witness = with_modified_entry(&honest, input, entry, |entry| entry.0 = other);
                CorrectSwbfiUpdate
                    .test_assertion_failure(
                        witness.standard_input(),
                        witness.nondeterminism(),
                        &[
                            BlockValidationRule::RemovalRecordsUnpackFailure.error_id(),
                            BlockValidationRule::RemovalRecordsValidity.error_id(),
                        ],
                    )
                    .unwrap_or_else(|error| panic!("height {height} -> {other}: {error:?}"));
                checked += 1;
            }
        }
        assert!(checked > 0);
    }

    /// Path digests are load-bearing in every word: a spread of digests
    /// over every tree's path list, at every word each. The snippet's own
    /// test covers every digest.
    #[test]
    fn every_word_of_spread_path_digests_is_rejected() {
        let honest = witness_with_chunks();
        let digests = tree_entries(&honest)
            .into_iter()
            .flat_map(|(input, entry)| {
                let path_len = honest.inputs[input]
                    .target_chunks
                    .iter()
                    .nth(entry)
                    .unwrap()
                    .1
                     .0
                    .authentication_path
                    .len();
                (0..path_len).map(move |digest| (input, entry, digest))
            })
            .collect::<Vec<_>>();
        assert!(!digests.is_empty(), "the test data must hold paths");
        for (input, entry, digest) in spread(digests, 12) {
            for word in 0..Digest::LEN {
                let witness = with_modified_entry(&honest, input, entry, |entry| {
                    entry.1 .0.authentication_path[digest].0[word] += bfe!(1);
                });
                assert_rejects(
                    &witness,
                    BlockValidationRule::RemovalRecordsValidity.error_id(),
                );
            }
        }
    }

    /// Every word of every inactive-SWBF peak whose tree holds chunks is
    /// load-bearing.
    #[test]
    fn every_word_of_every_peak_with_chunks_is_rejected() {
        let honest = witness_with_chunks();
        let inputs = &honest.inputs;
        let mutator_set = &honest.mutator_set;
        let swbfi_leaf_count = mutator_set.swbf_inactive.num_leafs();
        let chunk_indices = ResolveChunkIndices::chunk_indices_below(inputs, swbfi_leaf_count);
        let insertions = ChunkInsertions::insertions(
            inputs,
            &chunk_indices,
            SwbfiPeaksAfterRemovals::window_start(mutator_set),
        );
        let peaks_with_chunks = MutateSwbfiPeaks::runs(
            swbfi_leaf_count,
            &chunk_indices,
            &ChunkWitness::chunks(inputs),
            &insertions,
        )
        .into_iter()
        .enumerate()
        .filter(|(_, (_, old_leafs, _))| !old_leafs.is_empty())
        .map(|(peak, _)| peak)
        .collect::<Vec<_>>();
        assert!(
            !peaks_with_chunks.is_empty(),
            "the test data must hold chunks"
        );
        for (peak, word) in peaks_with_chunks
            .into_iter()
            .flat_map(|p| (0..Digest::LEN).map(move |w| (p, w)))
        {
            let mut witness = honest.clone();
            let swbfi = &witness.mutator_set.swbf_inactive;
            let mut peaks = swbfi.peaks();
            peaks[peak].0[word] += bfe!(1);
            witness.mutator_set.swbf_inactive = MmrAccumulator::init(peaks, swbfi.num_leafs());
            assert_rejects(
                &witness,
                BlockValidationRule::RemovalRecordsValidity.error_id(),
            );
        }
    }

    /// Chunk contents are load-bearing: for a spread of chunks, an entry
    /// added, and for a spread of their entries, one changed and one
    /// removed. The peak mutation's own test covers every entry.
    #[test]
    fn every_change_to_spread_chunk_entries_is_rejected() {
        let honest = witness_with_chunks();
        let chunks = spread(chunk_entries(&honest), 8);
        assert!(!chunks.is_empty(), "the test data must hold chunks");
        let rejects = |witness: &CorrectSwbfiUpdateWitness| {
            assert_rejects(
                witness,
                BlockValidationRule::RemovalRecordsValidity.error_id(),
            );
        };
        for (input, entry) in chunks {
            rejects(&with_modified_entry(&honest, input, entry, |entry| {
                entry.1 .1.relative_indices.insert(0, 0);
            }));
            let num_entries = honest.inputs[input]
                .target_chunks
                .iter()
                .nth(entry)
                .unwrap()
                .1
                 .1
                .relative_indices
                .len();
            for index in spread((0..num_entries).collect(), 3) {
                rejects(&with_modified_entry(&honest, input, entry, |entry| {
                    let chunk = &mut entry.1 .1.relative_indices;
                    chunk[index] = if chunk[index] == 0 {
                        1
                    } else {
                        chunk[index] - 1
                    };
                }));
                rejects(&with_modified_entry(&honest, input, entry, |entry| {
                    entry.1 .1.relative_indices.remove(index);
                }));
            }
        }
    }

    #[test]
    fn input_carrying_a_tampered_path_is_rejected() {
        let witness = witness_with_modified_entries(|entries| {
            let position = entries.iter().position(is_tree_with_chunk).unwrap();
            let path = &mut entries[position].1 .0.authentication_path;
            path[0] = StdRng::seed_from_u64(0).random();
        });
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn input_missing_a_chunk_is_rejected() {
        // The chunk goes; its tree's paths stay.
        let witness = witness_with_modified_entries(|entries| {
            let position = entries.iter().position(is_tree_with_chunk).unwrap();
            entries[position].0 += RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET;
            entries[position].1 .1 = Chunk::empty_chunk();
        });
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn input_carrying_a_superfluous_chunk_is_rejected() {
        let witness = witness_with_modified_entries(|entries| {
            entries.push((
                RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT,
                (MmrMembershipProof::new(vec![]), Chunk::empty_chunk()),
            ));
        });
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsUnpackFailure.error_id(),
        );
    }

    #[test]
    fn input_trees_not_increasing_is_rejected() {
        // A tree repeated: the heights no longer strictly increase.
        let witness = witness_with_modified_entries(|entries| {
            let first = entries.iter().position(is_tree_with_chunk).unwrap();
            let duplicate = entries[first].clone();
            entries.insert(first + 1, duplicate);
        });
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsUnpackFailure.error_id(),
        );
    }

    /// The witness with one input's indices set in its chunks: that input is
    /// The witness's tokens with the one at this position changed.
    fn tampered_tokens(witness: &CorrectSwbfiUpdateWitness, position: usize) -> NonDeterminism {
        let mut nondeterminism = witness.nondeterminism();
        nondeterminism.individual_tokens[position] += bfe!(1);
        nondeterminism
    }

    fn assert_rejects_tokens(witness: &CorrectSwbfiUpdateWitness, nondeterminism: NonDeterminism) {
        assert!(CorrectSwbfiUpdate
            .run_tasm(&witness.standard_input(), nondeterminism)
            .is_err());
    }

    /// The number of tokens the window insertion reads, at the end of the
    /// witness's tokens, and the number the peak mutation reads before them.
    fn window_and_mutation_token_counts(witness: &CorrectSwbfiUpdateWitness) -> (usize, usize) {
        use super::super::chunk_insertions::ChunkInsertions;
        let inputs = &witness.inputs;
        let mutator_set = &witness.mutator_set;
        let window = WindowAfterRemovals::divined_tokens(inputs, mutator_set).len();

        let estimate = ChunkWitness::swbfi_leaf_count_estimate(inputs);
        let swbfi_leaf_count = mutator_set.swbf_inactive.num_leafs();
        let mut chunk_indices =
            ResolveChunkIndices::chunk_indices_below(inputs, estimate.max(swbfi_leaf_count));
        chunk_indices.truncate(ChunkWitness::num_chunks(inputs));
        let window_start = SwbfiPeaksAfterRemovals::window_start(mutator_set);
        let insertions = ChunkInsertions::insertions(inputs, &chunk_indices, window_start);
        let mutation = MutateSwbfiPeaks::divined_tokens(
            estimate,
            &chunk_indices,
            &ChunkWitness::chunks(inputs),
            &insertions,
        )
        .len();
        (window, mutation)
    }

    #[test]
    fn tampered_tokens_are_rejected() {
        let witness = witness_with_chunks();
        let total = witness.nondeterminism().individual_tokens.len();
        let (window, mutation) = window_and_mutation_token_counts(&witness);
        for position in [
            0,                            // the first chunk index
            total - window - mutation,    // the first insertion position
            total - window - 1,           // the last word of the root tokens
            total - window - Digest::LEN, // a word of the root pair's digests
            total - 1,                    // the last window insertion position
        ] {
            assert_rejects_tokens(&witness, tampered_tokens(&witness, position));
        }
    }

    #[test]
    fn insertion_position_out_of_place_is_rejected() {
        let witness = witness_with_chunks();
        let total = witness.nondeterminism().individual_tokens.len();
        let (window, mutation) = window_and_mutation_token_counts(&witness);
        let mut nondeterminism = witness.nondeterminism();
        // The first chunk's first insertion position moved past the chunk's
        // length. The Rust shadow reads past these tokens, so only the
        // program can reject.
        nondeterminism.individual_tokens[total - window - mutation] = bfe!(1 << 20);
        let error = CorrectSwbfiUpdate
            .run_tasm(&witness.standard_input(), nondeterminism)
            .unwrap_err();
        assert!(format!("{error:?}").contains(
            &BlockValidationRule::MutatorSetUpdateIntegrity
                .error_id()
                .to_string()
        ));
    }

    #[test]
    fn input_carrying_a_tampered_path_end_is_rejected() {
        let witness = witness_with_modified_entries(|entries| {
            let position = entries.iter().position(is_tree_with_chunk).unwrap();
            let path = &mut entries[position].1 .0.authentication_path;
            let last = path.len() - 1;
            path[last] = StdRng::seed_from_u64(1).random();
        });
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn input_carrying_a_chunk_with_an_index_removed_is_rejected() {
        let witness = witness_with_modified_entries(|entries| {
            let position = entries
                .iter()
                .position(|entry| {
                    is_tree_with_chunk(entry) && !entry.1 .1.relative_indices.is_empty()
                })
                .unwrap();
            entries[position].1 .1.relative_indices.pop();
        });
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    #[test]
    fn mutator_set_with_a_tampered_swbfi_peak_is_rejected() {
        let mut witness = witness_with_chunks();
        let swbfi = &witness.mutator_set.swbf_inactive;
        let mut peaks = swbfi.peaks();
        peaks[0] = StdRng::seed_from_u64(2).random();
        witness.mutator_set.swbf_inactive = MmrAccumulator::init(peaks, swbfi.num_leafs());
        // The claim input follows the tampered set, so the chunks are what
        // fails to authenticate.
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// An index moved into a chunk the witness does not hold.
    #[test]
    fn index_moved_to_a_chunk_the_witness_lacks_is_rejected() {
        let mut witness = witness_with_chunks();
        let swbfi_leaf_count = witness.mutator_set.swbf_inactive.num_leafs();
        let present = ResolveChunkIndices::chunk_indices_below(&witness.inputs, swbfi_leaf_count);
        let window_start = SwbfiPeaksAfterRemovals::window_start(&witness.mutator_set);
        let mut indices = witness.inputs[0].absolute_indices.to_array();
        let position = indices
            .iter()
            .position(|&index| index < window_start)
            .expect("some index must lie in the inactive SWBF");
        // A chunk within the index set's window, so that the set still
        // encodes, that the witness does not hold.
        let chunk_of = |index: u128| (index >> CHUNK_SIZE.ilog2()) as u64;
        let lowest = chunk_of(*indices.iter().min().unwrap());
        let absent = (lowest..lowest + u64::from(WINDOW_SIZE / CHUNK_SIZE))
            .filter(|chunk_index| *chunk_index < swbfi_leaf_count)
            .find(|chunk_index| !present.contains(chunk_index))
            .expect("the window must have a chunk the witness lacks");
        indices[position] = u128::from(absent) * u128::from(CHUNK_SIZE)
            + indices[position] % u128::from(CHUNK_SIZE);
        witness.inputs[0].absolute_indices = AbsoluteIndexSet::new(indices);
        assert_rejects(
            &witness,
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// An index moved within its chunk is a different transaction the leaf
    /// cannot tell from the honest one: it passes, and only the commitment
    /// in its output tells them apart, which is what binds it upstream.
    /// An index moved to either edge of its chunk stays in it and the update
    /// goes through, with another commitment; one step further it lies in
    /// the neighbouring chunk, and goes through if the witness holds that
    /// chunk and is rejected if not.
    /// The chunks the mutator set hands out are sorted, and stay sorted
    /// when other records' removals are applied to them: what the gap proof
    /// of the unspent check and the insertion hash rely on.
    #[test]
    fn mutator_set_keeps_its_chunks_sorted() {
        for (seed, num_records, aocl_size) in [(0, 2, 100), (1, 4, 1 << 12), (2, 3, 1 << 20)] {
            let mut rng = StdRng::seed_from_u64(seed);
            let msa_and_records = random_msa_and_records(&mut rng, num_records, aocl_size);
            let mut records = msa_and_records.unpacked_removal_records();
            let chunks_of = |records: &[RemovalRecord]| {
                records
                    .iter()
                    .flat_map(|record| record.target_chunks.indices_and_chunks())
                    .map(|(_, chunk)| chunk.relative_indices)
                    .collect::<Vec<_>>()
            };
            let chunks = chunks_of(&records);
            assert!(chunks.iter().all(|chunk| chunk.is_sorted()), "seed {seed}");

            // The first record removed, the others' chunks updated.
            let mut mutator_set = msa_and_records.mutator_set_accumulator.clone();
            let removed = records.remove(0);
            MutatorSetUpdate::new(vec![removed], vec![])
                .apply_to_accumulator_and_records(
                    &mut mutator_set,
                    &mut records.iter_mut().collect::<Vec<_>>(),
                    &mut [],
                )
                .expect("removal must apply");
            let updated = chunks_of(&records);
            assert!(updated.iter().all(|chunk| chunk.is_sorted()), "seed {seed}");
            assert!(
                chunks.iter().any(|chunk| !chunk.is_empty())
                    || updated.iter().any(|chunk| !chunk.is_empty()),
                "seed {seed}: the fixture must hold chunks"
            );
        }
    }

    #[test]
    fn index_moved_to_a_chunk_edge_and_across_it() {
        let honest = witness_with_chunks();
        let honest_output = CorrectSwbfiUpdate
            .run_tasm(&honest.standard_input(), honest.nondeterminism())
            .unwrap();
        let window_start = SwbfiPeaksAfterRemovals::window_start(&honest.mutator_set);
        let leaf_count = honest.mutator_set.swbf_inactive.num_leafs();
        let present = ResolveChunkIndices::chunk_indices_below(&honest.inputs, leaf_count);
        let chunk_size = u128::from(CHUNK_SIZE);
        let (mut seen_present, mut seen_absent) = (false, false);
        for input in 0..honest.inputs.len() {
            let indices = honest.inputs[input].absolute_indices.to_array();
            let Some(position) = indices.iter().position(|&index| index < window_start) else {
                continue;
            };
            let chunk_start = indices[position] - indices[position] % chunk_size;
            for target in [
                chunk_start,
                chunk_start + chunk_size - 1,
                chunk_start.wrapping_sub(1),
                chunk_start + chunk_size,
            ] {
                let mut moved = indices;
                moved[position] = target;
                let spread = moved.iter().max().unwrap() - moved.iter().min().unwrap();
                if target == indices[position]
                    || target >= window_start
                    || spread >= u128::from(WINDOW_SIZE)
                {
                    continue;
                }
                let mut witness = honest.clone();
                witness.inputs[input].absolute_indices = AbsoluteIndexSet::new(moved);
                if present.contains(&((target / chunk_size) as u64)) {
                    // The paths follow the insertions, so an honest prover
                    // recomputes them.
                    let witness = CorrectSwbfiUpdateWitness::new(
                        witness.packed_inputs(),
                        witness.mutator_set,
                    );
                    let output = CorrectSwbfiUpdate
                        .run_tasm(&witness.standard_input(), witness.nondeterminism())
                        .unwrap();
                    assert_eq!(honest_output[..2], output[..2]);
                    assert_ne!(honest_output[2..], output[2..]);
                    seen_present = true;
                } else {
                    assert_rejects(
                        &witness,
                        BlockValidationRule::RemovalRecordsValidity.error_id(),
                    );
                    seen_absent = true;
                }
            }
        }
        assert!(
            seen_present && seen_absent,
            "the test data must hit both cases"
        );
    }

    /// An index moved to the window start enters the active window and the
    /// update goes through, with another window; moved just below it, it
    /// needs the last chunk, which the witness holds or not.
    #[test]
    fn index_moved_to_the_window_start_and_just_below_it() {
        let chunk_of = |index: u128| (index >> CHUNK_SIZE.ilog2()) as u64;
        // A witness on a small AOCL, so that an input's index window reaches
        // the window start: an inactive index of it, whose chunk another
        // index of the record shares so the chunk stays needed when it moves
        // away, can move to the window start.
        let (honest, input, position) = (0..64)
            .map(|seed| witness_on_aocl(3, seed, 4_000))
            .find_map(|witness| {
                let window_start = SwbfiPeaksAfterRemovals::window_start(&witness.mutator_set);
                let target = (0..witness.inputs.len()).find_map(|input| {
                    let indices = witness.inputs[input].absolute_indices.to_array();
                    let minimum = *indices.iter().min().unwrap();
                    (0..indices.len())
                        .find(|&p| {
                            indices[p] < window_start
                                && window_start - minimum < u128::from(WINDOW_SIZE)
                                && indices.iter().enumerate().any(|(q, &other)| {
                                    q != p && chunk_of(other) == chunk_of(indices[p])
                                })
                        })
                        .map(|position| (input, position))
                })?;
                Some((witness, target.0, target.1))
            })
            .expect("some seed must give an input reaching the window start");
        let honest_output = CorrectSwbfiUpdate
            .run_tasm(&honest.standard_input(), honest.nondeterminism())
            .unwrap();
        let window_start = SwbfiPeaksAfterRemovals::window_start(&honest.mutator_set);
        let leaf_count = honest.mutator_set.swbf_inactive.num_leafs();
        let present = ResolveChunkIndices::chunk_indices_below(&honest.inputs, leaf_count);
        let indices = honest.inputs[input].absolute_indices.to_array();

        for target in [window_start, window_start - 1] {
            let mut moved = indices;
            moved[position] = target;
            let mut witness = honest.clone();
            witness.inputs[input].absolute_indices = AbsoluteIndexSet::new(moved);
            if target >= window_start || present.contains(&chunk_of(target)) {
                // The paths follow the insertions, so an honest prover
                // recomputes them.
                let witness =
                    CorrectSwbfiUpdateWitness::new(witness.packed_inputs(), witness.mutator_set);
                let output = CorrectSwbfiUpdate
                    .run_tasm(&witness.standard_input(), witness.nondeterminism())
                    .unwrap();
                assert_eq!(honest_output[..2], output[..2]);
                assert_ne!(honest_output[2..], output[2..]);
            } else {
                assert_rejects(
                    &witness,
                    BlockValidationRule::RemovalRecordsValidity.error_id(),
                );
            }
        }
    }

    #[test]
    fn index_moved_within_its_chunk_changes_the_commitment_only() {
        let honest = witness_with_chunks();
        let honest_output = CorrectSwbfiUpdate
            .run_tasm(&honest.standard_input(), honest.nondeterminism())
            .unwrap();

        let mut witness = honest.clone();
        let window_start = SwbfiPeaksAfterRemovals::window_start(&witness.mutator_set);
        let mut indices = witness.inputs[0].absolute_indices.to_array();
        let position = indices
            .iter()
            .position(|&index| index < window_start && index % u128::from(CHUNK_SIZE) > 0)
            .expect("some inactive index must not start its chunk");
        indices[position] -= 1;
        witness.inputs[0].absolute_indices = AbsoluteIndexSet::new(indices);
        // The paths follow the insertions, so an honest prover recomputes them.
        let witness = CorrectSwbfiUpdateWitness::new(witness.packed_inputs(), witness.mutator_set);
        let output = CorrectSwbfiUpdate
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();

        // Same leaf count and input count, other mutator set and peaks.
        assert_eq!(honest_output[..2], output[..2]);
        assert_ne!(
            honest_output[2..2 + Digest::LEN],
            output[2..2 + Digest::LEN]
        );
        assert_ne!(honest_output[2 + Digest::LEN..], output[2 + Digest::LEN..]);
    }

    /// spent. The chunks are not yet authenticated, so the unspent rule
    /// alone must catch this.
    fn witness_with_a_spent_input() -> CorrectSwbfiUpdateWitness {
        let mut witness = witness_with_chunks();
        let swbfi_leaf_count = witness.mutator_set.swbf_inactive.num_leafs();
        let window_start = u128::from(swbfi_leaf_count) << CHUNK_SIZE.ilog2();
        let chunk_indices =
            ResolveChunkIndices::chunk_indices_below(&witness.inputs, swbfi_leaf_count);
        let indices = witness
            .inputs
            .iter()
            .map(|input| input.absolute_indices.to_array())
            .find(|indices| indices.iter().all(|index| *index < window_start))
            .expect("some input must lie in the inactive SWBF");

        let mut entries = witness.inputs[0].target_chunks.clone().into_inner();
        let mut chunk_entries = entries
            .iter_mut()
            .filter(|(height, _)| {
                *height < RemovalRecordList::ENCODING_TREE_HEIGHT_OFFSET
                    || *height == RemovalRecordList::ENCODING_DELIMITER_IGNORE_TREE_HEIGHT
            })
            .map(|(_, (_, chunk))| chunk)
            .collect::<Vec<_>>();
        for index in indices {
            let chunk_index = (index >> CHUNK_SIZE.ilog2()) as u64;
            let position = chunk_indices.binary_search(&chunk_index).unwrap();
            chunk_entries[position].insert((index % u128::from(CHUNK_SIZE)) as u32);
        }
        witness.inputs[0].target_chunks = ChunkDictionary::new_in_given_order(entries);
        witness
    }

    #[test]
    fn spent_input_is_rejected() {
        assert_rejects(
            &witness_with_a_spent_input(),
            BlockValidationRule::RemovalRecordsValidity.error_id(),
        );
    }

    /// Prints how the program's cycles and table rows distribute over its
    /// subroutines, at the input counts a leaf of the aggregation tree is
    /// sized for.
    #[test]
    #[ignore = "prints a profile"]
    fn profile_leaf() {
        for num_inputs in [8, 16] {
            let witness = witness(num_inputs, 6);
            let profile = tasm_lib::generate_full_profile(
                &format!("{num_inputs} inputs"),
                CorrectSwbfiUpdate.program(),
                &witness.standard_input(),
                &witness.nondeterminism(),
            );
            println!("{profile}");
        }
    }
}
