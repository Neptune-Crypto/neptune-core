//! The composer's proof that it holds the mutator set: the contents of two
//! chunks of the inactive SWBF and one leaf of the AOCL, the ones the
//! parent's hash samples, with their membership in the mutator set after
//! the parent block, which the block's transaction is built on. A block's
//! appendix carries the claim; its input binds the parent and the two MMRs,
//! so the composer cannot pick the samples, and it can prove the claim as
//! soon as the parent lands.

use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::chunk::Chunk;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::arithmetic::u64::div_mod::DivMod;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_step_u64_index::MerkleStepU64Index;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::leaf_index_to_mt_index_and_peak_index::MmrLeafIndexToMtIndexAndPeakIndex;
use tasm_lib::prelude::*;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use super::mutator_set_hash::BagPeaksFromList;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

/// The hash of the parent's hash paired with a salt, whose words sample
/// leafs of the mutator set.
pub(super) fn sample_digest(prev_block_digest: Digest, salt: Digest) -> Digest {
    Tip5::hash_pair(prev_block_digest, salt)
}

/// The leafs of the mutator set whose contents the composer must know: two
/// of an inactive SWBF with this many leafs and one of an AOCL with this
/// many, each none when the MMR has none.
pub fn sampled_leafs(
    prev_block_digest: Digest,
    swbfi_leaf_count: u64,
    aocl_leaf_count: u64,
) -> (Option<[u64; 2]>, Option<u64>) {
    let [chunk_a, chunk_b, aocl_leaf, _, _] =
        sample_digest(prev_block_digest, Digest::default()).values();
    let chunks = (swbfi_leaf_count != 0)
        .then(|| [chunk_a, chunk_b].map(|word| word.value() % swbfi_leaf_count));
    let aocl_leaf = (aocl_leaf_count != 0).then(|| aocl_leaf.value() % aocl_leaf_count);
    (chunks, aocl_leaf)
}

#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
pub struct KnowsMutatorSetWitness {
    prev_block_digest: Digest,
    aocl: MmrAccumulator,
    swbfi: MmrAccumulator,
    chunk_a: Chunk,
    chunk_b: Chunk,
    aocl_leaf: Digest,
    /// The authentication paths of the two chunks, then of the AOCL leaf.
    paths: Vec<Vec<Digest>>,
}

impl KnowsMutatorSetWitness {
    /// For the chunks and AOCL leaf [`sampled_leafs`] picks in this mutator
    /// set, with their authentication paths; anything for an empty MMR.
    pub fn new(
        prev_block_digest: Digest,
        mutator_set: &MutatorSetAccumulator,
        chunks: [Chunk; 2],
        chunk_paths: [Vec<Digest>; 2],
        aocl_leaf: Digest,
        aocl_path: Vec<Digest>,
    ) -> Self {
        let [chunk_a, chunk_b] = chunks;
        let [path_a, path_b] = chunk_paths;
        Self {
            prev_block_digest,
            aocl: mutator_set.aocl.clone(),
            swbfi: mutator_set.swbf_inactive.clone(),
            chunk_a,
            chunk_b,
            aocl_leaf,
            paths: vec![path_a, path_b, aocl_path],
        }
    }

    fn mutator_set(&self) -> MutatorSetAccumulator {
        MutatorSetAccumulator {
            aocl: self.aocl.clone(),
            swbf_inactive: self.swbfi.clone(),
            ..Default::default()
        }
    }
}

impl SecretWitness for KnowsMutatorSetWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(KnowsMutatorSet::claim_input(
            self.prev_block_digest,
            &self.mutator_set(),
        ))
    }

    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program {
        KnowsMutatorSet.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );
        nondeterminism.digests = self.paths.concat();
        nondeterminism
    }
}

/// Input:
/// - the parent block's hash (5 words)
/// - the bagged peaks of the AOCL (5 words)
/// - the bagged peaks of the inactive SWBF (5 words)
///
/// Output: none.
///
/// Divines the two MMRs, which must bag to the input, two chunks and an
/// AOCL leaf, and their authentication paths to the leafs the parent's hash
/// samples.
#[derive(
    Debug, Clone, Copy, Default, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct KnowsMutatorSet;

impl KnowsMutatorSet {
    const MUTATOR_SET_MISMATCH_ERROR_ID: i128 = 1_000_610;
    const WRONG_LEAF_ERROR_ID: i128 = 1_000_611;

    pub fn claim_input(
        prev_block_digest: Digest,
        mutator_set: &MutatorSetAccumulator,
    ) -> Vec<BFieldElement> {
        [
            prev_block_digest,
            mutator_set.aocl.bag_peaks(),
            mutator_set.swbf_inactive.bag_peaks(),
        ]
        .iter()
        .flat_map(|digest| digest.reversed().values())
        .collect()
    }

    /// The claim a block whose parent has this hash, and this mutator set
    /// after it, must carry.
    pub fn claim(
        prev_block_digest: Digest,
        mutator_set: &MutatorSetAccumulator,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        Claim::new(Self.hash())
            .with_input(Self::claim_input(prev_block_digest, mutator_set))
            .about_version(consensus_rule_set.triton_proof_version().version())
    }
}

impl TritonProgram for KnowsMutatorSet {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit_witness = library.import(Box::new(
            VerifyNdSiIntegrity::<KnowsMutatorSetWitness>::default(),
        ));
        let bag_peaks = library.import(Box::new(BagPeaksFromList));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let div_mod = library.import(Box::new(DivMod));
        let leaf_index_to_mt_index = library.import(Box::new(MmrLeafIndexToMtIndexAndPeakIndex));
        let merkle_step = library.import(Box::new(MerkleStepU64Index));
        let sample_alloc = library.kmalloc(Digest::LEN as u32);

        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let read_leaf_count = triton_asm!(
            {&field!(MmrAccumulator::leaf_count)} addi 1 read_mem 2 pop 1
        );
        // BEFORE: _ *w [bagged_peaks] *mmr
        // AFTER:  _ *w
        let mmr_bags_to = triton_asm!(
            dup 0 {&field!(MmrAccumulator::peaks)}
            swap 1 {&read_leaf_count}
            call {bag_peaks}
            // _ *w [bagged_peaks] [witness_bagged_peaks]
            dup 9 dup 9 dup 9 dup 9 dup 9
            assert_vector error_id {Self::MUTATOR_SET_MISMATCH_ERROR_ID}
            pop 5 pop 5
        );
        let verify_chunks = "knows_mutator_set_verify_chunks".to_string();
        let verify_chunk = "knows_mutator_set_verify_chunk".to_string();
        let verify_aocl_leaf = "knows_mutator_set_verify_aocl_leaf".to_string();
        let verify_sample = "knows_mutator_set_verify_sample".to_string();
        let climb = "knows_mutator_set_climb".to_string();
        let code = triton_asm!(
            // The samples: the words of the parent's hash paired with a zero
            // digest.
            push 0 push 0 push 0 push 0 push 0
            read_io {Digest::LEN}
            // _ [salt] [prev_block_digest]
            hash
            push {sample_alloc.write_address()} write_mem {Digest::LEN} pop 1
            // _
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            dup 0 call {audit_witness} pop 1
            // _ *w
            read_io {Digest::LEN}
            dup 5 {&field!(KnowsMutatorSetWitness::aocl)}
            {&mmr_bags_to}
            read_io {Digest::LEN}
            dup 5 {&field!(KnowsMutatorSetWitness::swbfi)}
            {&mmr_bags_to}
            // _ *w
            dup 0 {&field!(KnowsMutatorSetWitness::swbfi)} {&read_leaf_count}
            add push 0 eq push 0 eq
            skiz call {verify_chunks}
            dup 0 {&field!(KnowsMutatorSetWitness::aocl)} {&read_leaf_count}
            add push 0 eq push 0 eq
            skiz call {verify_aocl_leaf}
            pop 1
            halt

            // BEFORE: _ *w
            // AFTER:  _ *w
            {verify_chunks}:
                dup 0 {&field_with_size!(KnowsMutatorSetWitness::chunk_a)}
                push {sample_alloc.write_address()} read_mem 1 pop 1
                call {verify_chunk}
                dup 0 {&field_with_size!(KnowsMutatorSetWitness::chunk_b)}
                push {sample_alloc.write_address()} addi 1 read_mem 1 pop 1
                call {verify_chunk}
                return

            // BEFORE: _ *w *chunk chunk_size sample
            // AFTER:  _ *w
            {verify_chunk}:
                place 2 call {hash_varlen}
                // _ *w sample [leaf]
                dup 6 {&field!(KnowsMutatorSetWitness::swbfi)}
                dup 0 {&field!(MmrAccumulator::peaks)} place 7
                // _ *w *peaks sample [leaf] *swbfi
                {&read_leaf_count} pick 7
                // _ *w *peaks [leaf] [leaf_count] sample
                call {verify_sample}
                return

            // BEFORE: _ *w
            // AFTER:  _ *w
            {verify_aocl_leaf}:
                dup 0 {&field!(KnowsMutatorSetWitness::aocl)}
                dup 0 {&field!(MmrAccumulator::peaks)}
                dup 2 {&field!(KnowsMutatorSetWitness::aocl_leaf)} {&read_digest}
                // _ *w *aocl *peaks [leaf]
                pick 6 {&read_leaf_count}
                push {sample_alloc.write_address()} addi 2 read_mem 1 pop 1
                // _ *w *peaks [leaf] [leaf_count] sample
                call {verify_sample}
                return

            // The leaf at the sample's index, modulo the leaf count, must be
            // the MMR's.
            // BEFORE: _ *peaks [leaf] [leaf_count] sample
            // AFTER:  _
            {verify_sample}:
                split
                // _ *peaks [leaf] [leaf_count] [sample]
                dup 3 dup 3 call {div_mod}
                // _ *peaks [leaf] [leaf_count] [quotient] [leaf_index]
                pick 3 pick 3 pop 2
                call {leaf_index_to_mt_index}
                // _ *peaks [leaf] [mt_index] peak_index
                place 7 place 6 place 6
                // _ *peaks peak_index [mt_index] [leaf]
                call {climb}
                // _ *peaks peak_index 0 1 [root]
                dup 7 push {Digest::LEN} mul dup 9 add addi 1 {&read_digest}
                // _ *peaks peak_index 0 1 [root] [peak]
                assert_vector error_id {Self::WRONG_LEAF_ERROR_ID}
                pop 5 pop 4
                return

            // INVARIANT: _ [mt_index] [node]
            {climb}:
                dup 6 dup 6 push 0 push 1 {&DataType::U64.compare()}
                skiz return
                call {merkle_step}
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
    use neptune_mutator_set::shared::CHUNK_SIZE;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::twenty_first::prelude::MerkleTree;

    use super::*;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;

    impl TritonProgramSpecification for KnowsMutatorSet {
        fn source(&self) {
            let prev_block_digest = tasm::tasmlib_io_read_stdin___digest();
            let witness: KnowsMutatorSetWitness =
                tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);
            let bagged_aocl_peaks = tasm::tasmlib_io_read_stdin___digest();
            assert_eq!(bagged_aocl_peaks, witness.aocl.bag_peaks());
            let bagged_swbfi_peaks = tasm::tasmlib_io_read_stdin___digest();
            assert_eq!(bagged_swbfi_peaks, witness.swbfi.bag_peaks());
            let swbfi_leaf_count = witness.swbfi.num_leafs();
            let aocl_leaf_count = witness.aocl.num_leafs();
            let (chunks, aocl_leaf) =
                sampled_leafs(prev_block_digest, swbfi_leaf_count, aocl_leaf_count);
            if let Some(leaf_indices) = chunks {
                let leafs = [&witness.chunk_a, &witness.chunk_b].map(Tip5::hash);
                for (leaf_index, leaf) in leaf_indices.into_iter().zip(leafs) {
                    assert!(tasm::mmr_verify_from_secret_in_leaf_index_on_stack(
                        &witness.swbfi.peaks(),
                        swbfi_leaf_count,
                        leaf_index,
                        leaf,
                    ));
                }
            }
            if let Some(leaf_index) = aocl_leaf {
                assert!(tasm::mmr_verify_from_secret_in_leaf_index_on_stack(
                    &witness.aocl.peaks(),
                    aocl_leaf_count,
                    leaf_index,
                    witness.aocl_leaf,
                ));
            }
        }
    }

    /// An MMR held in full: one Merkle tree per peak over its leafs.
    pub(in crate::block::validity) struct KnownMmr {
        trees: Vec<MerkleTree>,
        pub(in crate::block::validity) leafs: Vec<Digest>,
    }

    impl KnownMmr {
        pub(in crate::block::validity) fn new(leafs: Vec<Digest>) -> Self {
            let num_leafs = leafs.len();
            let mut trees = vec![];
            let mut first_leaf = 0;
            for height in (0..64)
                .rev()
                .filter(|height| num_leafs & (1 << height) != 0)
            {
                let num_tree_leafs = 1 << height;
                let tree = MerkleTree::par_new(&leafs[first_leaf..first_leaf + num_tree_leafs]);
                trees.push(tree.unwrap());
                first_leaf += num_tree_leafs;
            }
            Self { trees, leafs }
        }

        pub(in crate::block::validity) fn random(rng: &mut StdRng, num_leafs: u64) -> Self {
            Self::new((0..num_leafs).map(|_| rng.random()).collect())
        }

        pub(in crate::block::validity) fn num_leafs(&self) -> u64 {
            u64::try_from(self.leafs.len()).unwrap()
        }

        pub(in crate::block::validity) fn accumulator(&self) -> MmrAccumulator {
            let peaks = self.trees.iter().map(MerkleTree::root).collect();
            MmrAccumulator::init(peaks, self.num_leafs())
        }

        /// The authentication path of this leaf, from the leaf up.
        pub(in crate::block::validity) fn path(&self, leaf_index: u64) -> Vec<Digest> {
            let mut local_index = usize::try_from(leaf_index).unwrap();
            for tree in &self.trees {
                if local_index < tree.num_leafs() {
                    let proof = tree.inclusion_proof_for_leaf_indices(&[local_index]);
                    return proof.unwrap().into_authentication_paths().unwrap()[0].clone();
                }
                local_index -= tree.num_leafs();
            }
            panic!("leaf index {leaf_index} is out of range");
        }
    }

    /// An inactive SWBF held in full, over random chunks.
    pub(in crate::block::validity) struct ArchivalSwbfi {
        pub(in crate::block::validity) mmr: KnownMmr,
        pub(in crate::block::validity) chunks: Vec<Chunk>,
    }

    impl ArchivalSwbfi {
        pub(in crate::block::validity) fn random(rng: &mut StdRng, num_leafs: u64) -> Self {
            let chunks = (0..num_leafs)
                .map(|_| {
                    let mut chunk = Chunk::empty_chunk();
                    for _ in 0..rng.random_range(0..20) {
                        chunk.insert(rng.random_range(0..CHUNK_SIZE));
                    }
                    chunk
                })
                .collect::<Vec<_>>();
            let mmr = KnownMmr::new(chunks.iter().map(Tip5::hash).collect());
            Self { mmr, chunks }
        }

        pub(in crate::block::validity) fn num_leafs(&self) -> u64 {
            self.mmr.num_leafs()
        }

        pub(in crate::block::validity) fn accumulator(&self) -> MmrAccumulator {
            self.mmr.accumulator()
        }

        pub(in crate::block::validity) fn chunk(&self, leaf_index: u64) -> &Chunk {
            &self.chunks[usize::try_from(leaf_index).unwrap()]
        }

        pub(in crate::block::validity) fn path(&self, leaf_index: u64) -> Vec<Digest> {
            self.mmr.path(leaf_index)
        }
    }

    /// The witness a composer with this mutator set holds for a block whose
    /// parent has this hash.
    fn witness(
        prev_block_digest: Digest,
        swbfi: &ArchivalSwbfi,
        aocl: &KnownMmr,
    ) -> KnowsMutatorSetWitness {
        let mutator_set = MutatorSetAccumulator {
            aocl: aocl.accumulator(),
            swbf_inactive: swbfi.accumulator(),
            ..Default::default()
        };
        let (chunk_indices, aocl_leaf_index) =
            sampled_leafs(prev_block_digest, swbfi.num_leafs(), aocl.num_leafs());
        let (chunks, chunk_paths) = match chunk_indices {
            Some(indices) => (
                indices.map(|index| swbfi.chunk(index).clone()),
                indices.map(|index| swbfi.path(index)),
            ),
            None => (
                [Chunk::empty_chunk(), Chunk::empty_chunk()],
                [vec![], vec![]],
            ),
        };
        let (aocl_leaf, aocl_path) = match aocl_leaf_index {
            Some(index) => (
                aocl.leafs[usize::try_from(index).unwrap()],
                aocl.path(index),
            ),
            None => (Digest::default(), vec![]),
        };
        KnowsMutatorSetWitness::new(
            prev_block_digest,
            &mutator_set,
            chunks,
            chunk_paths,
            aocl_leaf,
            aocl_path,
        )
    }

    fn assert_accepts(witness: &KnowsMutatorSetWitness) {
        let input = witness.standard_input();
        let rust_output = KnowsMutatorSet
            .run_rust(&input, witness.nondeterminism())
            .unwrap();
        let tasm_output = KnowsMutatorSet
            .run_tasm(&input, witness.nondeterminism())
            .unwrap();
        assert!(rust_output.is_empty());
        assert_eq!(rust_output, tasm_output);
    }

    fn assert_rejects(witness: &KnowsMutatorSetWitness, error_id: i128) {
        KnowsMutatorSet
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[error_id],
            )
            .unwrap();
    }

    #[test]
    fn sampled_leafs_of_any_trees_are_accepted() {
        let mut rng = StdRng::seed_from_u64(0);
        for swbfi_leafs in [0, 1, 2, 3, 7, 8, 35] {
            let swbfi = ArchivalSwbfi::random(&mut rng, swbfi_leafs);
            for aocl_leafs in [0, 1, 4, 100] {
                let aocl = KnownMmr::random(&mut rng, aocl_leafs);
                for _ in 0..2 {
                    assert_accepts(&witness(rng.random(), &swbfi, &aocl));
                }
            }
        }
    }

    #[test]
    fn samples_cover_every_leaf_and_differ() {
        let mut rng = StdRng::seed_from_u64(1);
        let num_leafs = 5;
        let mut sampled = [[false; 5]; 3];
        let mut chunks_differ = false;
        for _ in 0..200 {
            let (chunks, aocl_leaf) = sampled_leafs(rng.random(), num_leafs, num_leafs);
            let [chunk_a, chunk_b] = chunks.unwrap();
            chunks_differ |= chunk_a != chunk_b;
            for (samples, index) in sampled
                .iter_mut()
                .zip([chunk_a, chunk_b, aocl_leaf.unwrap()])
            {
                samples[usize::try_from(index).unwrap()] = true;
            }
        }
        assert!(sampled.iter().flatten().all(|&leaf| leaf));
        assert!(chunks_differ);
        assert_eq!((None, None), sampled_leafs(rng.random(), 0, 0));
    }

    #[test]
    fn mutator_set_other_than_the_claim_binds_is_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let swbfi = ArchivalSwbfi::random(&mut rng, 35);
        let aocl = KnownMmr::random(&mut rng, 100);
        let witness = witness(rng.random(), &swbfi, &aocl);
        for bag in 1..=2 {
            let mut input = witness.standard_input();
            input.individual_tokens[bag * Digest::LEN] += bfe!(1);
            KnowsMutatorSet
                .test_assertion_failure(
                    input,
                    witness.nondeterminism(),
                    &[KnowsMutatorSet::MUTATOR_SET_MISMATCH_ERROR_ID],
                )
                .unwrap();
        }
    }

    #[test]
    fn other_chunk_leaf_or_path_is_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        for (swbfi_leafs, aocl_leafs) in [(1, 1), (2, 3), (35, 100)] {
            let swbfi = ArchivalSwbfi::random(&mut rng, swbfi_leafs);
            let aocl = KnownMmr::random(&mut rng, aocl_leafs);
            let honest = witness(rng.random(), &swbfi, &aocl);

            let mut other_chunk_a = honest.clone();
            other_chunk_a
                .chunk_a
                .insert(rng.random_range(0..CHUNK_SIZE));
            assert_rejects(&other_chunk_a, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);

            let mut other_chunk_b = honest.clone();
            other_chunk_b
                .chunk_b
                .insert(rng.random_range(0..CHUNK_SIZE));
            assert_rejects(&other_chunk_b, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);

            let mut other_aocl_leaf = honest.clone();
            other_aocl_leaf.aocl_leaf = rng.random();
            assert_rejects(&other_aocl_leaf, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);

            for path in 0..3 {
                if honest.paths[path].is_empty() {
                    continue;
                }
                let mut other_path = honest.clone();
                other_path.paths[path][0] = rng.random();
                assert_rejects(&other_path, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);
            }
        }
    }

    #[test]
    fn leafs_sampled_by_another_parent_are_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let swbfi = ArchivalSwbfi::random(&mut rng, 35);
        let aocl = KnownMmr::random(&mut rng, 100);
        let honest = witness(rng.random(), &swbfi, &aocl);
        let other_parent: Digest = rng.random();
        assert_ne!(
            sampled_leafs(honest.prev_block_digest, 35, 100),
            sampled_leafs(other_parent, 35, 100)
        );
        let mut witness = honest;
        witness.prev_block_digest = other_parent;
        assert_rejects(&witness, KnowsMutatorSet::WRONG_LEAF_ERROR_ID);
    }

    #[test]
    fn claim_is_the_witness_claim_with_the_proof_version() {
        let mut rng = StdRng::seed_from_u64(5);
        let swbfi = ArchivalSwbfi::random(&mut rng, 8);
        let aocl = KnownMmr::random(&mut rng, 9);
        let witness = witness(rng.random(), &swbfi, &aocl);
        let consensus_rule_set = ConsensusRuleSet::HardforkDelta;
        let claim = KnowsMutatorSet::claim(
            witness.prev_block_digest,
            &witness.mutator_set(),
            consensus_rule_set,
        );
        let expected = witness
            .claim()
            .about_version(consensus_rule_set.triton_proof_version().version());
        assert_eq!(expected, claim);
    }
}
