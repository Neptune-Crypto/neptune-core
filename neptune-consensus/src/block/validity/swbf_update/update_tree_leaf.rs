//! One changed leaf of a Merkle tree, walked up its authentication path
//! twice with `merkle_step_mem`: with the old digest to the root the tree
//! has, and with the new digest to the root it gets. The leaves of a tree
//! are updated in turn, each path against the tree after the leaves before
//! it have changed, so the walks chain: a leaf's old walk must land on the
//! root the previous leaf's new walk produced.

use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::*;

use crate::block::block_validation_error::BlockValidationRule;

/// ```text
/// BEFORE: _ *running_root *path [node_index] *path [node_index] [old_leaf] [new_leaf]
/// AFTER:  _
/// ```
///
/// `*running_root` points at the root the tree has, which the snippet
/// replaces by the root it gets. `*path` points at the leaf's authentication
/// path, one digest per level of the tree, against the tree as it is when
/// the leaf's turn comes, and comes twice, once per walk. `node_index` is
/// the leaf's index plus the tree's leaf count, as two limbs with the high
/// one raised by one: a u32 index shows one above its low limb, which is
/// where the walk stops. The tree height is at least one; a tree height
/// above 62 is not supported.
///
/// The old digest's walk must reproduce the running root; the new digest's
/// walk yields the root the tree has afterwards.
///
/// Crashes with the error ID of rule 2.b if the old walk misses the running
/// root: the leaf does not sit in the tree.
#[derive(Debug, Copy, Clone)]
pub(super) struct UpdateTreeLeaf;

impl UpdateTreeLeaf {
    pub(super) fn old_root_mismatch_error_id() -> i128 {
        BlockValidationRule::RemovalRecordsValidity.error_id()
    }

    /// The node indices of a tree's authentication structure for these leaf
    /// indices, from the highest down: the order the Merkle tree gives the
    /// structure's digests.
    pub(super) fn auth_struct_indices(tree_height: u32, leaf_indices: &[u64]) -> Vec<u64> {
        let num_leafs = 1 << tree_height;
        let mut needed = HashSet::new();
        let mut computable = HashSet::new();
        for &leaf_index in leaf_indices {
            let mut node_index = leaf_index + num_leafs;
            while node_index > 1 {
                computable.insert(node_index);
                needed.insert(node_index ^ 1);
                node_index /= 2;
            }
        }
        needed
            .difference(&computable)
            .copied()
            .sorted_unstable()
            .rev()
            .collect()
    }

    /// Sets a leaf in a tree of known nodes and recomputes its ancestors.
    pub(super) fn set_leaf(
        nodes: &mut HashMap<u64, Digest>,
        tree_height: u32,
        leaf_index: u64,
        digest: Digest,
    ) {
        let mut node = leaf_index + (1 << tree_height);
        nodes.insert(node, digest);
        while node > 1 {
            let parent = node / 2;
            let child = |node| nodes.get(&node).copied().unwrap_or_default();
            nodes.insert(
                parent,
                Tip5::hash_pair(child(parent * 2), child(parent * 2 + 1)),
            );
            node = parent;
        }
    }

    /// The paths the walks take, from the tree's authentication structure
    /// for the leaves: for each leaf in order, its siblings up the tree
    /// after the leaves before it have changed. An unknown node reads as
    /// zero, so any structure yields paths; a wrong one yields wrong roots.
    pub(super) fn sequential_paths(
        tree_height: u32,
        auth_struct: &[Digest],
        old_leafs: &[(u64, Digest)],
        new_leafs: &[(u64, Digest)],
    ) -> Vec<Digest> {
        let leaf_indices = old_leafs.iter().map(|(index, _)| *index).collect_vec();
        let mut nodes: HashMap<u64, Digest> = Self::auth_struct_indices(tree_height, &leaf_indices)
            .into_iter()
            .zip(auth_struct.iter().copied())
            .collect();
        for &(leaf_index, digest) in old_leafs {
            Self::set_leaf(&mut nodes, tree_height, leaf_index, digest);
        }

        let mut paths = vec![];
        for &(leaf_index, digest) in new_leafs {
            let mut node = leaf_index + (1 << tree_height);
            while node > 1 {
                paths.push(nodes.get(&(node ^ 1)).copied().unwrap_or_default());
                node /= 2;
            }
            Self::set_leaf(&mut nodes, tree_height, leaf_index, digest);
        }
        paths
    }

    /// Both roots the walks over these paths and leaves produce, on the
    /// host machine, or nothing where the snippet crashes: a later leaf's
    /// old walk off the running root.
    #[cfg(test)]
    pub(super) fn try_roots(
        tree_height: u32,
        paths: &[Digest],
        old_leafs: &[(u64, Digest)],
        new_leafs: &[(u64, Digest)],
    ) -> Option<(Digest, Digest)> {
        let walk = |leaf_index: u64, path: &[Digest], mut node: Digest| {
            let mut node_index = leaf_index + (1 << tree_height);
            for &sibling in path {
                node = if node_index.is_multiple_of(2) {
                    Tip5::hash_pair(node, sibling)
                } else {
                    Tip5::hash_pair(sibling, node)
                };
                node_index /= 2;
            }
            node
        };
        let path_of = |i: usize| {
            let start = i * tree_height as usize;
            paths
                .get(start..start + tree_height as usize)
                .unwrap_or_default()
        };
        let mut old_root = Digest::default();
        let mut running = Digest::default();
        for (i, (&(index, old), &(_, new))) in old_leafs.iter().zip(new_leafs).enumerate() {
            let old_walk = walk(index, path_of(i), old);
            if i == 0 {
                old_root = old_walk;
            } else if old_walk != running {
                return None;
            }
            running = walk(index, path_of(i), new);
        }
        Some((old_root, running))
    }

    /// The inverse of [`Self::sequential_paths`]: the tree's authentication
    /// structure for the leaves, from their sequential paths and old
    /// digests. A path's sibling is an old node unless an earlier leaf's
    /// change reached it, in which case the earlier leaf's old walk knows
    /// it.
    pub(super) fn auth_struct_from_paths(
        tree_height: u32,
        paths: &[Digest],
        old_leafs: &[(u64, Digest)],
    ) -> Vec<Digest> {
        let leaf_indices = old_leafs.iter().map(|(index, _)| *index).collect_vec();
        let mut path = paths.iter().copied();
        let mut nodes = HashMap::new();
        for &(leaf_index, digest) in old_leafs {
            let mut node = leaf_index + (1 << tree_height);
            while node > 1 {
                let sibling = path.next().unwrap_or_default();
                nodes.entry(node ^ 1).or_insert(sibling);
                node /= 2;
            }
            Self::set_leaf(&mut nodes, tree_height, leaf_index, digest);
        }
        Self::auth_struct_indices(tree_height, &leaf_indices)
            .into_iter()
            .map(|node| nodes.get(&node).copied().unwrap_or_default())
            .collect()
    }
}

impl BasicSnippet for UpdateTreeLeaf {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*running_root".to_string()),
            (DataType::VoidPointer, "*path".to_string()),
            (DataType::U64, "node_index_high_raised".to_string()),
            (DataType::VoidPointer, "*path".to_string()),
            (DataType::U64, "node_index_high_raised".to_string()),
            (DataType::Digest, "old_leaf".to_string()),
            (DataType::Digest, "new_leaf".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_update_tree_leaf".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let new_alloc = library.kmalloc(Digest::LEN as u32);

        let entrypoint = self.entrypoint();
        let walk_low_levels = format!("{entrypoint}_walk_low_levels");
        let walk_u32_loop = format!("{entrypoint}_walk_u32_loop");

        // Up the path with `merkle_step_mem`, two instructions per level. A
        // node index with a high limb first walks its low 31 levels.
        // BEFORE: _ *path (hi + 1) lo [node]
        // AFTER:  _ *path' 1 1 [root]
        let walk = triton_asm!(
            dup 6 push 1 eq push 0 eq skiz call {walk_low_levels}
            call {walk_u32_loop}
        );

        triton_asm!(
            {entrypoint}:
                // _ *running *path (hi + 1) lo *path (hi + 1) lo [old] [new]
                push {new_alloc.write_address()} write_mem {Digest::LEN} pop 1
                {&walk}
                // _ *running *path (hi + 1) lo *path' 1 1 [old_root]

                dup 11 addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
                assert_vector error_id {Self::old_root_mismatch_error_id()}
                pop 5 pop 3
                // _ *running *path (hi + 1) lo

                push {new_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&walk}
                // _ *running *path' 1 1 [new_root]

                dup 8 write_mem {Digest::LEN} pop 1
                pop 4
                return

            // The lowest 31 levels of a node index with a high limb: their
            // turns are the low limb's lower 31 bits, so a u32 that halves
            // to one after exactly 31 steps carries them. What remains of
            // the index is a u32 for tree heights up to 62.
            // BEFORE: _ *path (hi + 1) lo [node]
            // AFTER:  _ *path' 1 (node_index >> 31) [node']
            {walk_low_levels}:
                pick 6 addi -1 place 6
                dup 5 push {1_u64 << 31} swap 1 div_mod addi {1_u64 << 31}
                // _ *path hi lo [node] q (r + 2^31)

                pick 8 pick 8 pop 1
                // _ *path [node] q (r + 2^31) hi

                place 8 pick 1 place 7
                // _ hi q *path [node] (r + 2^31)

                place 5 push 1 place 6
                // _ hi q *path 1 (r + 2^31) [node]

                call {walk_u32_loop}
                // _ hi q *path' 1 1 [node']

                pick 5 pop 1 pick 5 pop 1
                pick 6 pick 7 push 2 mul add
                // _ *path' [node'] (2 hi + q)

                place 5 push 1 place 6
                return

            // INVARIANT: _ *path 1 node_index [node]
            {walk_u32_loop}:
                merkle_step_mem
                recurse_or_return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::function::Function;
    use tasm_lib::traits::function::FunctionInitialState;
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::traits::rust_shadow::RustShadowError;
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::vm::VMState;
    use tasm_lib::twenty_first::util_types::merkle_tree::MerkleTree;

    use super::*;

    type IndexedLeafs = Vec<(u64, Digest)>;

    const PATHS_POINTER: BFieldElement = BFieldElement::new(1_000);
    const RUNNING_POINTER: BFieldElement = BFieldElement::new(1 << 20);

    fn path_memory(paths: &[Digest]) -> HashMap<BFieldElement, BFieldElement> {
        let mut ram = HashMap::new();
        for (i, path_digest) in paths.iter().enumerate() {
            for (j, &word) in path_digest.values().iter().enumerate() {
                ram.insert(PATHS_POINTER + bfe!(1 + (i * Digest::LEN + j) as u64), word);
            }
        }
        ram
    }

    /// The pointer to the `i`th leaf's path in a list of paths of this
    /// height.
    fn path_pointer(tree_height: u32, i: usize) -> BFieldElement {
        PATHS_POINTER + bfe!(1 + i * tree_height as usize * Digest::LEN)
    }

    fn read_digest(
        memory: &HashMap<BFieldElement, BFieldElement>,
        pointer: BFieldElement,
    ) -> Digest {
        let word = |i: usize| {
            memory
                .get(&(pointer + bfe!(i as u64)))
                .copied()
                .unwrap_or_default()
        };
        Digest::new(core::array::from_fn(word))
    }

    /// The snippet's arguments on the stack, top last: the node index with
    /// its high limb raised, twice.
    fn arguments(
        path: BFieldElement,
        node_index: u64,
        old: Digest,
        new: Digest,
    ) -> Vec<BFieldElement> {
        let index = vec![
            path,
            bfe!((node_index >> 32) + 1),
            bfe!(node_index & u64::from(u32::MAX)),
        ];
        [
            vec![RUNNING_POINTER],
            index.clone(),
            index,
            old.reversed().values().to_vec(),
            new.reversed().values().to_vec(),
        ]
        .concat()
    }

    fn write_digest(
        memory: &mut HashMap<BFieldElement, BFieldElement>,
        pointer: BFieldElement,
        digest: Digest,
    ) {
        for (i, &word) in digest.values().iter().enumerate() {
            memory.insert(pointer + bfe!(i as u64), word);
        }
    }

    impl Function for UpdateTreeLeaf {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
        ) -> Result<(), RustShadowError> {
            let new: Digest = tasm_lib::pop_encodable(stack)?;
            let old: Digest = tasm_lib::pop_encodable(stack)?;
            let raised: u64 = tasm_lib::pop_encodable(stack)?;
            let path = stack.pop().unwrap();
            let raised_again: u64 = tasm_lib::pop_encodable(stack)?;
            let path_again = stack.pop().unwrap();
            let running_pointer = stack.pop().unwrap();
            assert_eq!((path, raised), (path_again, raised_again));
            let node_index = raised - (1 << 32);

            // Up the path: a node index with a high limb walks its low 31
            // levels on a u32 first; the same arithmetic either way.
            let walk = |mut node_index: u64, mut node: Digest| {
                let mut path = path;
                while node_index != 1 {
                    let sibling = read_digest(memory, path);
                    path += bfe!(Digest::LEN as u64);
                    node = if node_index.is_multiple_of(2) {
                        Tip5::hash_pair(node, sibling)
                    } else {
                        Tip5::hash_pair(sibling, node)
                    };
                    node_index /= 2;
                }
                node
            };
            assert_eq!(
                read_digest(memory, running_pointer),
                walk(node_index, old),
                "old leaf must sit in the tree"
            );
            let new_root = walk(node_index, new);

            // The snippet parks the new leaf in static memory.
            write_digest(memory, bfe!(-6), new);
            write_digest(memory, running_pointer, new_root);
            Ok(())
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> FunctionInitialState {
            let mut rng = StdRng::from_seed(seed);
            let tree_height = match bench_case {
                Some(BenchmarkCase::CommonCase) => 20,
                Some(BenchmarkCase::WorstCase) => 62,
                None => rng.random_range(1..=62),
            };
            self.initial_state(&mut rng, tree_height)
        }

        fn corner_case_initial_states(&self) -> Vec<FunctionInitialState> {
            let mut rng = StdRng::seed_from_u64(0);
            [1, 2, 31, 32, 33, 62]
                .into_iter()
                .map(|tree_height| self.initial_state(&mut rng, tree_height))
                .collect()
        }
    }

    impl UpdateTreeLeaf {
        /// A random leaf of a sparse tree of this height, with its path and
        /// the tree's root as the running root.
        fn initial_state(&self, rng: &mut StdRng, tree_height: u32) -> FunctionInitialState {
            let index = rng.random_range(0..1_u64 << tree_height);
            let old: Digest = rng.random();
            let tree = SparseTree::new(tree_height, &[(index, old)]);
            let mut memory = path_memory(&tree.path(index));
            write_digest(&mut memory, RUNNING_POINTER, tree.root());
            FunctionInitialState {
                stack: [
                    self.init_stack_for_isolated_run(),
                    arguments(
                        PATHS_POINTER + bfe!(1),
                        index + (1 << tree_height),
                        old,
                        rng.random(),
                    ),
                ]
                .concat(),
                memory,
            }
        }
    }

    /// A tree whose untouched leaves are zero digests, for trees far too
    /// tall to build.
    struct SparseTree {
        height: u32,
        nodes: HashMap<u64, Digest>,
        /// The digest of an untouched node at each level above the leaves.
        defaults: Vec<Digest>,
    }

    impl SparseTree {
        fn new(height: u32, leafs: &[(u64, Digest)]) -> Self {
            let mut defaults = vec![Digest::default()];
            for _ in 0..height {
                let below = *defaults.last().unwrap();
                defaults.push(Tip5::hash_pair(below, below));
            }
            let mut tree = Self {
                height,
                nodes: HashMap::new(),
                defaults,
            };
            for &(index, digest) in leafs {
                tree.set_leaf(index, digest);
            }
            tree
        }

        fn node(&self, node: u64) -> Digest {
            let level = (self.height - node.ilog2()) as usize;
            self.nodes
                .get(&node)
                .copied()
                .unwrap_or(self.defaults[level])
        }

        fn set_leaf(&mut self, index: u64, digest: Digest) {
            let mut node = index + (1 << self.height);
            self.nodes.insert(node, digest);
            while node > 1 {
                let parent = node / 2;
                let digest = Tip5::hash_pair(self.node(parent * 2), self.node(parent * 2 + 1));
                self.nodes.insert(parent, digest);
                node = parent;
            }
        }

        fn root(&self) -> Digest {
            self.node(1)
        }

        /// The siblings up from the leaf.
        fn path(&self, index: u64) -> Vec<Digest> {
            let mut node = index + (1 << self.height);
            let mut path = vec![];
            while node > 1 {
                path.push(self.node(node ^ 1));
                node /= 2;
            }
            path
        }
    }

    /// Sequential paths and both roots in a sparse tree.
    fn sparse_paths_and_roots(
        tree_height: u32,
        old_leafs: &[(u64, Digest)],
        new_leafs: &[(u64, Digest)],
    ) -> (Vec<Digest>, Digest, Digest) {
        let mut tree = SparseTree::new(tree_height, old_leafs);
        let old_root = tree.root();
        let mut paths = vec![];
        for &(index, digest) in new_leafs {
            paths.extend(tree.path(index));
            tree.set_leaf(index, digest);
        }
        (paths, old_root, tree.root())
    }

    /// The root the snippet leaves for one leaf, if it accepts the inputs.
    fn tasm_update(
        mut memory: HashMap<BFieldElement, BFieldElement>,
        running: Digest,
        path: BFieldElement,
        node_index: u64,
        old: Digest,
        new: Digest,
    ) -> Result<Digest, InstructionError> {
        write_digest(&mut memory, RUNNING_POINTER, running);
        let program = Program::new(&UpdateTreeLeaf.link_for_isolated_run());
        let nondeterminism = NonDeterminism::default().with_ram(memory);
        let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
        let init_stack = UpdateTreeLeaf.init_stack_for_isolated_run();
        vm_state.op_stack.stack =
            [init_stack.clone(), arguments(path, node_index, old, new)].concat();
        vm_state.run()?;

        assert_eq!(init_stack, vm_state.op_stack.stack);
        Ok(read_digest(&vm_state.ram, RUNNING_POINTER))
    }

    /// The leaves updated in turn, each by its own run of the snippet from
    /// the root the previous one left, as the peak mutation does it.
    fn tasm_new_root(
        tree_height: u32,
        paths: &[Digest],
        old_leafs: &[(u64, Digest)],
        new_leafs: &[(u64, Digest)],
        old_root: Digest,
    ) -> Result<Digest, InstructionError> {
        let memory = path_memory(paths);
        let mut running = old_root;
        for (i, (&(index, old), &(_, new))) in old_leafs.iter().zip(new_leafs).enumerate() {
            running = tasm_update(
                memory.clone(),
                running,
                path_pointer(tree_height, i),
                index + (1 << tree_height),
                old,
                new,
            )?;
        }
        Ok(running)
    }

    fn random_case(
        rng: &mut StdRng,
        tree_height: u32,
        num_leafs: usize,
    ) -> (IndexedLeafs, IndexedLeafs) {
        let mut indices = (0..num_leafs)
            .map(|_| rng.random_range(0..1_u64 << tree_height))
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices.dedup();
        let old = indices.iter().map(|&i| (i, rng.random())).collect();
        let new = indices.iter().map(|&i| (i, rng.random())).collect();
        (old, new)
    }

    #[test]
    fn rust_shadow_agrees_with_tasm() {
        ShadowedFunction::new(UpdateTreeLeaf).test();
    }

    /// Small trees built in full: the structure's paths lead from the old
    /// tree's root to the new tree's, and the structure comes back from the
    /// paths.
    #[test]
    fn paths_from_the_structure_reach_the_merkle_root_and_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        for tree_height in 1..7 {
            for num_leafs in [1, 2, 5, 20] {
                let mut leafs = (0..1_u64 << tree_height)
                    .map(|_| rng.random::<Digest>())
                    .collect_vec();
                let (old, new) = random_case(&mut rng, tree_height, num_leafs);
                let old = old
                    .into_iter()
                    .map(|(i, _)| (i, leafs[i as usize]))
                    .collect_vec();
                let indices = old.iter().map(|(i, _)| *i as usize).collect_vec();
                let old_tree = MerkleTree::par_new(&leafs).unwrap();
                let auth_struct = old_tree.authentication_structure(&indices).unwrap();

                let paths = UpdateTreeLeaf::sequential_paths(tree_height, &auth_struct, &old, &new);
                assert_eq!(indices.len() * tree_height as usize, paths.len());
                assert_eq!(
                    auth_struct,
                    UpdateTreeLeaf::auth_struct_from_paths(tree_height, &paths, &old)
                );

                for &(i, digest) in &new {
                    leafs[i as usize] = digest;
                }
                let new_tree = MerkleTree::par_new(&leafs).unwrap();
                assert_eq!(
                    Ok(new_tree.root()),
                    tasm_new_root(tree_height, &paths, &old, &new, old_tree.root())
                );
            }
        }
    }

    #[test]
    fn tall_trees_agree() {
        let mut rng = StdRng::seed_from_u64(3);
        for (tree_height, num_leafs) in [(12, 3), (20, 41), (32, 3), (40, 5), (62, 3)] {
            let (old, new) = random_case(&mut rng, tree_height, num_leafs);
            let (paths, old_root, new_root) = sparse_paths_and_roots(tree_height, &old, &new);
            assert_eq!(
                Ok(new_root),
                tasm_new_root(tree_height, &paths, &old, &new, old_root),
                "height {tree_height}, {num_leafs} leafs"
            );
        }
    }

    /// The error the snippet raises when a leaf's old walk misses the
    /// running root.
    fn old_root_mismatch(result: Result<Digest, InstructionError>) -> bool {
        matches!(
            result,
            Err(InstructionError::VectorAssertionFailed(_, AssertionError { id, .. }))
                if id == Some(UpdateTreeLeaf::old_root_mismatch_error_id())
        )
    }

    /// Every word of every path digest and of every old leaf breaks the
    /// chain of running roots, starting at the given root; every word of a
    /// new leaf but the last's does too, and the last's changes the new
    /// root. Every word of the given root is checked by the first leaf.
    #[test]
    fn every_word_of_every_path_leaf_and_root_is_checked() {
        let mut rng = StdRng::seed_from_u64(1);
        for (tree_height, num_leafs) in [(4, 1), (4, 3), (33, 1), (33, 3)] {
            let (old, new) = random_case(&mut rng, tree_height, num_leafs);
            let num_leafs = old.len();
            let (paths, old_root, new_root) = sparse_paths_and_roots(tree_height, &old, &new);
            assert_eq!(
                Ok(new_root),
                tasm_new_root(tree_height, &paths, &old, &new, old_root)
            );
            let case = format!("height {tree_height}, {num_leafs} leafs");

            for (path_position, word) in
                (0..paths.len()).flat_map(|p| (0..Digest::LEN).map(move |w| (p, w)))
            {
                let mut tampered = paths.clone();
                tampered[path_position].0[word] += bfe!(1);
                let result = tasm_new_root(tree_height, &tampered, &old, &new, old_root);
                assert!(
                    old_root_mismatch(result),
                    "{case}: path {path_position} word {word}"
                );
            }
            for word in 0..Digest::LEN {
                let mut tampered = old_root;
                tampered.0[word] += bfe!(1);
                let result = tasm_new_root(tree_height, &paths, &old, &new, tampered);
                assert!(old_root_mismatch(result), "{case}: root word {word}");
            }
            for (leaf, word) in (0..num_leafs).flat_map(|l| (0..Digest::LEN).map(move |w| (l, w))) {
                let mut tampered = old.clone();
                tampered[leaf].1 .0[word] += bfe!(1);
                let result = tasm_new_root(tree_height, &paths, &tampered, &new, old_root);
                assert!(
                    old_root_mismatch(result),
                    "{case}: old leaf {leaf} word {word}"
                );

                let mut tampered = new.clone();
                tampered[leaf].1 .0[word] += bfe!(1);
                let result = tasm_new_root(tree_height, &paths, &old, &tampered, old_root);
                if leaf == num_leafs - 1 {
                    assert_ne!(Ok(new_root), result, "{case}: new leaf {leaf} word {word}");
                    assert!(result.is_ok(), "{case}: new leaf {leaf} word {word}");
                } else {
                    assert!(
                        old_root_mismatch(result),
                        "{case}: new leaf {leaf} word {word}"
                    );
                }
            }
        }
    }

    #[test]
    fn paths_that_run_out_read_on_and_are_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let (old, new) = random_case(&mut rng, 5, 3);
        let (mut paths, old_root, _) = sparse_paths_and_roots(5, &old, &new);
        paths.truncate(paths.len() - 3);
        assert!(old_root_mismatch(tasm_new_root(
            5, &paths, &old, &new, old_root
        )));
    }

    /// Random leaf indices, or a cluster of them within 256 consecutive
    /// leaves the way one input's chunks lie.
    fn leaf_indices(
        rng: &mut StdRng,
        tree_height: u32,
        num_leafs: usize,
        clustered: bool,
    ) -> Vec<u64> {
        let num_tree_leafs = 1_u64 << tree_height;
        let (start, span) = if clustered {
            let span = 256.min(num_tree_leafs);
            (rng.random_range(0..=num_tree_leafs - span), span)
        } else {
            (0, num_tree_leafs)
        };
        let mut indices = (0..num_leafs)
            .map(|_| start + rng.random_range(0..span))
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    /// The total rows of the processor, op-stack, RAM and hash tables.
    fn table_rows(program: Program, nondeterminism: NonDeterminism) -> [u64; 4] {
        let profile =
            tasm_lib::generate_full_profile("", program, &PublicInput::default(), &nondeterminism);
        let total = profile
            .to_string()
            .lines()
            .find(|line| line.starts_with("| Total"))
            .expect("profile must total")
            .to_string();
        let cells = total
            .split('|')
            .skip(2)
            .take(4)
            .map(|cell| {
                cell.trim()
                    .split(' ')
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        [cells[0], cells[1], cells[2], cells[3]]
    }

    /// Both approaches on identical leaves, over tree heights and leaf
    /// counts, scattered and clustered. The path walks are one run of the
    /// snippet per leaf, summed, so their rows leave out the loop the peak
    /// mutation runs around them, about twenty rows per leaf; the structure
    /// is one run.
    #[test]
    #[ignore = "prints a benchmark"]
    fn benchmark_against_the_authentication_structure() {
        use super::super::roots_from_authentication_struct::RootsFromAuthenticationStruct;

        let mut rng = StdRng::seed_from_u64(2);
        println!(
            "{:>6} {:>6} {:>9} | {:>36} | {:>36}",
            "height",
            "leafs",
            "layout",
            "structure: proc / opstk / ram / hash",
            "paths: proc / opstk / ram / hash"
        );
        for tree_height in [4, 8, 12, 16, 20, 24, 31, 32, 40, 48, 60] {
            for (num_leafs, clustered) in
                [(1, false), (5, false), (41, false), (41, true), (82, true)]
            {
                let indices = leaf_indices(&mut rng, tree_height, num_leafs, clustered);
                let old = indices
                    .iter()
                    .map(|&i| (i, rng.random()))
                    .collect::<Vec<_>>();
                let new = indices
                    .iter()
                    .map(|&i| (i, rng.random()))
                    .collect::<Vec<_>>();
                let tree = SparseTree::new(tree_height, &old);

                let (paths, old_root, _) = sparse_paths_and_roots(tree_height, &old, &new);
                let memory = path_memory(&paths);
                let mut running = old_root;
                let mut paths_rows = [0; 4];
                for (i, (&(index, old_leaf), &(_, new_leaf))) in old.iter().zip(&new).enumerate() {
                    let mut library = Library::new();
                    let snippet = library.import(Box::new(UpdateTreeLeaf));
                    let pushes = arguments(
                        path_pointer(tree_height, i),
                        index + (1 << tree_height),
                        old_leaf,
                        new_leaf,
                    )
                    .into_iter()
                    .flat_map(|word| triton_asm!(push { word }))
                    .collect::<Vec<_>>();
                    let program = Program::new(&triton_asm!(
                        {&pushes}
                        call {snippet} halt
                        {&library.all_imports()}
                    ));
                    let mut run_memory = memory.clone();
                    write_digest(&mut run_memory, RUNNING_POINTER, running);
                    let rows = table_rows(program, NonDeterminism::default().with_ram(run_memory));
                    for (total, rows) in paths_rows.iter_mut().zip(rows) {
                        *total += rows;
                    }
                    running = tasm_update(
                        memory.clone(),
                        running,
                        path_pointer(tree_height, i),
                        index + (1 << tree_height),
                        old_leaf,
                        new_leaf,
                    )
                    .unwrap();
                }

                let (auth_struct_indices, _) =
                    RootsFromAuthenticationStruct::auth_struct_and_sibling_indices(
                        tree_height,
                        &indices,
                    );
                let auth_struct = auth_struct_indices
                    .iter()
                    .map(|&node| tree.node(node))
                    .collect::<Vec<_>>();
                let (_, tokens) = RootsFromAuthenticationStruct::roots_and_tokens(
                    tree_height,
                    &auth_struct,
                    &old,
                    &new,
                );
                let mut library = Library::new();
                let snippet = library.import(Box::new(RootsFromAuthenticationStruct));
                let old_pointer = bfe!(1 << 24);
                let new_pointer = bfe!(1 << 25);
                let program = Program::new(&triton_asm!(
                    push {tree_height} push {PATHS_POINTER} push {old_pointer} push {new_pointer}
                    call {snippet} halt
                    {&library.all_imports()}
                ));
                let mut ram = HashMap::new();
                encode_to_memory(&mut ram, PATHS_POINTER, &auth_struct);
                encode_to_memory(&mut ram, old_pointer, &old);
                encode_to_memory(&mut ram, new_pointer, &new);
                let structure_rows = table_rows(program, NonDeterminism::new(tokens).with_ram(ram));

                let cells = |rows: [u64; 4]| {
                    format!(
                        "{:>8} {:>8} {:>8} {:>8}",
                        rows[0], rows[1], rows[2], rows[3]
                    )
                };
                println!(
                    "{:>6} {:>6} {:>9} | {} | {}",
                    tree_height,
                    indices.len(),
                    if clustered { "clustered" } else { "scattered" },
                    cells(structure_rows),
                    cells(paths_rows),
                );
            }
        }
    }
}
