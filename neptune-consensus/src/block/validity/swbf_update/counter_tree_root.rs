//! The root of a chunk as a Merkle tree over its index counters: the chunk
//! form of proposal f) in the design document, built here only to measure
//! what a window slide would cost, since a slide must build this root from
//! the slid indices. Nothing uses it yet.
//!
//! The tree has one leaf per index of the chunk, holding the index's count
//! in its first word, and hashes pairs up to the root. Subtrees without any
//! index have known roots, so a sparse chunk costs its occupied nodes only.

use neptune_mutator_set::shared::CHUNK_SIZE;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// The tree's height: one leaf per index of a chunk.
pub(super) const TREE_HEIGHT: usize = CHUNK_SIZE.ilog2() as usize;

/// The leaf holding this count.
pub(super) fn leaf(count: u32) -> Digest {
    Digest::new([bfe!(count), bfe!(0), bfe!(0), bfe!(0), bfe!(0)])
}

/// The roots of the subtrees without any index, by height.
pub(super) fn zero_subtree_roots() -> [Digest; TREE_HEIGHT + 1] {
    let mut roots = [Digest::default(); TREE_HEIGHT + 1];
    for height in 1..=TREE_HEIGHT {
        roots[height] = Tip5::hash_pair(roots[height - 1], roots[height - 1]);
    }
    roots
}

/// A chunk's counter tree in full, with the paths its insertions need.
pub(super) struct CounterTree {
    counts: Vec<u32>,
    /// Node `n`'s digest at `nodes[n]`, the root at 1, the leaves from
    /// `CHUNK_SIZE` on.
    nodes: Vec<Digest>,
}

impl CounterTree {
    pub(super) fn new(sorted_indices: &[u32]) -> Self {
        let mut counts = vec![0u32; CHUNK_SIZE as usize];
        for &index in sorted_indices {
            counts[index as usize] += 1;
        }
        let mut nodes = vec![Digest::default(); 2 * CHUNK_SIZE as usize];
        for (position, &count) in counts.iter().enumerate() {
            nodes[CHUNK_SIZE as usize + position] = leaf(count);
        }
        for node in (1..CHUNK_SIZE as usize).rev() {
            nodes[node] = Tip5::hash_pair(nodes[2 * node], nodes[2 * node + 1]);
        }
        Self { counts, nodes }
    }

    pub(super) fn root(&self) -> Digest {
        self.nodes[1]
    }

    /// The siblings on the way up from this position's leaf.
    pub(super) fn path(&self, position: u32) -> Vec<Digest> {
        let mut node = (CHUNK_SIZE + position) as usize;
        let mut path = vec![];
        while node > 1 {
            path.push(self.nodes[node ^ 1]);
            node /= 2;
        }
        path
    }

    /// Counts the position once more, returning the count it had.
    pub(super) fn increment(&mut self, position: u32) -> u32 {
        let count = self.counts[position as usize];
        self.counts[position as usize] += 1;
        let mut node = (CHUNK_SIZE + position) as usize;
        self.nodes[node] = leaf(count + 1);
        while node > 1 {
            node /= 2;
            self.nodes[node] = Tip5::hash_pair(self.nodes[2 * node], self.nodes[2 * node + 1]);
        }
        count
    }
}

/// The root over these sorted indices, each counted as often as it occurs.
///
/// # Panics
///
/// If an index is not below the chunk size.
pub(super) fn counter_tree_root(sorted_indices: &[u32]) -> Digest {
    fn node(indices: &[u32], height: usize, low: u32, zero: &[Digest]) -> Digest {
        if indices.is_empty() {
            return zero[height];
        }
        if height == 0 {
            return leaf(indices.len() as u32);
        }
        let mid = low + (1 << (height - 1));
        let split = indices.partition_point(|&index| index < mid);
        Tip5::hash_pair(
            node(&indices[..split], height - 1, low, zero),
            node(&indices[split..], height - 1, mid, zero),
        )
    }

    assert!(sorted_indices.iter().all(|&index| index < CHUNK_SIZE));
    node(sorted_indices, TREE_HEIGHT, 0, &zero_subtree_roots())
}

/// ```text
/// BEFORE: _ *indices
/// AFTER:  _ [root]
/// ```
///
/// The indices are a list of u32s below the chunk size, sorted, an index
/// occurring as often as it is counted.
#[derive(Debug, Copy, Clone)]
pub(super) struct CounterTreeRoot;

impl BasicSnippet for CounterTreeRoot {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*indices".to_string())]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "root".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_counter_tree_root".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let zero_table = format!("{entrypoint}_zero_table");
        let node = format!("{entrypoint}_node");
        let empty_node = format!("{entrypoint}_empty_node");
        let use_sentinel = format!("{entrypoint}_use_sentinel");
        let leaf_node = format!("{entrypoint}_leaf_node");
        let leaf_loop = format!("{entrypoint}_leaf_loop");

        // The zero subtrees' roots by height, five words each, written from
        // constants when the program starts.
        let zero_roots = library.kmalloc((Digest::LEN * (TREE_HEIGHT + 1)) as u32);
        let write_zero_roots = zero_subtree_roots()
            .iter()
            .enumerate()
            .flat_map(|(height, root)| {
                let address = zero_roots.write_address().value() + (Digest::LEN * height) as u64;
                let push_root = root
                    .values()
                    .into_iter()
                    .rev()
                    .map(|word| triton_asm!(push { word }))
                    .collect::<Vec<_>>()
                    .concat();
                triton_asm!({&push_root} push {address} write_mem {Digest::LEN} pop 1)
            })
            .collect::<Vec<_>>();
        let zero_root_last_word = |height_on_stack: Vec<LabelledInstruction>| {
            triton_asm!(
                {&height_on_stack}
                push {Digest::LEN} mul
                push {zero_roots.write_address().value() + Digest::LEN as u64 - 1} add
            )
        };

        triton_asm!(
            // BEFORE: _ *indices
            // AFTER:  _ [root]
            {entrypoint}:
                call {zero_table}
                read_mem 1 addi 2
                // _ n *first

                dup 1 dup 1 add place 2 pick 1 pop 1
                // _ *end *first

                push {TREE_HEIGHT} push 0
                call {node}
                // _ *end *ptr [root]

                // Every index was consumed, so all lie below the chunk size.
                pick 6 pick 6 eq assert
                return

            // BEFORE: _
            // AFTER:  _
            {zero_table}:
                {&write_zero_roots}
                return

            // The root of the subtree of this height starting at this index,
            // consuming the indices in it.
            // BEFORE: _ *end *ptr height low
            // AFTER:  _ *end *ptr' [root]
            {node}:
                dup 2 dup 4 eq
                // _ *end *ptr height low at_end

                dup 3 read_mem 1 pop 1
                dup 1 skiz call {use_sentinel}
                // _ *end *ptr height low at_end next_index

                dup 3 push 2 pow dup 3 add
                // _ *end *ptr height low at_end next_index high

                swap 1 lt push 0 eq add
                // _ *end *ptr height low is_empty

                dup 0 skiz call {empty_node}
                skiz return
                // _ *end *ptr height low

                dup 1 push 0 eq
                dup 0 skiz call {leaf_node}
                skiz return
                // _ *end *ptr height low

                pick 3 pick 3
                dup 3 addi -1 dup 3
                call {node}
                // _ height low *end *ptr' [left]

                pick 6 pick 6
                dup 8 addi -1
                dup 8 dup 1 push 2 pow add
                call {node}
                // _ height low [left] *end *ptr'' [right]

                pick 6 pick 6
                place 13 place 13
                // _ *end *ptr'' height low [left] [right]

                pick 9 pick 9 pick 9 pick 9 pick 9
                hash
                // _ *end *ptr'' height low [root]

                pick 5 pop 1 pick 5 pop 1
                return

            // BEFORE: _ at_end next_index
            // AFTER:  _ at_end chunk_size
            {use_sentinel}:
                pop 1 push {CHUNK_SIZE}
                return

            // BEFORE: _ *end *ptr height low is_empty
            // AFTER:  _ *end *ptr [zero[height]] 1
            {empty_node}:
                pop 2
                {&zero_root_last_word(triton_asm!())}
                read_mem {Digest::LEN} pop 1
                push 1
                return

            // BEFORE: _ *end *ptr height low is_leaf
            // AFTER:  _ *end *ptr' [leaf(count)] 1
            {leaf_node}:
                pop 1 pick 1 pop 1 push 0
                call {leaf_loop}
                // _ *end *ptr' low count

                pick 1 pop 1
                push 0 push 0 push 0 push 0 pick 4
                push 1
                return

            // Counts the indices equal to the leaf's, consuming them.
            // INVARIANT: _ *end *ptr low count
            {leaf_loop}:
                dup 3 dup 3 eq skiz return
                dup 2 read_mem 1 pop 1 dup 2 eq push 0 eq skiz return
                pick 2 addi 1 place 2
                addi 1
                recurse
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::vm::VM;

    use super::*;

    const INDICES_POINTER: u64 = 1_000;

    /// A program that computes the root of the list in memory and writes it
    /// to standard output.
    fn program() -> Program {
        let mut library = Library::new();
        let root = library.import(Box::new(CounterTreeRoot));
        Program::new(&triton_asm!(
            push {INDICES_POINTER}
            call {root}
            write_io {Digest::LEN}
            halt
            {&library.all_imports()}
        ))
    }

    fn nondeterminism(sorted_indices: &[u32]) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        let list = [
            vec![bfe!(sorted_indices.len() as u64)],
            sorted_indices.iter().map(|&index| bfe!(index)).collect(),
        ]
        .concat();
        for (i, word) in list.into_iter().enumerate() {
            nondeterminism
                .ram
                .insert(bfe!(INDICES_POINTER + i as u64), word);
        }
        nondeterminism
    }

    fn tasm_root(sorted_indices: &[u32]) -> Digest {
        let output = VM::run(
            program(),
            PublicInput::default(),
            nondeterminism(sorted_indices),
        )
        .unwrap();
        Digest::new(output.try_into().unwrap())
    }

    /// This many sorted indices with repeats, at most `distinct` distinct.
    fn sorted_indices(rng: &mut StdRng, count: usize, distinct: u32) -> Vec<u32> {
        let mut indices = (0..count)
            .map(|_| rng.random_range(0..distinct.min(CHUNK_SIZE)))
            .collect::<Vec<_>>();
        indices.sort_unstable();
        indices
    }

    #[test]
    fn dense_and_sparse_roots_agree() {
        let mut rng = StdRng::seed_from_u64(0);
        let indices = sorted_indices(&mut rng, 300, CHUNK_SIZE);
        let mut counts = vec![0u32; CHUNK_SIZE as usize];
        for &index in &indices {
            counts[index as usize] += 1;
        }
        let mut level = counts.into_iter().map(leaf).collect::<Vec<_>>();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| Tip5::hash_pair(pair[0], pair[1]))
                .collect();
        }
        assert_eq!(level[0], counter_tree_root(&indices));
    }

    #[test]
    fn roots_agree_with_the_host() {
        let mut rng = StdRng::seed_from_u64(1);
        let cases = [
            vec![],
            vec![0],
            vec![CHUNK_SIZE - 1],
            vec![7, 7, 7],
            vec![0, 1, 2, 3, 4094, 4095, 4095],
            sorted_indices(&mut rng, 100, CHUNK_SIZE),
            sorted_indices(&mut rng, 250, CHUNK_SIZE),
            sorted_indices(&mut rng, 410, CHUNK_SIZE),
            sorted_indices(&mut rng, 1_000, 100),
        ];
        for indices in cases {
            assert_eq!(
                counter_tree_root(&indices),
                tasm_root(&indices),
                "{} indices",
                indices.len()
            );
        }
    }

    #[test]
    fn index_at_the_chunk_size_is_rejected() {
        let output = VM::run(
            program(),
            PublicInput::default(),
            nondeterminism(&[CHUNK_SIZE]),
        );
        assert!(output.is_err());
    }

    /// Prints the rows a slide's root costs at several chunk densities.
    #[test]
    #[ignore = "prints a profile"]
    fn profile_slide_root() {
        let mut rng = StdRng::seed_from_u64(2);
        for count in [0, 100, 250, 410, 1_000] {
            let indices = sorted_indices(&mut rng, count, CHUNK_SIZE);
            let distinct = {
                let mut d = indices.clone();
                d.dedup();
                d.len()
            };
            let profile = tasm_lib::generate_full_profile(
                &format!("{count} indices, {distinct} distinct"),
                program(),
                &PublicInput::default(),
                &nondeterminism(&indices),
            );
            let total = profile
                .to_string()
                .lines()
                .find(|line| line.starts_with("| Total"))
                .unwrap()
                .to_string();
            println!("{count} indices, {distinct} distinct: {total}");
        }
    }
}
