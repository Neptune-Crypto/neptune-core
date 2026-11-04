//! The root of a Merkle tree before and after some of its leaves change,
//! from one authentication structure: the sibling nodes of the changed
//! leaves' paths, which are the same before and after. One walk yields
//! both roots.
//!
//! The walk is tasm-lib's root-from-authentication-structure argument,
//! carried over to two digests per node. Challenges come from a sponge
//! over the leaves and the structure. A running product takes, for every
//! node the program knows, the factor `γ·index + xfe(old) + δ·xfe(new) −
//! β`; the prover then divines the tree's sibling pairs from the deepest
//! up, each dividing its children's factors out and multiplying its
//! parent's in, the parents hashed from the children; and the product must
//! end as the root's factor alone. A structure node is the same digest
//! before and after, so it contributes `(1 + δ)·xfe`.

use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use tasm_lib::hashing::absorb_multiple::AbsorbMultiple;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::x_field_element::EXTENSION_DEGREE;

/// ```text
/// BEFORE: _ tree_height *auth_struct *old_indexed_leafs *new_indexed_leafs
/// AFTER:  _ [old_root] [new_root]
/// ```
///
/// The indexed leaves are lists of leaf index and digest, the same leaf
/// indices in the same order in both, at least one. The authentication
/// structure is a list of digests, the siblings of the paths from the
/// highest node index down. The prover supplies the structure's node
/// indices in ascending order, then for each sibling pair from the deepest
/// up their indices and the right and left digests, old and new each.
///
/// Crashes with an error ID if a leaf index reaches the tree's leaf count
/// or the two lists' indices differ, and without one if the divined data
/// do not describe the tree the leaves and the structure define.
#[derive(Debug, Copy, Clone)]
pub(super) struct RootsFromAuthenticationStruct;

impl RootsFromAuthenticationStruct {
    pub(super) const LEAF_INDEX_GE_NUM_LEAFS_ERROR_ID: i128 = 1_000_630;
    pub(super) const LEAF_INDICES_DIFFER_ERROR_ID: i128 = 1_000_631;

    fn indexed_leaf_element_type() -> DataType {
        DataType::Tuple(vec![DataType::U64, DataType::Digest])
    }

    /// The node indices of a tree's authentication structure for these leaf
    /// indices, from the highest down, and the pairs of sibling nodes the
    /// structure and the leafs determine, from the deepest up.
    pub(super) fn auth_struct_and_sibling_indices(
        tree_height: u32,
        leaf_indices: &[u64],
    ) -> (Vec<u64>, Vec<(u64, u64)>) {
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
        let auth_struct_indices = needed
            .difference(&computable)
            .copied()
            .sorted_unstable()
            .rev()
            .collect();
        let sibling_indices = needed
            .union(&computable)
            .copied()
            .sorted_unstable()
            .rev()
            .chunks(2)
            .into_iter()
            .filter_map(|mut pair| Some((pair.next()?, pair.next()?)))
            .map(|(right, left)| (left, right))
            .collect();
        (auth_struct_indices, sibling_indices)
    }

    /// Both roots and the tokens the program reads for them: the node index
    /// of each structure element, then for each pair of siblings their
    /// indices and the right and left digests, old and new each. Any
    /// structure serves; a wrong one yields wrong roots.
    pub(super) fn roots_and_tokens(
        tree_height: u32,
        auth_struct: &[Digest],
        old_leafs: &[(u64, Digest)],
        new_leafs: &[(u64, Digest)],
    ) -> ((Digest, Digest), Vec<BFieldElement>) {
        let leaf_indices = old_leafs.iter().map(|(index, _)| *index).collect_vec();
        let (auth_struct_indices, sibling_indices) =
            Self::auth_struct_and_sibling_indices(tree_height, &leaf_indices);

        let nodes = |leafs: &[(u64, Digest)]| -> HashMap<u64, Digest> {
            let mut nodes: HashMap<u64, Digest> = leafs
                .iter()
                .map(|&(leaf_index, digest)| (leaf_index + (1 << tree_height), digest))
                .collect();
            nodes.extend(
                auth_struct_indices
                    .iter()
                    .copied()
                    .zip(auth_struct.iter().copied()),
            );
            nodes
        };
        let mut old_nodes = nodes(old_leafs);
        let mut new_nodes = nodes(new_leafs);
        let mut pairs = vec![];
        for &(left, right) in &sibling_indices {
            let mut pair = vec![];
            for nodes in [&mut old_nodes, &mut new_nodes] {
                let left_digest = nodes.get(&left).copied().unwrap_or_default();
                let right_digest = nodes.get(&right).copied().unwrap_or_default();
                nodes.insert(left / 2, Tip5::hash_pair(left_digest, right_digest));
                pair.push((left_digest, right_digest));
            }
            pairs.push(pair);
        }

        let reversed = |digest: Digest| digest.encode().into_iter().rev();
        let structure_tokens = auth_struct_indices
            .iter()
            .rev()
            .flat_map(|node_index| node_index.encode().into_iter().rev());
        let sibling_tokens =
            sibling_indices
                .iter()
                .zip(pairs)
                .flat_map(|(&(left, right), pair)| {
                    let [(left_old, right_old), (left_new, right_new)] = pair[..] else {
                        unreachable!()
                    };
                    [bfe!(left), bfe!(right)]
                        .into_iter()
                        .chain(reversed(right_old))
                        .chain(reversed(right_new))
                        .chain(reversed(left_old))
                        .chain(reversed(left_new))
                });
        let tokens = structure_tokens.chain(sibling_tokens).collect();

        let root = |nodes: &HashMap<u64, Digest>| {
            nodes
                .get(&1)
                .copied()
                .unwrap_or_else(|| nodes[&(1 << tree_height)])
        };
        ((root(&old_nodes), root(&new_nodes)), tokens)
    }
}

impl BasicSnippet for RootsFromAuthenticationStruct {
    fn parameters(&self) -> Vec<(DataType, String)> {
        let leafs = DataType::List(Box::new(Self::indexed_leaf_element_type()));
        vec![
            (DataType::U32, "tree_height".to_string()),
            (
                DataType::List(Box::new(DataType::Digest)),
                "*auth_struct".to_string(),
            ),
            (leafs.clone(), "*old_indexed_leafs".to_string()),
            (leafs, "*new_indexed_leafs".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "old_root".to_string()),
            (DataType::Digest, "new_root".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_roots_from_authentication_struct".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let absorb_multiple = library.import(Box::new(AbsorbMultiple));

        let alpha = library.kmalloc(EXTENSION_DEGREE as u32);
        let minus_beta = library.kmalloc(EXTENSION_DEGREE as u32);
        let gamma = library.kmalloc(EXTENSION_DEGREE as u32);
        let delta = library.kmalloc(EXTENSION_DEGREE as u32);
        let delta_plus_one = library.kmalloc(EXTENSION_DEGREE as u32);
        // The distance from an old leaf's word to the new leaf's.
        let new_offset = library.kmalloc(1);
        let t_old = library.kmalloc(Digest::LEN as u32);
        let t_new = library.kmalloc(Digest::LEN as u32);
        let right_old = library.kmalloc(Digest::LEN as u32);
        let right_new = library.kmalloc(Digest::LEN as u32);
        let left_old = library.kmalloc(Digest::LEN as u32);
        let left_new = library.kmalloc(Digest::LEN as u32);

        let element_size = Self::indexed_leaf_element_type().stack_size();
        let two_pow_32: u64 = 1 << 32;
        let one_half = BFieldElement::new(2).inverse();

        let entrypoint = self.entrypoint();
        let leafs_loop = format!("{entrypoint}_leafs_loop");
        let auth_struct_loop = format!("{entrypoint}_auth_struct_loop");
        let nd_loop = format!("{entrypoint}_nd_loop");
        let store_ts = format!("{entrypoint}_store_ts");

        // BEFORE: _ *auth_struct *old *new
        // AFTER:  _
        let derive_challenges = triton_asm!(
            sponge_init
            dup 0 read_mem 1 addi 1 swap 1 push {element_size} mul addi 1
            call {absorb_multiple}
            dup 1 read_mem 1 addi 1 swap 1 push {element_size} mul addi 1
            call {absorb_multiple}
            dup 2 read_mem 1 addi 1 swap 1 push {Digest::LEN} mul addi 1
            call {absorb_multiple}
            pop 3
            // _

            sponge_squeeze pop 1
            // _ [gamma] [-beta] [alpha]

            push {alpha.write_address()} write_mem {EXTENSION_DEGREE} pop 1
            push {minus_beta.write_address()} write_mem {EXTENSION_DEGREE} pop 1
            push {gamma.write_address()} write_mem {EXTENSION_DEGREE} pop 1
            sponge_squeeze pop 5 pop 2
            // _ [delta]

            dup 2 dup 2 dup 2
            push {delta.write_address()} write_mem {EXTENSION_DEGREE} pop 1
            push 0 push 0 push 1 xx_add
            push {delta_plus_one.write_address()} write_mem {EXTENSION_DEGREE} pop 1
            // _
        );

        // BEFORE: _ [digest]
        // AFTER:  _ [xfe]
        let digest_to_xfe = triton_asm!(
            push 1
            push {alpha.read_address()} read_mem {EXTENSION_DEGREE} pop 1
            xx_mul
            xx_add
        );

        // BEFORE: _ [old] [new]
        // AFTER:  _ [xfe(old) + delta * xfe(new)]
        let pair_to_xfe = triton_asm!(
            {&digest_to_xfe}
            push {delta.read_address()} read_mem {EXTENSION_DEGREE} pop 1
            xx_mul
            place 7 place 7 place 7
            {&digest_to_xfe}
            xx_add
        );

        // BEFORE: _ [xfe] node_index
        // AFTER:  _ [gamma * node_index + xfe - beta]
        let node_factor = triton_asm!(
            push {gamma.read_address()} read_mem {EXTENSION_DEGREE} pop 1
            pick 3 xb_mul
            xx_add
            push {minus_beta.read_address()} read_mem {EXTENSION_DEGREE} pop 1
            xx_add
        );

        // BEFORE: _ hi lo
        // AFTER:  _ bfe
        let u64_to_bfe = triton_asm!(swap 1 push {two_pow_32} mul add);

        // BEFORE: _ lhs_hi lhs_lo rhs_hi rhs_lo
        // AFTER:  _ lhs_hi lhs_lo (rhs < lhs)
        let u64_lt = triton_asm!(
            dup 2 swap 1 lt
            dup 1 dup 4 eq mul
            dup 3 swap 1 swap 2 lt
            add
        );

        let dup_top_digest = triton_asm![dup 4; Digest::LEN];
        let store_digest = |allocation: &tasm_lib::library::StaticAllocation| {
            triton_asm!(
                {&dup_top_digest}
                push {allocation.write_address()} write_mem {Digest::LEN} pop 1
            )
        };
        let read_digest = |allocation: &tasm_lib::library::StaticAllocation| triton_asm!(push {allocation.read_address()} read_mem {Digest::LEN} pop 1);
        let compare_xfes = DataType::Xfe.compare();

        triton_asm!(
            // BEFORE: _ tree_height *auth_struct *old *new
            // AFTER:  _ [old_root] [new_root]
            {entrypoint}:
                dup 0 dup 2 push -1 mul add
                push {new_offset.write_address()} write_mem 1 pop 1
                dup 2 dup 2 dup 2
                {&derive_challenges}
                pop 1
                // _ tree_height *auth_struct *old

                swap 2 push 2 pow swap 2
                // _ num_leafs *auth_struct *old

                /* The leaves' factors, from the last leaf down. */
                dup 0 read_mem 1 push 1 add swap 1
                dup 0 push 0 eq push 0 eq assert
                push {element_size} mul add
                // _ num_leafs *auth_struct *old *old_last_word

                dup 3 split
                push 0 push 0 push 1
                // _ num_leafs *auth_struct *old *old_last_word [num_leafs: u64] [p]

                dup 6 dup 6 eq push 0 eq skiz call {leafs_loop}
                // _ num_leafs *auth_struct *old *old [num_leafs: u64] [p]

                /* The structure's factors, with its divined node indices. */
                push 0 swap 4 pop 1 push 0 swap 5 pop 1
                // _ num_leafs *auth_struct *old *old [prev: u64] [p]

                swap 7 swap 6 pop 1
                // _ num_leafs p0 *auth_struct *old [prev] p2 p1

                dup 5 read_mem 1 push 1 add swap 1 push {Digest::LEN} mul add
                swap 5 swap 7
                // _ num_leafs *old *auth_struct *auth_struct_last_word [prev] [p]

                dup 6 dup 6 eq push 0 eq skiz call {auth_struct_loop}
                swap 4 pop 1 swap 4 pop 1 swap 4 pop 2
                // _ num_leafs *old [p]

                /* The initial roots: the first leaves, for a tree of height 0. */
                dup 3 push {Digest::LEN} add read_mem {Digest::LEN} pop 1
                push {t_old.write_address()} write_mem {Digest::LEN} pop 1
                dup 3 push {Digest::LEN} add
                push {new_offset.read_address()} read_mem 1 pop 1 add
                read_mem {Digest::LEN} pop 1
                push {t_new.write_address()} write_mem {Digest::LEN} pop 1
                swap 2 swap 4 swap 1 swap 3 pop 1
                // _ [p] num_leafs

                push 1 eq push 0 eq skiz call {nd_loop}
                // _ [p]

                /* The product must be the roots' factor. */
                {&read_digest(&t_old)}
                {&read_digest(&t_new)}
                {&pair_to_xfe}
                push 1
                {&node_factor}
                {&compare_xfes}
                assert
                // _

                {&read_digest(&t_old)}
                {&read_digest(&t_new)}
                return

            // INVARIANT: _ num_leafs *auth_struct *old *old_lw [num_leafs: u64] [p]
            {leafs_loop}:
                dup 5 push {new_offset.read_address()} read_mem 1 pop 1 add
                read_mem 2 pop 1
                // _ num_leafs *auth_struct *old *old_lw [num_leafs] [p] [new_index]

                dup 7 read_mem 2 swap 10 pop 1
                // _ num_leafs *auth_struct *old (*old_lw - 2) [num_leafs] [p] [new_index] [index]

                dup 3 dup 2 eq dup 3 dup 2 eq mul
                assert error_id {Self::LEAF_INDICES_DIFFER_ERROR_ID}
                pick 3 pick 3 pop 2
                // _ num_leafs *auth_struct *old (*old_lw - 2) [num_leafs] [p] [index]

                dup 6 dup 2 lt
                dup 7 dup 3 eq
                dup 7 dup 3 lt
                mul add
                assert error_id {Self::LEAF_INDEX_GE_NUM_LEAFS_ERROR_ID}
                {&u64_to_bfe}
                dup 9 add
                // _ num_leafs *auth_struct *old (*old_lw - 2) [num_leafs] [p] node_index

                dup 6 read_mem {Digest::LEN} swap 12 pop 1
                // _ num_leafs *auth_struct *old (*old_lw - 7) [num_leafs] [p] node_index [old]

                dup 11 addi {Digest::LEN}
                push {new_offset.read_address()} read_mem 1 pop 1 add
                read_mem {Digest::LEN} pop 1
                // _ num_leafs *auth_struct *old (*old_lw - 7) [num_leafs] [p] node_index [old] [new]

                {&pair_to_xfe}
                pick 3
                {&node_factor}
                xx_mul
                // _ num_leafs *auth_struct *old (*old_lw - 7) [num_leafs] [p']

                recurse_or_return

            // INVARIANT: _ *auth_struct *auth_struct_lw [prev: u64] [p]
            {auth_struct_loop}:
                divine 2
                dup 6 dup 6 {&u64_lt}
                assert
                swap 5 pop 1 swap 5 pop 1
                // _ *auth_struct *auth_struct_lw [node_index] [p]

                dup 5 read_mem {Digest::LEN} swap 11 pop 1
                // _ *auth_struct (*auth_struct_lw - 5) [node_index] [p] [digest]

                {&digest_to_xfe}
                push {delta_plus_one.read_address()} read_mem {EXTENSION_DEGREE} pop 1
                xx_mul
                // _ *auth_struct *auth_struct_lw [node_index] [p] [(1 + delta) * xfe]

                dup 7 push {two_pow_32} mul dup 7 add
                {&node_factor}
                xx_mul
                // _ *auth_struct *auth_struct_lw [node_index] [p']

                recurse_or_return

            // INVARIANT: _ [p]
            {nd_loop}:
                divine 2
                dup 1 push 1 add eq assert
                swap 3 swap 2 swap 1
                // _ left_index [p]

                divine {Digest::LEN}
                {&store_digest(&right_old)}
                divine {Digest::LEN}
                {&store_digest(&right_new)}
                {&pair_to_xfe}
                dup 6 push 1 add
                {&node_factor}
                // _ left_index [p] [right_factor]

                divine {Digest::LEN}
                {&store_digest(&left_old)}
                divine {Digest::LEN}
                {&store_digest(&left_new)}
                {&pair_to_xfe}
                dup 9
                {&node_factor}
                // _ left_index [p] [right_factor] [left_factor]

                xx_mul x_invert xx_mul
                // _ left_index [p']

                {&read_digest(&right_old)}
                {&read_digest(&left_old)}
                hash
                {&read_digest(&right_new)}
                {&read_digest(&left_new)}
                hash
                // _ left_index [p'] [t_old] [t_new]

                dup 13 push 2 eq skiz call {store_ts}
                {&pair_to_xfe}
                dup 6 push {one_half} mul
                {&node_factor}
                xx_mul
                // _ left_index [p'']

                swap 1 swap 2 swap 3
                push 2 eq skiz return
                recurse

            // BEFORE: _ [t_old] [t_new]
            // AFTER:  _ [t_old] [t_new]
            {store_ts}:
                {&store_digest(&t_new)}
                pick 9 pick 9 pick 9 pick 9 pick 9
                {&store_digest(&t_old)}
                place 9 place 9 place 9 place 9 place 9
                return
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
    use tasm_lib::triton_vm::isa::instruction::AssertionError;
    use tasm_lib::triton_vm::vm::VMState;
    use tasm_lib::twenty_first::util_types::merkle_tree::MerkleTree;

    use super::*;

    /// Both roots the snippet leaves, if it accepts the inputs, with the
    /// stack checked to balance.
    fn tasm_roots(
        tree_height: u32,
        auth_struct: &[Digest],
        old_leafs: &[(u64, Digest)],
        new_leafs: &[(u64, Digest)],
        tokens: Vec<BFieldElement>,
    ) -> Result<(Digest, Digest), InstructionError> {
        let auth_struct_pointer = bfe!(1_000);
        let old_pointer = bfe!(10_000);
        let new_pointer = bfe!(20_000);
        let mut nondeterminism = NonDeterminism::new(tokens);
        encode_to_memory(
            &mut nondeterminism.ram,
            auth_struct_pointer,
            &auth_struct.to_vec(),
        );
        encode_to_memory(&mut nondeterminism.ram, old_pointer, &old_leafs.to_vec());
        encode_to_memory(&mut nondeterminism.ram, new_pointer, &new_leafs.to_vec());

        let program = Program::new(&RootsFromAuthenticationStruct.link_for_isolated_run());
        let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
        let init_stack = RootsFromAuthenticationStruct.init_stack_for_isolated_run();
        vm_state.op_stack.stack = [
            init_stack.clone(),
            vec![
                bfe!(tree_height),
                auth_struct_pointer,
                old_pointer,
                new_pointer,
            ],
        ]
        .concat();
        vm_state.run()?;

        let stack = &vm_state.op_stack.stack;
        assert_eq!(init_stack.len() + 2 * Digest::LEN, stack.len());
        assert_eq!(init_stack[..], stack[..init_stack.len()]);
        let digest_at = |start: usize| {
            let mut words = stack[start..start + Digest::LEN].to_vec();
            words.reverse();
            Digest::new(words.try_into().unwrap())
        };
        Ok((
            digest_at(init_stack.len()),
            digest_at(init_stack.len() + Digest::LEN),
        ))
    }

    /// A tree, some of its leaves changed: the structure and both indexed
    /// leaf lists, with the roots the Merkle trees give.
    struct Case {
        tree_height: u32,
        auth_struct: Vec<Digest>,
        old_leafs: Vec<(u64, Digest)>,
        new_leafs: Vec<(u64, Digest)>,
        old_root: Digest,
        new_root: Digest,
    }

    impl Case {
        fn random(rng: &mut StdRng, tree_height: u32, leaf_indices: &[u64]) -> Self {
            let num_leafs = 1_usize << tree_height;
            let old: Vec<Digest> = (0..num_leafs).map(|_| rng.random()).collect();
            let mut new = old.clone();
            for &index in leaf_indices {
                new[index as usize] = rng.random();
            }
            let old_tree = MerkleTree::par_new(&old).unwrap();
            let new_tree = MerkleTree::par_new(&new).unwrap();
            let (auth_struct_indices, _) =
                RootsFromAuthenticationStruct::auth_struct_and_sibling_indices(
                    tree_height,
                    leaf_indices,
                );
            let auth_struct = auth_struct_indices
                .iter()
                .map(|&node| old_tree.node(node as usize).unwrap())
                .collect();
            let leafs = |tree: &[Digest]| {
                leaf_indices
                    .iter()
                    .map(|&index| (index, tree[index as usize]))
                    .collect()
            };
            Self {
                tree_height,
                auth_struct,
                old_leafs: leafs(&old),
                new_leafs: leafs(&new),
                old_root: old_tree.root(),
                new_root: new_tree.root(),
            }
        }

        fn tokens(&self) -> Vec<BFieldElement> {
            let ((old_root, new_root), tokens) = RootsFromAuthenticationStruct::roots_and_tokens(
                self.tree_height,
                &self.auth_struct,
                &self.old_leafs,
                &self.new_leafs,
            );
            assert_eq!((self.old_root, self.new_root), (old_root, new_root));
            tokens
        }

        fn run(&self, tokens: Vec<BFieldElement>) -> Result<(Digest, Digest), InstructionError> {
            tasm_roots(
                self.tree_height,
                &self.auth_struct,
                &self.old_leafs,
                &self.new_leafs,
                tokens,
            )
        }

        fn assert_agrees(&self) {
            assert_eq!(Ok((self.old_root, self.new_root)), self.run(self.tokens()));
        }
    }

    fn random_leaf_indices(rng: &mut StdRng, tree_height: u32) -> Vec<u64> {
        let num_leafs = 1_u64 << tree_height;
        let mut indices = (0..num_leafs)
            .filter(|_| rng.random_bool(0.3))
            .collect::<Vec<_>>();
        if indices.is_empty() {
            indices.push(rng.random_range(0..num_leafs));
        }
        indices
    }

    #[test]
    fn both_roots_agree_with_the_merkle_trees() {
        let mut rng = StdRng::seed_from_u64(0);
        for tree_height in 0..7 {
            for _ in 0..8 {
                let leaf_indices = random_leaf_indices(&mut rng, tree_height);
                Case::random(&mut rng, tree_height, &leaf_indices).assert_agrees();
            }
        }
    }

    #[test]
    fn every_leaf_changed_and_no_structure_agrees() {
        let mut rng = StdRng::seed_from_u64(1);
        for tree_height in 0..5 {
            let all = (0..1_u64 << tree_height).collect::<Vec<_>>();
            let case = Case::random(&mut rng, tree_height, &all);
            assert!(case.auth_struct.is_empty());
            case.assert_agrees();
        }
    }

    #[test]
    fn unchanged_leaves_give_equal_roots() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut case = Case::random(&mut rng, 5, &[3, 17, 30]);
        case.new_leafs = case.old_leafs.clone();
        case.new_root = case.old_root;
        case.assert_agrees();
    }

    #[test]
    fn leaf_index_at_the_leaf_count_is_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut case = Case::random(&mut rng, 3, &[1, 6]);
        let tokens = case.tokens();
        case.old_leafs[1].0 = 8;
        case.new_leafs[1].0 = 8;
        let error = case.run(tokens).unwrap_err();
        assert!(matches!(
            error,
            InstructionError::AssertionFailed(AssertionError { id: Some(id), .. })
                if id == RootsFromAuthenticationStruct::LEAF_INDEX_GE_NUM_LEAFS_ERROR_ID
        ));
    }

    #[test]
    fn differing_leaf_indices_are_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut case = Case::random(&mut rng, 3, &[1, 6]);
        let tokens = case.tokens();
        case.new_leafs[0].0 = 2;
        let error = case.run(tokens).unwrap_err();
        assert!(matches!(
            error,
            InstructionError::AssertionFailed(AssertionError { id: Some(id), .. })
                if id == RootsFromAuthenticationStruct::LEAF_INDICES_DIFFER_ERROR_ID
        ));
    }

    #[test]
    fn tampered_structure_yields_other_roots_without_crashing() {
        let mut rng = StdRng::seed_from_u64(5);
        let mut case = Case::random(&mut rng, 4, &[2, 9]);
        case.auth_struct[0] = rng.random();
        let ((old_root, new_root), tokens) = RootsFromAuthenticationStruct::roots_and_tokens(
            case.tree_height,
            &case.auth_struct,
            &case.old_leafs,
            &case.new_leafs,
        );
        assert_ne!(case.old_root, old_root);
        assert_ne!(case.new_root, new_root);
        assert_eq!(Ok((old_root, new_root)), case.run(tokens));
    }

    #[test]
    fn tampered_divined_data_are_rejected() {
        let mut rng = StdRng::seed_from_u64(6);
        let case = Case::random(&mut rng, 4, &[2, 9, 10]);
        let honest = case.tokens();
        let (num_structure, _) = RootsFromAuthenticationStruct::auth_struct_and_sibling_indices(
            case.tree_height,
            &case.old_leafs.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        );
        let structure_words = 2 * num_structure.len();
        // Each pair: two indices, then four digests.
        let pair_words = 2 + 4 * Digest::LEN;
        // A tampered digest leaves the token structure intact, so the
        // product check itself must fail; a tampered index may derail the
        // reading first.
        for (position, must_be_assertion) in [
            (0, false),                                    // a structure node index
            (structure_words, false),                      // a pair's left index
            (structure_words + 1, false),                  // a pair's right index
            (structure_words + 2, true),                   // right old digest
            (structure_words + 2 + Digest::LEN, true),     // right new digest
            (structure_words + 2 + 2 * Digest::LEN, true), // left old digest
            (structure_words + 2 + 3 * Digest::LEN, true), // left new digest
            (structure_words + pair_words + 4, true),      // a later pair's digest
            (honest.len() - 1, true),                      // the root pair's last word
        ] {
            let mut tokens = honest.clone();
            tokens[position] += bfe!(1);
            let error = case.run(tokens).unwrap_err();
            if must_be_assertion {
                assert!(
                    matches!(error, InstructionError::AssertionFailed(_)),
                    "position {position}: {error}"
                );
            }
        }
    }

    #[test]
    fn swapped_old_and_new_digests_are_rejected() {
        let mut rng = StdRng::seed_from_u64(7);
        let case = Case::random(&mut rng, 3, &[5]);
        let honest = case.tokens();
        let (structure, _) =
            RootsFromAuthenticationStruct::auth_struct_and_sibling_indices(3, &[5]);
        let start = 2 * structure.len() + 2;
        let mut tokens = honest.clone();
        // Swap the right pair's old and new digests.
        let (old, new) = tokens[start..start + 2 * Digest::LEN].split_at_mut(Digest::LEN);
        old.swap_with_slice(new);
        assert!(matches!(
            case.run(tokens),
            Err(InstructionError::AssertionFailed(_))
        ));
    }

    #[test]
    fn pairs_of_non_siblings_are_rejected() {
        let mut rng = StdRng::seed_from_u64(8);
        let case = Case::random(&mut rng, 3, &[5]);
        let (structure, _) =
            RootsFromAuthenticationStruct::auth_struct_and_sibling_indices(3, &[5]);
        let mut tokens = case.tokens();
        let start = 2 * structure.len();
        tokens[start + 1] = tokens[start] + bfe!(2);
        assert!(case.run(tokens).is_err());
    }

    /// The premise: the changed leaves' authentication structure is the
    /// same before and after, since it consists of nodes no changed leaf
    /// lies under.
    #[test]
    fn structure_is_the_same_before_and_after() {
        let mut rng = StdRng::seed_from_u64(10);
        for tree_height in 1..7 {
            let leaf_indices = random_leaf_indices(&mut rng, tree_height);
            let num_leafs = 1_usize << tree_height;
            let old: Vec<Digest> = (0..num_leafs).map(|_| rng.random()).collect();
            let mut new = old.clone();
            for &index in &leaf_indices {
                new[index as usize] = rng.random();
            }
            let indices = leaf_indices.iter().map(|&i| i as usize).collect::<Vec<_>>();
            let old_structure = MerkleTree::par_new(&old)
                .unwrap()
                .authentication_structure(&indices)
                .unwrap();
            let new_structure = MerkleTree::par_new(&new)
                .unwrap()
                .authentication_structure(&indices)
                .unwrap();
            assert_eq!(old_structure, new_structure, "height {tree_height}");
        }
    }

    #[test]
    fn single_changed_leaf_in_a_tall_tree_agrees() {
        let mut rng = StdRng::seed_from_u64(11);
        Case::random(&mut rng, 12, &[2_027]).assert_agrees();
        Case::random(&mut rng, 12, &[0, 4_095]).assert_agrees();
    }

    #[test]
    fn empty_leaf_lists_are_rejected() {
        let mut rng = StdRng::seed_from_u64(12);
        let mut case = Case::random(&mut rng, 3, &[1]);
        let tokens = case.tokens();
        case.old_leafs.clear();
        case.new_leafs.clear();
        assert!(matches!(
            case.run(tokens),
            Err(InstructionError::AssertionFailed(_))
        ));
    }

    /// The lists are read in lockstep, so the same leaves in another order
    /// do not pass.
    #[test]
    fn reordered_new_leaves_are_rejected() {
        let mut rng = StdRng::seed_from_u64(13);
        let mut case = Case::random(&mut rng, 4, &[3, 8, 12]);
        let tokens = case.tokens();
        case.new_leafs.swap(0, 2);
        assert!(matches!(
            case.run(tokens),
            Err(InstructionError::AssertionFailed(AssertionError { id: Some(id), .. }))
                if id == RootsFromAuthenticationStruct::LEAF_INDICES_DIFFER_ERROR_ID
        ));
    }

    /// A pair's parent index is the left index halved, which presumes the
    /// left index even; a pair of neighbours that are not siblings must not
    /// balance the product.
    #[test]
    fn pair_with_odd_left_index_is_rejected() {
        let mut rng = StdRng::seed_from_u64(14);
        let case = Case::random(&mut rng, 4, &[6]);
        let (structure, pairs) =
            RootsFromAuthenticationStruct::auth_struct_and_sibling_indices(4, &[6]);
        let mut tokens = case.tokens();
        let start = 2 * structure.len();
        assert_eq!(bfe!(pairs[0].0), tokens[start]);
        tokens[start] += bfe!(1);
        tokens[start + 1] += bfe!(1);
        assert!(matches!(
            case.run(tokens),
            Err(InstructionError::AssertionFailed(_))
        ));
    }

    /// The loop runs until the root pair; fewer pairs leave it reading
    /// past the tokens.
    #[test]
    fn truncated_tokens_are_rejected() {
        let mut rng = StdRng::seed_from_u64(15);
        let case = Case::random(&mut rng, 4, &[6, 9]);
        let mut tokens = case.tokens();
        tokens.truncate(tokens.len() - 2 - 4 * Digest::LEN);
        assert!(case.run(tokens).is_err());
    }

    /// Tokens past the root pair are never read.
    #[test]
    fn extra_tokens_are_ignored() {
        let mut rng = StdRng::seed_from_u64(16);
        let case = Case::random(&mut rng, 4, &[6, 9]);
        let mut tokens = case.tokens();
        tokens.extend([bfe!(7); 10]);
        assert_eq!(Ok((case.old_root, case.new_root)), case.run(tokens));
    }

    #[test]
    fn structure_indices_out_of_order_are_rejected() {
        let mut rng = StdRng::seed_from_u64(9);
        let case = Case::random(&mut rng, 4, &[2, 9]);
        let mut tokens = case.tokens();
        // Two structure node indices, two words each, swapped.
        tokens.swap(0, 2);
        tokens.swap(1, 3);
        assert!(case.run(tokens).is_err());
    }
}
