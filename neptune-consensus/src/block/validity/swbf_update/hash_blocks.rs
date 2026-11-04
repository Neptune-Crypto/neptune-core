//! The hash of words stored padded: the blocks of ten words absorbed
//! straight from memory, so that the digest is that of `Tip5::hash_varlen`
//! of the words before the padding.

use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

use super::absorb_blocks::AbsorbBlocks;

/// ```text
/// BEFORE: _ *blocks num_blocks
/// AFTER:  _ [digest]
/// ```
///
/// The words come padded the way the sponge pads them: a one after the
/// last word, then zeros to a multiple of ten; see [`Self::padded`].
#[derive(Debug, Copy, Clone)]
pub(super) struct HashBlocks;

impl HashBlocks {
    /// The words padded for the sponge.
    pub(super) fn padded(words: &[BFieldElement]) -> Vec<BFieldElement> {
        let mut padded = words.to_vec();
        padded.push(bfe!(1));
        padded.resize(padded.len().next_multiple_of(10), bfe!(0));
        padded
    }

    /// A chunk's storage in the witness: its encoding, the length of the
    /// rest then its sorted list of set indices, padded for the sponge, so
    /// that its hash is the hash of the blocks.
    pub(super) fn chunk_storage(chunk: &[u32]) -> Vec<BFieldElement> {
        let mut encoding = vec![bfe!(chunk.len() as u64 + 1), bfe!(chunk.len() as u64)];
        encoding.extend(chunk.iter().map(|&index| bfe!(index)));
        Self::padded(&encoding)
    }

    /// The chunk's list of set indices, out of its storage.
    pub(super) fn chunk(storage: &[BFieldElement]) -> Vec<u32> {
        let len = storage[1].value() as usize;
        storage[2..2 + len]
            .iter()
            .map(|word| u32::try_from(word.value()).expect("a chunk holds u32s"))
            .collect()
    }
}

impl BasicSnippet for HashBlocks {
    fn parameters(&self) -> Vec<(DataType, String)> {
        AbsorbBlocks.parameters()
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "digest".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_hash_blocks".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let absorb_blocks = library.import(Box::new(AbsorbBlocks));

        triton_asm!(
            // BEFORE: _ *blocks num_blocks
            // AFTER:  _ [digest]
            {self.entrypoint()}:
                sponge_init
                call {absorb_blocks}
                sponge_squeeze
                pick 9 pick 9 pick 9 pick 9 pick 9 pop 5
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
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::vm::VMState;

    use super::*;

    #[test]
    fn hashes_like_the_host() {
        let mut rng = StdRng::seed_from_u64(0);
        for num_words in (0..=30).chain([159, 160, 161, 199, 200, 201, 412, 413, 4_096]) {
            let words = (0..num_words)
                .map(|_| rng.random())
                .collect::<Vec<BFieldElement>>();
            let padded = HashBlocks::padded(&words);
            let pointer = bfe!(1_000);
            let mut nondeterminism = NonDeterminism::default();
            for (i, &word) in padded.iter().enumerate() {
                nondeterminism.ram.insert(pointer + bfe!(i as u64), word);
            }
            let program = Program::new(&HashBlocks.link_for_isolated_run());
            let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
            vm_state.op_stack.stack = [
                HashBlocks.init_stack_for_isolated_run(),
                vec![pointer, bfe!(padded.len() as u64 / 10)],
            ]
            .concat();
            vm_state.run().unwrap();
            let stack = &vm_state.op_stack.stack;
            let mut digest = stack[stack.len() - Digest::LEN..].to_vec();
            digest.reverse();
            assert_eq!(
                Tip5::hash_varlen(&words),
                Digest::new(digest.try_into().unwrap()),
                "{num_words} words"
            );
        }
    }

    #[test]
    fn chunk_storage_round_trips_and_hashes_like_the_chunk() {
        for chunk_len in [0, 7, 8, 17, 412] {
            let chunk = (0..chunk_len as u32).collect::<Vec<_>>();
            let storage = HashBlocks::chunk_storage(&chunk);
            assert_eq!(chunk, HashBlocks::chunk(&storage));
            assert!(storage.len().is_multiple_of(10));
            let expected = Tip5::hash(&neptune_mutator_set::removal_record::chunk::Chunk {
                relative_indices: chunk,
            });
            let pointer = bfe!(1_000);
            let mut nondeterminism = NonDeterminism::default();
            for (i, &word) in storage.iter().enumerate() {
                nondeterminism.ram.insert(pointer + bfe!(i as u64), word);
            }
            let program = Program::new(&HashBlocks.link_for_isolated_run());
            let mut vm_state = VMState::new(program, PublicInput::default(), nondeterminism);
            vm_state.op_stack.stack = [
                HashBlocks.init_stack_for_isolated_run(),
                vec![pointer, bfe!(storage.len() as u64 / 10)],
            ]
            .concat();
            vm_state.run().unwrap();
            let stack = &vm_state.op_stack.stack;
            let mut digest = stack[stack.len() - Digest::LEN..].to_vec();
            digest.reverse();
            assert_eq!(
                expected,
                Digest::new(digest.try_into().unwrap()),
                "{chunk_len}"
            );
        }
    }
}
