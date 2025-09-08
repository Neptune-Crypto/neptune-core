use itertools::Itertools;
use tasm_lib::prelude::*;
use tasm_lib::twenty_first::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
use tasm_lib::twenty_first::util_types::mmr::shared_advanced::get_peak_heights;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;
use tasm_lib::verifier::stark_verify::StarkVerify;
use triton_vm::prelude::*;

use super::environment::ND_INDIVIDUAL_TOKEN;
use super::environment::ND_MEMORY;
use super::environment::PROGRAM_DIGEST;
use super::environment::PUB_INPUT;
use super::environment::PUB_OUTPUT;
use crate::protocol::proof_abstractions::tasm::environment::ND_DIGESTS;

/// Get the hash digest of the program that's currently running.
pub fn own_program_digest() -> Digest {
    PROGRAM_DIGEST.with(|v| *v.borrow())
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_stdin___bfe() -> BFieldElement {
    PUB_INPUT.with(|v| v.borrow_mut().pop_front().unwrap())
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_stdin___xfe() -> XFieldElement {
    let x2 = PUB_INPUT.with(|v| v.borrow_mut().pop_front().unwrap());
    let x1 = PUB_INPUT.with(|v| v.borrow_mut().pop_front().unwrap());
    let x0 = PUB_INPUT.with(|v| v.borrow_mut().pop_front().unwrap());
    XFieldElement::new([x0, x1, x2])
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_stdin___u32() -> u32 {
    let val: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    val
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_stdin___u64() -> u64 {
    let hi: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    let lo: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    (u64::from(hi) << 32) + u64::from(lo)
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_stdin___u128() -> u128 {
    let e3: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    let e2: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    let e1: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    let e0: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    (u128::from(e3) << 96) + (u128::from(e2) << 64) + (u128::from(e1) << 32) + u128::from(e0)
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_stdin___digest() -> Digest {
    let e4 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e3 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e2 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e1 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e0 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    Digest::new([e0, e1, e2, e3, e4])
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___bfe(x: BFieldElement) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(x));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___xfe(x: XFieldElement) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.coefficients.to_vec()));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___digest(x: Digest) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.values().to_vec()));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___bool(x: bool) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(BFieldElement::new(u64::from(x))));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___u32(x: u32) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(BFieldElement::new(u64::from(x))));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___u64(x: u64) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.encode()));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___u128(x: u128) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.encode()));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___encoding<T: BFieldCodec>(t: T) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(t.encode()));
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_secin___bfe() -> BFieldElement {
    ND_INDIVIDUAL_TOKEN.with(|v| v.borrow_mut().pop_front().unwrap())
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_secin___u64() -> u64 {
    let hi: u32 = ND_INDIVIDUAL_TOKEN
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    let lo: u32 = ND_INDIVIDUAL_TOKEN
        .with(|v| v.borrow_mut().pop_front().unwrap())
        .try_into()
        .unwrap();
    (u64::from(hi) << 32) + u64::from(lo)
}

#[expect(non_snake_case)]
pub fn tasmlib_io_read_secin___digest() -> Digest {
    let e4 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e3 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e2 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e1 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e0 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop_front()
            .expect("cannot read digest from secin -- input not long enough")
    });
    Digest::new([e0, e1, e2, e3, e4])
}

/// Verify a Merkle tree membership claim using the nondeterministically
/// supplied digests as authentication path. Crashes the VM if verification
/// fails.
pub fn tasmlib_hashing_merkle_verify(
    root: Digest,
    leaf_index: u32,
    leaf: Digest,
    tree_height: u32,
) {
    let mut path: Vec<Digest> = vec![];

    ND_DIGESTS.with_borrow_mut(|nd_digests| {
        for _ in 0..tree_height {
            path.push(nd_digests.pop_front().unwrap());
        }
    });

    let mt_inclusion_proof = MerkleTreeInclusionProof {
        tree_height,
        indexed_leafs: vec![(leaf_index as usize, leaf)],
        authentication_structure: path.clone(),
    };

    assert!(
        mt_inclusion_proof.verify(root),
        "expected root {root} but that's not what we got"
    );
}

pub fn mmr_verify_from_secret_in_leaf_index_on_stack(
    peaks: &[Digest],
    num_leafs: u64,
    leaf_index: u64,
    leaf: Digest,
) -> bool {
    let (_, peak_index) = leaf_index_to_mt_index_and_peak_index(leaf_index, num_leafs);
    let peak_index = peak_index as usize;
    let peak_heights = get_peak_heights(num_leafs);
    let tree_height = peak_heights[peak_index];

    let mut auth_path: Vec<Digest> = vec![];
    ND_DIGESTS.with_borrow_mut(|nd_digests| {
        for _ in 0..tree_height {
            auth_path.push(nd_digests.pop_front().unwrap());
        }
    });
    let mmr_mp = MmrMembershipProof::new(auth_path);

    mmr_mp.verify(leaf_index, leaf, peaks, num_leafs)
}

/// Test whether two lists of digests are equal, up to order.
pub fn tasmlib_list_unsafeimplu32_multiset_equality(left: Vec<Digest>, right: Vec<Digest>) {
    assert_eq!(left.len(), right.len());
    let mut left_sorted = left.clone();
    left_sorted.sort();

    let mut right_sorted = right.clone();
    right_sorted.sort();

    assert_eq!(left_sorted, right_sorted);
}

pub(crate) struct EnvironmentMemoryIter(pub BFieldElement);

impl Iterator for EnvironmentMemoryIter {
    type Item = BFieldElement;

    fn next(&mut self) -> Option<Self::Item> {
        let value = ND_MEMORY.with(|v| {
            v.borrow()
                .get(&self.0)
                .copied()
                .unwrap_or_else(|| BFieldElement::new(0))
        });
        self.0.increment();
        Some(value)
    }
}

/// In nondeterministically-initialized memory, there lives an object of type
/// T. Given a pointer to it, get that object.
///
/// In TritonVM, this operation has no effect. the rust shadow, we decode the
/// object that lives there.
pub fn decode_from_memory<T: TasmObject>(start_address: BFieldElement) -> T {
    let mut iterator = EnvironmentMemoryIter(start_address);
    *T::decode_iter(&mut iterator).expect("decode from memory failed")
}

/// Verify a STARK proof. Crashes if the (claim, proof) pair is invalid.
///
/// Consumes the right number of non-deterministic digests from the
/// non-deterministic digests stream. Also consumes the right number of
/// non-deterministic individual tokens from the non-deterministic individual
/// tokens stream. The latter number happens to be 0 right now, but that might
/// change if the `StarkVerify` snippet changes.
pub fn verify_stark(stark_parameters: Stark, claim: &Claim, proof: &Proof) {
    assert!(triton_vm::verify(stark_parameters, claim, proof));

    let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(stark_parameters);

    let num_digests_consumed =
        stark_verify_snippet.number_of_nondeterministic_digests_consumed(proof);
    ND_DIGESTS.with_borrow_mut(|digest_stream| {
        (0..num_digests_consumed).for_each(|_| {
            digest_stream.pop_front().expect(
                "digest stream should contain all digests divined by `StarkVerify` snippet",
            );
        })
    });

    let num_tokens_consumed =
        stark_verify_snippet.number_of_nondeterministic_tokens_consumed(proof, claim);
    ND_INDIVIDUAL_TOKEN.with_borrow_mut(|token_stream| {
        (0..num_tokens_consumed).for_each(|_| {
            token_stream
                .pop_front()
                .expect("token stream should contain all tokens divined by `StarkVerify` snippet");
        })
    });
}

/// Verify an MMR successor proof. Crashes if the proof is invalid for the given
/// MMR accumulators.
///
/// Removes the [`MmrSuccessorProof`]'s authentication path from the
/// environment's [`NonDeterminism`].
///
/// # Panics
///
/// - if the proof does not establish a valid successor relationship between the
///   old and new MMRs
/// - if the authentication path present in non-determinism is different from the
///   one in the passed-in proof
pub fn verify_mmr_successor_proof(
    old_mmr: &MmrAccumulator,
    new_mmr: &MmrAccumulator,
    proof: &MmrSuccessorProof,
) {
    let mut proof_paths = vec![];
    if !proof.paths.is_empty() {
        ND_INDIVIDUAL_TOKEN.with_borrow_mut(|tokens| {
            let first_digest = (0..Digest::LEN)
                .map(|_| tokens.pop_front().expect("should find proof path tokens"))
                .collect_vec()
                .try_into()
                .unwrap();
            proof_paths.push(Digest::new(first_digest).reversed());
        });
    }

    ND_DIGESTS.with_borrow_mut(|digest_stream| {
        for _ in 1..proof.paths.len() {
            proof_paths.push(digest_stream.pop_front().expect(
                "digest stream should contain all digests divined by `VerifyMmrSuccessor` snippet",
            ));
        }
    });

    assert_eq!(proof_paths, proof.paths);

    assert!(proof.verify(old_mmr, new_mmr));
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use tasm_lib::verifier::stark_verify::StarkVerify;

    use super::*;
    use crate::protocol::proof_abstractions;
    use crate::protocol::proof_abstractions::tasm::builtins::verify_stark;
    use crate::protocol::proof_abstractions::Claim;
    use crate::protocol::proof_abstractions::Program;

    #[test]
    fn can_verify_halt_in_emulated_environment() {
        let program_code = triton_asm! { halt };
        let program = Program::new(&program_code);
        let claim = Claim::about_program(&program);
        let stark_parameters = Stark::default();
        let proof = triton_vm::prove(
            stark_parameters,
            &claim,
            program.clone(),
            NonDeterminism::new(vec![]),
        )
        .unwrap();

        let mut nondeterminism = NonDeterminism::new(vec![]);
        StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
            &mut nondeterminism,
            &proof,
            &claim,
        );

        proof_abstractions::tasm::environment::init(program.hash(), &[], nondeterminism);

        verify_stark(stark_parameters, &claim, &proof);
    }
}
