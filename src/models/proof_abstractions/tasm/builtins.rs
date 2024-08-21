use itertools::Itertools;
use tasm_lib::memory::{encode_to_memory, last_populated_nd_memory_address};
use tasm_lib::prelude::Library;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::program::Program;
use tasm_lib::triton_vm::vm::VMState;
use tasm_lib::verifier::stark_verify::StarkVerify;
use tasm_lib::{
    triton_vm::program::NonDeterminism, triton_vm::proof::Claim, triton_vm::proof::Proof,
    triton_vm::stark::Stark, twenty_first::math::b_field_element::BFieldElement,
    twenty_first::math::x_field_element::XFieldElement, twenty_first::prelude::MmrMembershipProof,
    twenty_first::util_types::merkle_tree::MerkleTreeInclusionProof,
    twenty_first::util_types::mmr::shared_advanced::get_peak_heights,
    twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index, Digest,
};

use crate::models::proof_abstractions::tasm::environment::ND_DIGESTS;
use crate::triton_vm::triton_asm;

use super::environment::{ND_INDIVIDUAL_TOKEN, ND_MEMORY, PROGRAM_DIGEST, PUB_INPUT, PUB_OUTPUT};

/// Get the hash digest of the program that's currently running.
pub fn own_program_digest() -> Digest {
    PROGRAM_DIGEST.with(|v| *v.borrow())
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_stdin___bfe() -> BFieldElement {
    #[allow(clippy::unwrap_used)]
    PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap())
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_stdin___xfe() -> XFieldElement {
    let x2 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let x1 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let x0 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    XFieldElement::new([x0, x1, x2])
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_stdin___u32() -> u32 {
    #[allow(clippy::unwrap_used)]
    let val: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    val
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_stdin___u64() -> u64 {
    #[allow(clippy::unwrap_used)]
    let hi: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    let lo: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    ((hi as u64) << 32) + lo as u64
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_stdin___u128() -> u128 {
    #[allow(clippy::unwrap_used)]
    let e3: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    let e2: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    let e1: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    let e0: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    ((e3 as u128) << 96) + ((e2 as u128) << 64) + ((e1 as u128) << 32) + e0 as u128
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_stdin___digest() -> Digest {
    let e4 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e3 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e2 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e1 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    let e0 = PUB_INPUT.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from stdin -- input not long enough")
    });
    Digest::new([e0, e1, e2, e3, e4])
}

#[allow(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___bfe(x: BFieldElement) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(x));
}

#[allow(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___xfe(x: XFieldElement) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.coefficients.to_vec()));
}

#[allow(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___digest(x: Digest) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.values().to_vec()));
}

#[allow(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___bool(x: bool) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(BFieldElement::new(x as u64)));
}

#[allow(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___u32(x: u32) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(BFieldElement::new(x as u64)));
}

#[allow(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___u64(x: u64) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.encode()));
}

#[allow(non_snake_case)]
pub fn tasmlib_io_write_to_stdout___u128(x: u128) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.encode()));
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_secin___bfe() -> BFieldElement {
    #[allow(clippy::unwrap_used)]
    ND_INDIVIDUAL_TOKEN.with(|v| v.borrow_mut().pop().unwrap())
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_secin___u64() -> u64 {
    #[allow(clippy::unwrap_used)]
    let hi: u32 = ND_INDIVIDUAL_TOKEN
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    let lo: u32 = ND_INDIVIDUAL_TOKEN
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    ((hi as u64) << 32) + lo as u64
}

#[allow(non_snake_case)]
pub fn tasmlib_io_read_secin___digest() -> Digest {
    let e4 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e3 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e2 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e1 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from secin -- input not long enough")
    });
    let e0 = ND_INDIVIDUAL_TOKEN.with(|v| {
        v.borrow_mut()
            .pop()
            .expect("cannot read digest from secin -- input not long enough")
    });
    Digest::new([e0, e1, e2, e3, e4])
}

/// Verify a Merkle tree membership claim using the nondeterministically supplied digests
/// as authentication path.
pub fn tasmlib_hashing_merkle_verify(
    root: Digest,
    leaf_index: u32,
    leaf: Digest,
    tree_height: u32,
) {
    let mut path: Vec<Digest> = vec![];

    ND_DIGESTS.with_borrow_mut(|nd_digests| {
        for _ in 0..tree_height {
            path.push(nd_digests.pop().unwrap());
        }
    });

    let mt_inclusion_proof = MerkleTreeInclusionProof {
        tree_height: tree_height as usize,
        indexed_leafs: vec![(leaf_index as usize, leaf)],
        authentication_structure: path.clone(),
    };

    assert!(mt_inclusion_proof.verify(root));
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
            auth_path.push(nd_digests.pop().unwrap());
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
                .cloned()
                .unwrap_or_else(|| BFieldElement::new(0))
        });
        self.0.increment();
        Some(value)
    }
}

/// In nondeterministically-initialized memory, there lives an object of type T. Given a
/// pointer to it, get that object. In TritonVM, this operation has no effect. the rust
/// shadow, we decode the object that lives there.
pub fn decode_from_memory<T: TasmObject>(start_address: BFieldElement) -> T {
    let mut iterator = EnvironmentMemoryIter(start_address);
    *T::decode_iter(&mut iterator).expect("decode from memory failed")
}

/// Verify a STARK proof.
pub fn verify_stark(stark_parameters: Stark, claim: Claim, proof: &Proof) -> bool {
    // We want to verify the proof in a way that updates the emulated environment (in
    // particular: non-determinism) in the exact same way that the actual verify snippet
    // modifies the actual Triton VM environment. However, there is no rust (or host
    // machine) code that modifies the environment accurately because this is too
    // much hassle to write for too little benefit. So what we do here is invoke the
    // tasm snippet, wrapped in make-shift program, in Triton VM and percolate the
    // induced environment changes.

    let stark_verify_snippet = StarkVerify::new_with_dynamic_layout(stark_parameters);

    // create nondeterminism object for running Triton VM and populate it with
    // the contents of the environment's variables
    let mut nondeterminism =
        NonDeterminism::new(ND_INDIVIDUAL_TOKEN.with_borrow(|tokens| tokens.clone()))
            .with_digests(ND_DIGESTS.with_borrow(|digests| digests.clone()))
            .with_ram(ND_MEMORY.with_borrow(|memory| memory.clone()));

    // update the nondeterminism in anticipation of verifying the proof
    stark_verify_snippet.update_nondeterminism(&mut nondeterminism, proof, claim.clone());

    // store the proof and claim to memory
    let highest_nd_address = last_populated_nd_memory_address(&nondeterminism.ram).unwrap_or(0);
    let proof_pointer = BFieldElement::new(highest_nd_address as u64 + 1);
    let claim_pointer = encode_to_memory(&mut nondeterminism.ram, proof_pointer, proof);
    encode_to_memory(&mut nondeterminism.ram, claim_pointer, &claim);

    // create a tasm program to verify the claim+proof
    let mut library = Library::new();
    let stark_verify = library.import(Box::new(stark_verify_snippet.clone()));
    let program_code = triton_asm! {
        push {claim_pointer}
        push {proof_pointer}
        call {stark_verify}
        halt
        {&library.all_imports()}
    };
    let program = Program::new(&program_code);

    // report on error, if any
    if let Err(vm_error) = program.run(vec![].into(), nondeterminism.clone()) {
        println!("Erro verifying STARK proof.");
        println!("instruction error: {}", vm_error.source);
        println!("VM state:\n{}", vm_error.vm_state);
        return false;
    }

    // run the program and get the final state
    let mut vm_state = VMState::new(&program, vec![].into(), nondeterminism);
    vm_state.run().unwrap();

    // percolate the environment changes
    ND_MEMORY.replace(vm_state.ram);
    ND_DIGESTS.replace(vm_state.secret_digests.into_iter().collect_vec());
    ND_INDIVIDUAL_TOKEN.replace(vm_state.secret_individual_tokens.into_iter().collect_vec());

    true
}

#[cfg(test)]
mod test {
    use crate::models::proof_abstractions::tasm::builtins::verify_stark;
    use crate::models::proof_abstractions::Claim;
    use crate::models::proof_abstractions::Program;
    use crate::triton_vm;
    use tasm_lib::triton_vm::program::NonDeterminism;
    use tasm_lib::triton_vm::stark::Stark;
    use tasm_lib::triton_vm::triton_asm;

    #[test]
    fn can_verify_halt_in_emulated_environment() {
        let program_code = triton_asm! { halt };
        let program = Program::new(&program_code);
        let claim = Claim::new(program.hash());
        let stark_parameters = Stark::default();
        let proof = triton_vm::prove(
            stark_parameters,
            &claim,
            &program,
            NonDeterminism::new(vec![]),
        ).unwrap();
        assert!(verify_stark(stark_parameters, claim, &proof));
    }
}
