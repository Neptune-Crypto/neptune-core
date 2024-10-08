use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::math::x_field_element::XFieldElement;
use tasm_lib::twenty_first::util_types::merkle_tree::MerkleTreeInclusionProof;
use tasm_lib::Digest;

use crate::models::blockchain::shared::Hash;
use crate::models::consensus::tasm::environment::ND_DIGESTS;

use super::environment::ND_INDIVIDUAL_TOKEN;
use super::environment::ND_MEMORY;
use super::environment::PROGRAM_DIGEST;
use super::environment::PUB_INPUT;
use super::environment::PUB_OUTPUT;

/// Get the hash digest of the program that's currently running.
pub fn own_program_digest() -> Digest {
    PROGRAM_DIGEST.with(|v| *v.borrow())
}

#[allow(non_snake_case)]
pub fn tasm_io_read_stdin___bfe() -> BFieldElement {
    #[allow(clippy::unwrap_used)]
    PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap())
}

#[allow(non_snake_case)]
pub fn tasm_io_read_stdin___xfe() -> XFieldElement {
    let x2 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let x1 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let x0 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    XFieldElement::new([x0, x1, x2])
}

#[allow(non_snake_case)]
pub fn tasm_io_read_stdin___u32() -> u32 {
    #[allow(clippy::unwrap_used)]
    let val: u32 = PUB_INPUT
        .with(|v| v.borrow_mut().pop().unwrap())
        .try_into()
        .unwrap();
    val
}

#[allow(non_snake_case)]
pub fn tasm_io_read_stdin___u64() -> u64 {
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
pub fn tasm_io_read_stdin___u128() -> u128 {
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
pub fn tasm_io_read_stdin___digest() -> Digest {
    let e4 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let e3 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let e2 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let e1 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    let e0 = PUB_INPUT.with(|v| v.borrow_mut().pop().unwrap());
    Digest::new([e0, e1, e2, e3, e4])
}

#[allow(non_snake_case)]
pub fn tasm_io_write_to_stdout___bfe(x: BFieldElement) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(x));
}

#[allow(non_snake_case)]
pub fn tasm_io_write_to_stdout___xfe(x: XFieldElement) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.coefficients.to_vec()));
}

#[allow(non_snake_case)]
pub fn tasm_io_write_to_stdout___digest(x: Digest) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.values().to_vec()));
}

#[allow(non_snake_case)]
pub fn tasm_io_write_to_stdout___bool(x: bool) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(BFieldElement::new(x as u64)));
}

#[allow(non_snake_case)]
pub fn tasm_io_write_to_stdout___u32(x: u32) {
    PUB_OUTPUT.with(|v| v.borrow_mut().push(BFieldElement::new(x as u64)));
}

#[allow(non_snake_case)]
pub fn tasm_io_write_to_stdout___u64(x: u64) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.encode()));
}

#[allow(non_snake_case)]
pub fn tasm_io_write_to_stdout___u128(x: u128) {
    PUB_OUTPUT.with(|v| v.borrow_mut().extend(x.encode()));
}

#[allow(non_snake_case)]
pub fn tasm_io_read_secin___bfe() -> BFieldElement {
    #[allow(clippy::unwrap_used)]
    ND_INDIVIDUAL_TOKEN.with(|v| v.borrow_mut().pop().unwrap())
}

/// Verify a Merkle tree membership claim using the nondeterministically supplied digests
/// as authentication path.
pub fn tasm_hashing_merkle_verify(root: Digest, leaf_index: u32, leaf: Digest, tree_height: u32) {
    let mut path: Vec<Digest> = vec![];

    ND_DIGESTS.with_borrow_mut(|nd_digests| {
        for _ in 0..tree_height {
            path.push(nd_digests.pop().unwrap());
        }
    });

    let mt_inclusion_proof = MerkleTreeInclusionProof::<Hash> {
        tree_height: tree_height as usize,
        indexed_leaves: vec![(leaf_index as usize, leaf)],
        authentication_structure: path,
        _hasher: std::marker::PhantomData,
    };

    assert!(mt_inclusion_proof.verify(root));
}

/// Test whether two lists of digests are equal, up to order.
pub fn tasm_list_unsafeimplu32_multiset_equality(left: Vec<Digest>, right: Vec<Digest>) {
    assert_eq!(left.len(), right.len());
    let mut left_sorted = left.clone();
    left_sorted.sort();

    let mut right_sorted = right.clone();
    right_sorted.sort();

    assert_eq!(left_sorted, right_sorted);
}

struct EnvironmentMemoryIter(pub BFieldElement);

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
    *T::decode_iter(&mut iterator).unwrap()
}
