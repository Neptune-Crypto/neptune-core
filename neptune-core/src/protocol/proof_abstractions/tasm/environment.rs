//! This module contains functions for interacting with the input/output monad
//! implicit in a VM execution. It contains functions for mutating and verifying
//! the correct content of the input/output while executing a Rust function
//! on the host machine's native architecture (i.e. your machine).
//!
//! It has been shamelessly copied from greenhat's omnizk compiler project:
//! <https://github.com/greenhat/omnizk>

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::VecDeque;

use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;

thread_local! {
    pub(super) static PUB_INPUT: RefCell<VecDeque<BFieldElement>> = const {RefCell::new(VecDeque::new())};
    pub(super) static PUB_OUTPUT: RefCell<Vec<BFieldElement>> = const { RefCell::new(vec![])};

    pub(super) static ND_INDIVIDUAL_TOKEN: RefCell<VecDeque<BFieldElement>> = const{RefCell::new(VecDeque::new())};
    pub(super) static ND_DIGESTS: RefCell<VecDeque<Digest>> = const{RefCell::new(VecDeque::new())};
    pub(super) static ND_MEMORY: RefCell<HashMap<BFieldElement, BFieldElement>> =
        RefCell::new(HashMap::default());

    pub(super) static PROGRAM_DIGEST: RefCell<Digest> = RefCell::new(Digest::default());
}

#[cfg(test)]
pub(crate) fn audit_end_state() {
    assert!(ND_DIGESTS.with_borrow(|f| f.is_empty()));
    assert!(PUB_INPUT.with_borrow(|f| f.is_empty()));
    assert!(ND_INDIVIDUAL_TOKEN.with_borrow(|f| f.is_empty()));
}

#[cfg(test)]
pub(crate) fn init(
    program_digest: Digest,
    input: &[BFieldElement],
    nondeterminism: tasm_lib::triton_vm::prelude::NonDeterminism,
) {
    PUB_INPUT.with(|v| {
        *v.borrow_mut() = input.to_vec().into();
    });
    ND_INDIVIDUAL_TOKEN.with(|v| {
        *v.borrow_mut() = nondeterminism.individual_tokens.into();
    });
    ND_DIGESTS.with(|v| {
        *v.borrow_mut() = nondeterminism.digests.into();
    });
    ND_MEMORY.with(|v| {
        *v.borrow_mut() = nondeterminism.ram;
    });
    PUB_OUTPUT.with(|v| {
        *v.borrow_mut() = vec![];
    });
    PROGRAM_DIGEST.with(|v| {
        *v.borrow_mut() = program_digest;
    });
}
