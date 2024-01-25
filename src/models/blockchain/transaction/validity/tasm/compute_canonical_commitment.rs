use crate::prelude::{triton_vm, twenty_first};

use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use crate::util_types::mutator_set::ms_membership_proof::pseudorandom_mutator_set_membership_proof;
use num_traits::{One, Zero};
use rand::RngCore;
use rand::{rngs::StdRng, Rng, SeedableRng};
use tasm_lib::data_type::DataType;
use tasm_lib::empty_stack;
use tasm_lib::library::Library;
use tasm_lib::memory::push_ram_to_stack::PushRamToStack;
use tasm_lib::neptune::mutator_set::commit::Commit;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::traits::function::{Function, FunctionInitialState};
use triton_vm::prelude::{triton_asm, BFieldElement, Digest};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::util_types::mutator_set::{
    ms_membership_proof::MsMembershipProof, mutator_set_trait::commit,
};

/// Compute a canonical commitment from an item and its membership proof.
#[derive(Debug, Clone)]
pub(crate) struct ComputeCanonicalCommitment;

impl BasicSnippet for ComputeCanonicalCommitment {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::Tuple(vec![DataType::Digest, DataType::VoidPointer]),
            "item_and_*membership_proof".to_string(),
        )]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(
            DataType::Tuple(vec![DataType::VoidPointer, DataType::Digest]),
            "*membership_proof_and_canonical_commitment".to_string(),
        )]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_compute_commitment".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<triton_vm::instruction::LabelledInstruction> {
        type MsMpH = MsMembershipProof<Hash>;
        let mp_to_sr = tasm_lib::field!(MsMpH::sender_randomness);
        let mp_to_rp = tasm_lib::field!(MsMpH::receiver_preimage);
        let commit = library.import(Box::new(Commit));
        let read_digest = library.import(Box::new(PushRamToStack {
            data_type: DataType::Digest,
        }));
        let entrypoint = self.entrypoint();

        triton_asm! {
        // BEFORE: _  i4 i3 i2 i1 i0 *mp
        // AFTER: _  *mp c4 c3 c2 c1 c0
        {entrypoint}:
            swap 5 swap 4 swap 3 swap 2 swap 1 dup 5
            // _  *mp i4 i3 i2 i1 i0 *mp

            dup 0                   // _ *mp i4 i3 i2 i1 i0 *mp *mp
            {&mp_to_sr}             // _ *mp i4 i3 i2 i1 i0 *mp *sr
            swap 1                  // _ *mp i4 i3 i2 i1 i0 *sr *mp
            {&mp_to_rp}             // _ *mp i4 i3 i2 i1 i0 *sr *rp_si

            push 0 push 0 push 0 push 0 push 0
            swap 5                  // _ *mp i4 i3 i2 i1 i0 *sr 0 0 0 0 0 *rp

            call {read_digest} // _ *mp i4 i3 i2 i1 i0 *sr 0 0 0 0 0 [receiver_preimage]
            hash
            // _ *mp i4 i3 i2 i1 i0 *sr rd4 rd3 rd2 rd1 rd0

            swap 6                  // _ *mp i4 i3 i2 i1 rd0 *sr rd4 rd3 rd2 rd1 i0
            swap 1                  // _ *mp i4 i3 i2 i1 rd0 *sr rd4 rd3 rd2 i0 rd1
            swap 7                  // _ *mp i4 i3 i2 rd1 rd0 *sr rd4 rd3 rd2 i0 i1
            swap 2                  // _ *mp i4 i3 i2 rd1 rd0 *sr rd4 rd3 i1 i0 rd2
            swap 8                  // _ *mp i4 i3 rd2 rd1 rd0 *sr rd4 rd3 i1 i0 i2
            swap 3                  // _ *mp i4 i3 rd2 rd1 rd0 *sr rd4 i2 i1 i0 rd3
            swap 9                  // _ *mp i4 rd3 rd2 rd1 rd0 *sr rd4 i2 i1 i0 i3
            swap 4                  // _ *mp i4 rd3 rd2 rd1 rd0 *sr i3 i2 i1 i0 rd4
            swap 10                 // _ *mp rd4 rd3 rd2 rd1 rd0 *sr i3 i2 i1 i0 i4
            swap 5                  // _ *mp rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 *sr

            call {read_digest} // _ *mp rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 sr4 sr3 sr2 sr1 sr0

            push 1  // _ *mp rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 sr4 sr3 sr2 sr1 sr0 1
            swap 5  // _ *mp rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 1 sr3 sr2 sr1 sr0 sr4
            swap 10 // _ *mp rd4 rd3 rd2 rd1 rd0 sr4 i3 i2 i1 i0 1 sr3 sr2 sr1 sr0 i4
            swap 5  // _ *mp rd4 rd3 rd2 rd1 rd0 sr4 i3 i2 i1 i0 i4 sr3 sr2 sr1 sr0 1
            swap 4 swap 9 swap 4 // _ *mp rd4 rd3 rd2 rd1 rd0 sr4 sr3 i2 i1 i0 i4 i3 sr2 sr1 sr0 1
            swap 3 swap 8 swap 3 // _ *mp rd4 rd3 rd2 rd1 rd0 sr4 sr3 sr2 i1 i0 i4 i3 i2 sr1 sr0 1
            swap 2 swap 7 swap 2 // _ *mp rd4 rd3 rd2 rd1 rd0 sr4 sr3 sr2 sr1 i0 i4 i3 i2 i1 sr0 1
            swap 1 swap 6 swap 1 // _ *mp rd4 rd3 rd2 rd1 rd0 sr4 sr3 sr2 sr1 sr0 i4 i3 i2 i1 i0 1
            pop 1

            call {commit}

            // _ *mp c4 c3 c2 c1 c0

            return
        }
    }
}

impl Function for ComputeCanonicalCommitment {
    fn rust_shadow(
        &self,
        stack: &mut Vec<BFieldElement>,
        memory: &mut std::collections::HashMap<BFieldElement, BFieldElement>,
    ) {
        // read arguments
        let size_address = stack.pop().unwrap() - BFieldElement::new(1);
        let mp_pointer = size_address + BFieldElement::one();
        let d0 = stack.pop().unwrap();
        let d1 = stack.pop().unwrap();
        let d2 = stack.pop().unwrap();
        let d3 = stack.pop().unwrap();
        let d4 = stack.pop().unwrap();
        let item = Digest::new([d0, d1, d2, d3, d4]);

        // read membership proof object from memory
        let encoding_size = memory.get(&size_address).unwrap().value() as usize;
        println!("size of encoding: {encoding_size}");
        println!("address = {}", size_address);
        let mut encoding = vec![];
        for i in 0..encoding_size {
            let read_word = memory
                .get(&(size_address + BFieldElement::new(i as u64) + BFieldElement::one()))
                .copied()
                .unwrap_or_else(BFieldElement::zero);
            encoding.push(read_word);
        }

        // decode object
        let membership_proof = *MsMembershipProof::<Hash>::decode(&encoding).unwrap();

        // compute commitment
        println!("receiver_preimage: {}", membership_proof.receiver_preimage);
        let receiver_digest = membership_proof.receiver_preimage.hash::<Hash>();
        println!("receiver_digest: {}", receiver_digest);
        println!(
            "\nsender_randomness:\n {}",
            membership_proof.sender_randomness
        );
        println!("\nitem:\n{}", item);
        let c = commit::<Hash>(item, membership_proof.sender_randomness, receiver_digest);

        // push onto stack
        stack.push(mp_pointer);
        stack.push(c.canonical_commitment.values()[4]);
        stack.push(c.canonical_commitment.values()[3]);
        stack.push(c.canonical_commitment.values()[2]);
        stack.push(c.canonical_commitment.values()[1]);
        stack.push(c.canonical_commitment.values()[0]);
    }

    fn pseudorandom_initial_state(
        &self,
        seed: [u8; 32],
        _bench_case: Option<tasm_lib::snippet_bencher::BenchmarkCase>,
    ) -> FunctionInitialState {
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        // generate random ms membership proof object
        let membership_proof = pseudorandom_mutator_set_membership_proof::<Hash>(rng.gen());

        // populate memory, with the size of the encoding prepended
        let address = BFieldElement::new(rng.next_u64() % (1 << 20));
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let mp_encoding = membership_proof.encode();
        memory.insert(address, BFieldElement::new(mp_encoding.len() as u64));
        for (i, v) in mp_encoding.iter().enumerate() {
            memory.insert(
                address + BFieldElement::one() + BFieldElement::new(i as u64),
                *v,
            );
        }

        // populate stack
        let mut stack = empty_stack();
        let digest: Digest = rng.gen();
        stack.push(digest.values()[4]);
        stack.push(digest.values()[3]);
        stack.push(digest.values()[2]);
        stack.push(digest.values()[1]);
        stack.push(digest.values()[0]);
        stack.push(address + BFieldElement::new(1));

        FunctionInitialState { stack, memory }
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::{traits::function::ShadowedFunction, traits::rust_shadow::RustShadow};

    use super::*;

    #[test]
    fn test_compute_canonical_commitment() {
        ShadowedFunction::new(ComputeCanonicalCommitment).test();
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::{traits::function::ShadowedFunction, traits::rust_shadow::RustShadow};

    use super::*;

    #[test]
    fn compute_canonical_commitment_benchmark() {
        ShadowedFunction::new(ComputeCanonicalCommitment).bench();
    }
}
