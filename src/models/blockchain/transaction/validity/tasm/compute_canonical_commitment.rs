use crate::models::blockchain::shared::Hash;
use num_traits::{One, Zero};
use rand::{rngs::StdRng, Rng, SeedableRng};
use tasm_lib::{
    memory::push_ram_to_stack::PushRamToStack,
    neptune::mutator_set::commit::Commit,
    snippet::{DataType, Snippet},
    structure::get_field::GetField,
    ExecutionState,
};
use triton_vm::{BFieldElement, Digest};
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use crate::util_types::mutator_set::{
    ms_membership_proof::MsMembershipProof, mutator_set_trait::commit,
};

pub(crate) struct ComputeCanonicalCommitment;

impl ComputeCanonicalCommitment {
    pub fn pseudorandom_input_state(_seed: [u8; 32]) -> ExecutionState {
        #[cfg(test)]
        {
            use crate::util_types::test_shared::mutator_set::pseudorandom_mutator_set_membership_proof;

            use rand::RngCore;
            use std::collections::HashMap;
            use tasm_lib::get_init_tvm_stack;

            let mut rng: StdRng = SeedableRng::from_seed(_seed);

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
            let mut stack = get_init_tvm_stack();
            let digest: Digest = rng.gen();
            stack.push(digest.values()[4]);
            stack.push(digest.values()[3]);
            stack.push(digest.values()[2]);
            stack.push(digest.values()[1]);
            stack.push(digest.values()[0]);
            stack.push(address + BFieldElement::new(1));

            ExecutionState {
                stack,
                std_in: vec![],
                secret_in: vec![],
                memory,
                words_allocated: 1,
            }
        }
        #[cfg(not(test))]
        unimplemented!("Cannot generate pseudorandom input state when not in test environment.")
    }
}

impl Snippet for ComputeCanonicalCommitment {
    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_compute_commitment".to_string()
    }

    fn inputs(&self) -> Vec<String> {
        vec![
            "i4".to_string(),
            "i3".to_string(),
            "i2".to_string(),
            "i1".to_string(),
            "i0".to_string(),
            "*mp".to_string(),
        ]
    }

    fn input_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::Digest, DataType::VoidPointer]
    }

    fn output_types(&self) -> Vec<tasm_lib::snippet::DataType> {
        vec![DataType::Digest]
    }

    fn outputs(&self) -> Vec<String> {
        vec![
            "c4".to_string(),
            "c3".to_string(),
            "c2".to_string(),
            "c1".to_string(),
            "c0".to_string(),
        ]
    }

    fn stack_diff(&self) -> isize {
        -1
    }

    fn function_code(&self, library: &mut tasm_lib::snippet_state::SnippetState) -> String {
        let get_field = library.import(Box::new(GetField));
        let commit = library.import(Box::new(Commit));
        let read_digest = library.import(Box::new(PushRamToStack {
            output_type: DataType::Digest,
        }));
        let entrypoint = self.entrypoint();

        format!(
            "
        // BEFORE: _  i4 i3 i2 i1 i0 *mp
        // AFTER: _  c4 c3 c2 c1 c0
        {entrypoint}:
            dup 0 push 0 call {get_field} // _ i4 i3 i2 i1 i0 *mp *sr_si
            swap 1 push 1 call {get_field} // _ i4 i3 i2 i1 i0 *sr_si *rp_si

            push 1 add  // _ i4 i3 i2 i1 i0 *sr_si *rp
            push 0 push 0 push 0 push 0 push 0
            swap 5                  // _ i4 i3 i2 i1 i0 *sr_si 0 0 0 0 0 *rp

            call {read_digest} // _ i4 i3 i2 i1 i0 *sr_si 0 0 0 0 0 [receiver_preimage]
            hash
            pop pop pop pop pop
            // _ i4 i3 i2 i1 i0 *sr_si rd4 rd3 rd2 rd1 rd0

            swap 6                  // _ i4 i3 i2 i1 rd0 *sr_si rd4 rd3 rd2 rd1 i0
            swap 1                  // _ i4 i3 i2 i1 rd0 *sr_si rd4 rd3 rd2 i0 rd1
            swap 7                  // _ i4 i3 i2 rd1 rd0 *sr_si rd4 rd3 rd2 i0 i1
            swap 2                  // _ i4 i3 i2 rd1 rd0 *sr_si rd4 rd3 i1 i0 rd2
            swap 8                  // _ i4 i3 rd2 rd1 rd0 *sr_si rd4 rd3 i1 i0 i2
            swap 3                  // _ i4 i3 rd2 rd1 rd0 *sr_si rd4 i2 i1 i0 rd3
            swap 9                  // _ i4 rd3 rd2 rd1 rd0 *sr_si rd4 i2 i1 i0 i3
            swap 4                  // _ i4 rd3 rd2 rd1 rd0 *sr_si i3 i2 i1 i0 rd4
            swap 10                 // _ rd4 rd3 rd2 rd1 rd0 *sr_si i3 i2 i1 i0 i4
            swap 5                  // _ rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 *sr_si
            push 1 add              // _ rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 *sr

            call {read_digest} // _ rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 sr4 sr3 sr2 sr1 sr0

            push 1  // _ rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 sr4 sr3 sr2 sr1 sr0 1
            swap 5  // _ rd4 rd3 rd2 rd1 rd0 i4 i3 i2 i1 i0 1 sr3 sr2 sr1 sr0 sr4
            swap 10 // _ rd4 rd3 rd2 rd1 rd0 sr4 i3 i2 i1 i0 1 sr3 sr2 sr1 sr0 i4
            swap 5  // _ rd4 rd3 rd2 rd1 rd0 sr4 i3 i2 i1 i0 i4 sr3 sr2 sr1 sr0 1
            swap 4 swap 9 swap 4 // _ rd4 rd3 rd2 rd1 rd0 sr4 sr3 i2 i1 i0 i4 i3 sr2 sr1 sr0 1
            swap 3 swap 8 swap 3 // _ rd4 rd3 rd2 rd1 rd0 sr4 sr3 sr2 i1 i0 i4 i3 i2 sr1 sr0 1
            swap 2 swap 7 swap 2 // _ rd4 rd3 rd2 rd1 rd0 sr4 sr3 sr2 sr1 i0 i4 i3 i2 i1 sr0 1
            swap 1 swap 6 swap 1 // _ rd4 rd3 rd2 rd1 rd0 sr4 sr3 sr2 sr1 sr0 i4 i3 i2 i1 i0 1
            pop

            call {commit}

            return
            "
        )
    }

    fn crash_conditions(&self) -> Vec<String> {
        vec![]
    }

    fn gen_input_states(&self) -> Vec<tasm_lib::ExecutionState> {
        let mut seed = [0u8; 32];
        seed[0] = 0xe2;
        seed[1] = 0x75;
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        vec![
            Self::pseudorandom_input_state(rng.gen()),
            Self::pseudorandom_input_state(rng.gen()),
            Self::pseudorandom_input_state(rng.gen()),
            Self::pseudorandom_input_state(rng.gen()),
        ]
    }

    fn common_case_input_state(&self) -> tasm_lib::ExecutionState {
        let mut seed = [0u8; 32];
        seed[0] = 0xe1;
        seed[1] = 0x75;
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        Self::pseudorandom_input_state(rng.gen())
    }

    fn worst_case_input_state(&self) -> tasm_lib::ExecutionState {
        let mut seed = [0u8; 32];
        seed[0] = 0xe3;
        seed[1] = 0x75;
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        Self::pseudorandom_input_state(rng.gen())
    }

    fn rust_shadowing(
        &self,
        stack: &mut Vec<triton_vm::BFieldElement>,
        _std_in: Vec<triton_vm::BFieldElement>,
        _secret_in: Vec<triton_vm::BFieldElement>,
        memory: &mut std::collections::HashMap<triton_vm::BFieldElement, triton_vm::BFieldElement>,
    ) {
        // read arguments
        let address = stack.pop().unwrap() - BFieldElement::new(1);
        let d0 = stack.pop().unwrap();
        let d1 = stack.pop().unwrap();
        let d2 = stack.pop().unwrap();
        let d3 = stack.pop().unwrap();
        let d4 = stack.pop().unwrap();
        let item = Digest::new([d0, d1, d2, d3, d4]);

        // read membership proof object from memory
        let encoding_size = memory.get(&address).unwrap().value() as usize;
        println!("size of encoding: {encoding_size}");
        println!("address = {}", address);
        let mut encoding = vec![];
        for i in 0..encoding_size {
            let read_word = memory
                .get(&(address + BFieldElement::new(i as u64) + BFieldElement::one()))
                .map(|x| *x)
                .unwrap_or_else(|| BFieldElement::zero());
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
        let c = commit::<Hash>(&item, &membership_proof.sender_randomness, &receiver_digest);

        // push onto stack
        stack.push(c.canonical_commitment.values()[4]);
        stack.push(c.canonical_commitment.values()[3]);
        stack.push(c.canonical_commitment.values()[2]);
        stack.push(c.canonical_commitment.values()[1]);
        stack.push(c.canonical_commitment.values()[0]);
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::test_helpers::test_rust_equivalence_multiple;

    use super::*;

    #[test]
    fn test_compute_canonical_commitment() {
        test_rust_equivalence_multiple(&ComputeCanonicalCommitment, false);
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::snippet_bencher::bench_and_write;

    use super::*;

    #[test]
    fn compute_canonical_commitment_benchmark() {
        bench_and_write(ComputeCanonicalCommitment)
    }
}
