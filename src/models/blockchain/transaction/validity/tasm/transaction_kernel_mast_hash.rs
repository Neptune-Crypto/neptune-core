use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::transaction_kernel::{
    pseudorandom_transaction_kernel, TransactionKernel,
};
use num_traits::One;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tasm_lib::function::Function;
use tasm_lib::library::Library;
use tasm_lib::snippet::BasicSnippet;
use tasm_lib::snippet_bencher::BenchmarkCase;
use tasm_lib::{
    hashing::hash_varlen::HashVarlen,
    list::unsafeimplu32::{
        get::UnsafeGet, new::UnsafeNew, set::UnsafeSet, set_length::UnsafeSetLength,
    },
    rust_shadowing_helper_functions,
    snippet::DataType,
    ExecutionState,
};
use triton_vm::{triton_asm, BFieldElement};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::{
    shared_math::{tip5::Digest, tip5::DIGEST_LENGTH},
    util_types::algebraic_hasher::AlgebraicHasher,
};

/// Computes the mast hash of a transaction kernel object
#[derive(Debug, Clone)]
pub struct TransactionKernelMastHash;

impl TransactionKernelMastHash {
    pub(crate) fn input_state_with_kernel_in_memory(
        address: BFieldElement,
        transaction_kernel_encoded: &[BFieldElement],
    ) -> ExecutionState {
        use triton_vm::NonDeterminism;

        assert!(address.value() > 1);
        // populate memory
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        for (i, t) in transaction_kernel_encoded.iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), *t);
        }
        memory.insert(
            address - BFieldElement::new(1),
            BFieldElement::new(transaction_kernel_encoded.len() as u64),
        );

        // set dynamic allocator
        memory.insert(
            <BFieldElement as num_traits::Zero>::zero(),
            BFieldElement::new(transaction_kernel_encoded.len() as u64) + address,
        );

        let mut stack = tasm_lib::get_init_tvm_stack();
        stack.push(address);
        ExecutionState {
            stack,
            std_in: vec![],
            nondeterminism: NonDeterminism::new(vec![]),
            memory,
            words_allocated: 0,
        }
    }
}

impl BasicSnippet for TransactionKernelMastHash {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "*transaction_kernel".to_string())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "mast_hash".to_string())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_transaction_kernel_mast_hash".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<triton_vm::instruction::LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let new_list = library.import(Box::new(UnsafeNew(DataType::Digest)));
        let get_element = library.import(Box::new(UnsafeGet(DataType::Digest)));
        let set_element = library.import(Box::new(UnsafeSet(DataType::Digest)));
        let set_length = library.import(Box::new(UnsafeSetLength(DataType::Digest)));

        let kernel_to_inputs_with_size = tasm_lib::field_with_size!(TransactionKernel::inputs);
        let kernel_to_outputs_with_size = tasm_lib::field_with_size!(TransactionKernel::outputs);
        let kernel_to_pubscripts_with_size =
            tasm_lib::field_with_size!(TransactionKernel::pubscript_hashes_and_inputs);
        let kernel_to_fee_with_size = tasm_lib::field_with_size!(TransactionKernel::fee);
        let kernel_to_coinbase_with_size = tasm_lib::field_with_size!(TransactionKernel::coinbase);
        let kernel_to_timestamp_with_size =
            tasm_lib::field_with_size!(TransactionKernel::timestamp);
        let kernel_to_mutator_set_hash_with_size =
            tasm_lib::field_with_size!(TransactionKernel::mutator_set_hash);

        let hash_varlen = library.import(Box::new(HashVarlen));

        triton_asm! {
        // BEFORE: _ *kernel
        // AFTER: _ d4 d3 d2 d1 d0
        {entrypoint}:
            // allocate new list of 16 digests
            push 16                      // _ *kernel 16
            dup 0                        // _ *kernel 16 16
            call {new_list}              // _ *kernel 16 *list
            swap 1                       // _ *kernel *list 16
            call {set_length}            // _ *kernel *list

            // populate list[8] with inputs digest
            dup 1                       // _ *kernel *list *kernel
            {&kernel_to_inputs_with_size}
                                        // _ *kernel *list *inputs *inputs_size
            call {hash_varlen}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 8                // _ *kernel *list d4 d3 d2 d1 d0 *list 8
            call {set_element}          // _ *kernel *list

            // populate list[9] with outputs digest
            dup 1                       // _ *kernel *list *kernel
            {&kernel_to_outputs_with_size}  // _ *kernel *list *outputs *outputs_size
            call {hash_varlen}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 9                // _ *kernel *list d4 d3 d2 d1 d0 *list 9
            call {set_element}          // _ *kernel *list

            // populate list[10] with pubscript_hashes_and_inputs digest
            dup 1                       // _ *kernel *list *kernel
            {&kernel_to_pubscripts_with_size}
                                        // _ *kernel *list *pubscript_hashes_and_inputs *pubscript_hashes_and_inputs_size_size
            call {hash_varlen}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 10               // _ *kernel *list d4 d3 d2 d1 d0 *list 10
            call {set_element}          // _ *kernel *list

            // populate list[11] with fee digest
            dup 1                       // _ *kernel *list *kernel
            {&kernel_to_fee_with_size}   // _ *kernel *list *fee *fee_size
            call {hash_varlen}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 11               // _ *kernel *list d4 d3 d2 d1 d0 *list 11
            call {set_element}          // _ *kernel *list

            // populate list[12] with coinbase digest
            dup 1                       // _ *kernel *list *kernel
            {&kernel_to_coinbase_with_size}
                                        // _ *kernel *list *coinbase *coinbase_size
            call {hash_varlen}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 12               // _ *kernel *list d4 d3 d2 d1 d0 *list 12
            call {set_element}          // _ *kernel *list

            // populate list[13] with timestamp digest
            dup 1                       // _ *kernel *list *kernel
            {&kernel_to_timestamp_with_size}
                                        // _ *kernel *list *timestamp *timestamp_size
            call {hash_varlen}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 13               // _ *kernel *list d4 d3 d2 d1 d0 *list 13
            call {set_element}          // _ *kernel *list

            // populate list[14] with mutator set hash digest
            dup 1                       // _ *kernel *list *kernel
            {&kernel_to_mutator_set_hash_with_size}
                                        // _ *kernel *list *mutator_set_hash *mutator_set_hash_size
            call {hash_varlen}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 14               // _ *kernel *list d4 d3 d2 d1 d0 *list 14
            call {set_element}          // _ *kernel *list

            // populate list[15] with default digest
            push 0 push 0 push 0 push 0 push 0
            dup 5 push 15               // _ *kernel *list d4 d3 d2 d1 d0 *list 15
            call {set_element}          // _ *kernel *list

            // hash 14||15 and store in 7
            dup 0 push 15               // _ *kernel *list *list 15
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 14               // _ *kernel *list d4 d3 d2 d1 d0 *list 14
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0 e4 e3 e2 e1 e0
            hash                        // _ *kernel *list f4 f3 f2 f1 f0 0 0 0 0 0
            pop pop pop pop pop         // _ *kernel *list f4 f3 f2 f1 f0
            dup 5 push 7                // _ *kernel *list f4 f3 f2 f1 f0 *list 7
            call {set_element}

            // hash 12||13 and store in 6
            dup 0 push 13               // _ *kernel *list *list 13
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 12               // _ *kernel *list d4 d3 d2 d1 d0 *list 12
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0 e4 e3 e2 e1 e0
            hash                        // _ *kernel *list f4 f3 f2 f1 f0 0 0 0 0 0
            pop pop pop pop pop         // _ *kernel *list f4 f3 f2 f1 f0
            dup 5 push 6                // _ *kernel *list f4 f3 f2 f1 f0 *list 6
            call {set_element}

            // hash 10||11 and store in 5
            dup 0 push 11               // _ *kernel *list *list 11
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 10               // _ *kernel *list d4 d3 d2 d1 d0 *list 10
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0 e4 e3 e2 e1 e0
            hash                        // _ *kernel *list f4 f3 f2 f1 f0 0 0 0 0 0
            pop pop pop pop pop         // _ *kernel *list f4 f3 f2 f1 f0
            dup 5 push 5                // _ *kernel *list f4 f3 f2 f1 f0 *list 5
            call {set_element}

            // hash 8||9 and store in 4
            dup 0 push 9                // _ *kernel *list *list 9
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 8                // _ *kernel *list d4 d3 d2 d1 d0 *list 8
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0 e4 e3 e2 e1 e0
            hash                        // _ *kernel *list f4 f3 f2 f1 f0 0 0 0 0 0
            pop pop pop pop pop         // _ *kernel *list f4 f3 f2 f1 f0
            dup 5 push 4                // _ *kernel *list f4 f3 f2 f1 f0 *list 4
            call {set_element}

            // hash 6||7 and store in 3
            dup 0 push 7                // _ *kernel *list *list 7
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 6                // _ *kernel *list d4 d3 d2 d1 d0 *list 6
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0 e4 e3 e2 e1 e0
            hash                        // _ *kernel *list f4 f3 f2 f1 f0 0 0 0 0 0
            pop pop pop pop pop         // _ *kernel *list f4 f3 f2 f1 f0
            dup 5 push 3                // _ *kernel *list f4 f3 f2 f1 f0 *list 3
            call {set_element}

            // hash 4||5 and store in 2
            dup 0 push 5                // _ *kernel *list *list 5
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 4                // _ *kernel *list d4 d3 d2 d1 d0 *list 4
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0 e4 e3 e2 e1 e0
            hash                        // _ *kernel *list f4 f3 f2 f1 f0 0 0 0 0 0
            pop pop pop pop pop         // _ *kernel *list f4 f3 f2 f1 f0
            dup 5 push 2                // _ *kernel *list f4 f3 f2 f1 f0 *list 2
            call {set_element}

            // hash 2||3 and store in 1
            dup 0 push 3                // _ *kernel *list *list 3
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0
            dup 5 push 2                // _ *kernel *list d4 d3 d2 d1 d0 *list 2
            call {get_element}          // _ *kernel *list d4 d3 d2 d1 d0 e4 e3 e2 e1 e0
            hash                        // _ *kernel *list f4 f3 f2 f1 f0 0 0 0 0 0
            pop pop pop pop pop         // _ *kernel *list f4 f3 f2 f1 f0
            dup 5 push 1                // _ *kernel *list f4 f3 f2 f1 f0 *list 1

            call {set_element}

            // return list[1]
            swap 1                      // _ *list *kernel
            pop
            push 1 // _ *list 1
            call {get_element}          // _ d4 d3 d2 d1 d0

            return
        }
    }
}

impl Function for TransactionKernelMastHash {
    fn rust_shadow(
        &self,
        stack: &mut Vec<triton_vm::BFieldElement>,
        memory: &mut std::collections::HashMap<triton_vm::BFieldElement, triton_vm::BFieldElement>,
    ) {
        // read address
        let address = stack.pop().unwrap();

        let mut sequence = vec![];
        let size = memory
            .get(&(address - BFieldElement::new(1)))
            .unwrap()
            .value();
        for i in 0..size {
            sequence.push(*memory.get(&(BFieldElement::new(i) + address)).unwrap());
        }
        let kernel = *TransactionKernel::decode(&sequence).unwrap();

        // inputs
        // let inputs_size = memory.get(&address).unwrap().value() as usize;
        // let inputs_encoded = (0..inputs_size)
        //     .map(|i| {
        //         *memory
        //             .get(&(address + BFieldElement::new(i as u64)))
        //             .unwrap()
        //     })
        //     .collect_vec();
        let inputs = kernel.inputs;
        let inputs_encoded = inputs.encode();
        let inputs_hash = Hash::hash_varlen(&inputs_encoded);
        // address += BFieldElement::one() + BFieldElement::new(inputs_size as u64);

        // outputs
        // let outputs_size = memory.get(&address).unwrap().value() as usize;
        // let outputs_encoded = (0..outputs_size)
        //     .map(|i| {
        //         *memory
        //             .get(&(address + BFieldElement::new(i as u64)))
        //             .unwrap()
        //     })
        //     .collect_vec();
        let outputs = kernel.outputs;
        let outputs_encoded = outputs.encode();
        let outputs_hash = Hash::hash_varlen(&outputs_encoded);
        // address += BFieldElement::one() + BFieldElement::new(outputs_size as u64);

        // pubscript_hashes_and_inputs
        // let pubscript_hashes_and_inputs_size = memory.get(&address).unwrap().value() as usize;
        // let pubscript_hashes_and_inputs_encoded = (0..pubscript_hashes_and_inputs_size)
        //     .map(|i| {
        //         *memory
        //             .get(&(address + BFieldElement::new(i as u64)))
        //             .unwrap()
        //     })
        //     .collect_vec();
        let pubscript_hashes_and_inputs = kernel.pubscript_hashes_and_inputs;
        let pubscript_hashes_and_inputs_encoded = pubscript_hashes_and_inputs.encode();
        let pubscript_hashes_and_inputs_hash =
            Hash::hash_varlen(&pubscript_hashes_and_inputs_encoded);
        // address +=
        //     BFieldElement::one() + BFieldElement::new(pubscript_hashes_and_inputs_size as u64);

        // fee
        // let fee_size = memory.get(&address).unwrap().value() as usize;
        // let fee_encoded = (0..fee_size)
        //     .map(|i| {
        //         *memory
        //             .get(&(address + BFieldElement::new(i as u64)))
        //             .unwrap()
        //     })
        //     .collect_vec();
        let fee = kernel.fee;
        let fee_encoded = fee.encode();
        let fee_hash = Hash::hash_varlen(&fee_encoded);
        // address += BFieldElement::one() + BFieldElement::new(fee_size as u64);

        // coinbase
        // let coinbase_size = memory.get(&address).unwrap().value() as usize;
        // let coinbase_encoded = (0..coinbase_size)
        //     .map(|i| {
        //         *memory
        //             .get(&(address + BFieldElement::new(i as u64)))
        //             .unwrap()
        //     })
        //     .collect_vec();
        let coinbase = kernel.coinbase;
        let coinbase_encoded = coinbase.encode();
        let coinbase_hash = Hash::hash_varlen(&coinbase_encoded);
        // address += BFieldElement::one() + BFieldElement::new(coinbase_size as u64);

        // timestamp
        // let timestamp_size = memory.get(&address).unwrap().value() as usize;
        // assert_eq!(timestamp_size, 1);
        // let timestamp_encoded = (0..timestamp_size)
        //     .map(|i| {
        //         *memory
        //             .get(&(address + BFieldElement::new(i as u64)))
        //             .unwrap()
        //     })
        //     .collect_vec();
        let timestamp = kernel.timestamp;
        let timestamp_encoded = timestamp.encode();
        let timestamp_hash = Hash::hash_varlen(&timestamp_encoded);
        // address += BFieldElement::one() + BFieldElement::new(timestamp_size as u64);

        // mutator_set_hash
        // let mutator_set_hash_size = memory.get(&address).unwrap().value() as usize;
        // let mutator_set_hash_encoded = (0..mutator_set_hash_size)
        //     .map(|i| {
        //         *memory
        //             .get(&(address + BFieldElement::new(i as u64)))
        //             .unwrap()
        //     })
        //     .collect_vec();
        let mutator_set_hash = kernel.mutator_set_hash;
        let mutator_set_hash_encoded = mutator_set_hash.encode();
        let mutator_set_hash_hash = Hash::hash_varlen(&mutator_set_hash_encoded);
        // address += BFieldElement::one() + BFieldElement::new(mutator_set_hash_size as u64);

        // padding
        let zero = Digest::default();

        // Merkleize
        let leafs = [
            inputs_hash,
            outputs_hash,
            pubscript_hashes_and_inputs_hash,
            fee_hash,
            coinbase_hash,
            timestamp_hash,
            mutator_set_hash_hash,
            zero,
        ];
        let mut nodes = [[zero; 8], leafs].concat();
        for i in (1..=7).rev() {
            nodes[i] = Hash::hash_pair(nodes[2 * i], nodes[2 * i + 1]);
        }
        let root = nodes[1].to_owned();

        // populate memory with merkle tree
        let list_address = rust_shadowing_helper_functions::dyn_malloc::dynamic_allocator(
            16 * DIGEST_LENGTH,
            memory,
        );
        rust_shadowing_helper_functions::unsafe_list::unsafe_list_new(list_address, memory);
        rust_shadowing_helper_functions::unsafe_list::unsafe_list_set_length(
            list_address,
            16,
            memory,
        );
        for (i, node) in nodes.into_iter().enumerate().skip(1) {
            for j in 0..DIGEST_LENGTH {
                memory.insert(
                    list_address
                        + BFieldElement::one()
                        + BFieldElement::new((i * DIGEST_LENGTH + j) as u64),
                    node.values()[j],
                );
            }
        }

        // write digest to stack
        stack.push(root.values()[4]);
        stack.push(root.values()[3]);
        stack.push(root.values()[2]);
        stack.push(root.values()[1]);
        stack.push(root.values()[0]);
    }

    fn pseudorandom_initial_state(
        &self,
        seed: [u8; 32],
        _bench_case: Option<BenchmarkCase>,
    ) -> (Vec<BFieldElement>, HashMap<BFieldElement, BFieldElement>) {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let input_state = Self::input_state_with_kernel_in_memory(
            BFieldElement::new(rng.gen_range(0..(1 << 20))),
            &twenty_first::shared_math::bfield_codec::BFieldCodec::encode(
                &pseudorandom_transaction_kernel(rand::Rng::gen::<[u8; 32]>(&mut rng), 4, 4, 2),
            ),
        );
        (input_state.stack, input_state.memory)
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::{
        function::ShadowedFunction, snippet::RustShadow,
        test_helpers::test_rust_equivalence_given_complete_state,
    };
    use twenty_first::shared_math::bfield_codec::BFieldCodec;
    use twenty_first::shared_math::tip5::Tip5State;
    use twenty_first::util_types::algebraic_hasher::Domain;

    use super::*;

    #[test]
    fn verify_agreement_with_tx_kernel_mast_hash() {
        let mut seed = [99u8; 32];
        seed[17] = 0x17;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let tx_kernel = pseudorandom_transaction_kernel(rng.gen(), 2, 2, 1);
        let execution_state = TransactionKernelMastHash::input_state_with_kernel_in_memory(
            BFieldElement::new(3),
            &tx_kernel.encode(),
        );

        let nondeterminism = execution_state.nondeterminism;
        let mut output_with_known_digest = test_rust_equivalence_given_complete_state(
            &ShadowedFunction::new(TransactionKernelMastHash),
            &execution_state.stack,
            &execution_state.std_in,
            &nondeterminism,
            &execution_state.memory,
            &Tip5State::new(Domain::FixedLength),
            execution_state.words_allocated,
            None,
        );

        // read the digest from the very short TX kernel
        let d0 = output_with_known_digest.final_stack.pop().unwrap();
        let d1 = output_with_known_digest.final_stack.pop().unwrap();
        let d2 = output_with_known_digest.final_stack.pop().unwrap();
        let d3 = output_with_known_digest.final_stack.pop().unwrap();
        let d4 = output_with_known_digest.final_stack.pop().unwrap();
        let mast_hash_from_vm = Digest::new([d0, d1, d2, d3, d4]);

        // Verify agreement with mast_hash method on tx kernel
        assert_eq!(tx_kernel.mast_hash(), mast_hash_from_vm);
    }

    #[test]
    fn test() {
        ShadowedFunction::new(TransactionKernelMastHash).test()
    }
}

#[cfg(test)]
mod benches {

    use tasm_lib::{function::ShadowedFunction, snippet::RustShadow};

    use super::*;

    #[test]
    fn bench() {
        ShadowedFunction::new(TransactionKernelMastHash).bench()
    }
}
