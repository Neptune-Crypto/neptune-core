use std::collections::HashMap;

use rand::rngs::StdRng;
use rand::RngCore;
use rand::SeedableRng;
use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::snippet_bencher::BenchmarkCase;
use tasm_lib::traits::basic_snippet::BasicSnippet;
use tasm_lib::traits::function::Function;
use tasm_lib::traits::function::FunctionInitialState;
use tasm_lib::triton_vm::prelude::*;
use twenty_first::math::bfield_codec::BFieldCodec;


use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::pseudorandom_utxo;
use crate::models::blockchain::transaction::utxo::Utxo;

/// HashUtxo takes a VoidPointer to a UTXO living in a contiguous
/// list, and hashes it.
#[derive(Debug, Clone)]
pub struct HashUtxo;

impl BasicSnippet for HashUtxo {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::VoidPointer, "utxo".to_string())]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Digest, "digest".to_string())]
    }

    fn entrypoint(&self) -> String {
        "tasm_neptune_transaction_hash_utxo".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let entrypoint = self.entrypoint();
        let hash_varlen = library.import(Box::new(HashVarlen));

        triton_asm!(
        // BEFORE: _ *utxo
        // AFTER:  _ [utxo_digest]
        {entrypoint}:
            push -1 add // _ *utxo_si // because it lives in a contiguous list
            read_mem 1  // _ utxo_size (*utxo_si - 1)
            push 2 add  // _ utxo_size *utxo
            swap 1      // _ *utxo utxo_size

            call {hash_varlen}
            return
        )
    }
}

impl Function for HashUtxo {
    fn rust_shadow(
        &self,
        stack: &mut Vec<BFieldElement>,
        memory: &mut std::collections::HashMap<BFieldElement, BFieldElement>,
    ) {
        // read address
        let address = stack.pop().unwrap();

        // read utxo
        let size = memory
            .get(&(address - BFieldElement::new(1)))
            .unwrap()
            .value() as usize;
        let mut utxo_encoded = vec![];
        for i in 0..size {
            utxo_encoded.push(
                memory
                    .get(&(address + BFieldElement::new(i as u64)))
                    .unwrap()
                    .to_owned(),
            );
        }
        let utxo = *Utxo::decode(&utxo_encoded).unwrap();

        // hash utxo
        let hash = Hash::hash(&utxo);

        // put on stack
        for v in hash.reversed().values() {
            stack.push(v);
        }
    }

    fn pseudorandom_initial_state(
        &self,
        seed: [u8; 32],
        _bench_case: Option<BenchmarkCase>,
    ) -> FunctionInitialState {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let utxo = pseudorandom_utxo(seed);
        let address = bfe!(rng.next_u64() % (1 << 20));
        let mut stack = tasm_lib::empty_stack();
        stack.push(address);
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let encoded_utxo = BFieldCodec::encode(&utxo);
        memory.insert(
            address - BFieldElement::new(1),
            BFieldElement::new(encoded_utxo.len() as u64),
        );
        for (i, v) in encoded_utxo.iter().enumerate() {
            memory.insert(address + BFieldElement::new(i as u64), v.to_owned());
        }

        FunctionInitialState { stack, memory }
    }
}

#[cfg(test)]
mod tests {
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;

    #[test]
    fn new_prop_test() {
        let shadowed_function = ShadowedFunction::new(HashUtxo);
        shadowed_function.test();
    }
}

#[cfg(test)]
mod benches {
    use tasm_lib::traits::function::ShadowedFunction;
    use tasm_lib::traits::rust_shadow::RustShadow;

    use super::*;

    #[test]
    fn hash_utxo_benchmark() {
        let shadowed_function = ShadowedFunction::new(HashUtxo);
        shadowed_function.bench();
    }
}
