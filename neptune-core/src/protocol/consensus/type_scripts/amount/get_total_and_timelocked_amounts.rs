use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::DataType;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::LabelledInstruction;

use crate::protocol::consensus::type_scripts::amount::total_amount_main_loop::DigestSource;
use crate::protocol::consensus::type_scripts::amount::total_amount_main_loop::TotalAmountMainLoop;

#[derive(Debug, Clone, Copy)]
pub struct GetTotalAndTimeLockedAmounts {
    type_script_hash: Digest,
}

impl BasicSnippet for GetTotalAndTimeLockedAmounts {
    fn inputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::VoidPointer, "*list_of_utxos".to_string()),
            (DataType::Bfe, "release_date".to_string()),
        ]
    }

    fn outputs(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U128, "total_amount".to_string()),
            (DataType::U128, "total_timelocked".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_get_total_and_timelocked_amounts".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let release_date_allocation = library.kmalloc(1);
        let total_amount_main_loop = TotalAmountMainLoop {
            digest_source: DigestSource::Hardcode(self.type_script_hash),
            release_date: release_date_allocation,
        };
        let total_amount_main_loop_label = library.import(Box::new(total_amount_main_loop));

        triton_asm! {
            // BEFORE: _ *utxos release_date
            // AFTER: _ [total_amount] [total_timelocked]
            {self.entrypoint()}:
                push {release_date_allocation.write_address()}
                write_mem 1
                pop 1
                // _ *utxos

                read_mem 1 addi 2
                // _ N *utxos[0]_si

                push 0 place 1
                // _ N 0 *utxos[0]_si

                push 0
                push 0
                push 0
                // _ N 0 *utxos[i]_si * * *

                push 0
                push 0
                push 0
                push 0
                // _ N 0 *utxos[i]_si * * * [amount1]

                push 0
                push 0
                push 0
                push 0
                // _ N 0 *utxos[i]_si * * * [amount1] [amount2]

                call {total_amount_main_loop_label}
                // _ N N *eof * * * [amount] [timelocked_amount]

                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                pick 8 pop 1
                // _ [amount] [timelocked_amount]

                return
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use itertools::Itertools;
    use num_traits::CheckedAdd;
    use rand::rng;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tasm_lib::empty_stack;
    use tasm_lib::library::STATIC_MEMORY_FIRST_ADDRESS;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::prelude::Digest;
    use tasm_lib::prelude::TasmObject;
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use tasm_lib::traits::algorithm::Algorithm;
    use tasm_lib::traits::algorithm::AlgorithmInitialState;
    use tasm_lib::traits::algorithm::ShadowedAlgorithm;
    use tasm_lib::traits::rust_shadow::RustShadow;
    use tasm_lib::triton_vm::prelude::BFieldCodec;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use tasm_lib::triton_vm::vm::NonDeterminism;

    use super::GetTotalAndTimeLockedAmounts;
    use crate::api::export::NativeCurrencyAmount;
    use crate::api::export::Timestamp;
    use crate::protocol::consensus::transaction::utxo::Coin;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::type_scripts::time_lock::TimeLock;
    use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;

    impl Algorithm for GetTotalAndTimeLockedAmounts {
        fn rust_shadow(
            &self,
            stack: &mut Vec<BFieldElement>,
            memory: &mut HashMap<BFieldElement, BFieldElement>,
            _nondeterminism: &NonDeterminism,
        ) {
            let release_date = Timestamp(stack.pop().unwrap());
            let address = stack.pop().unwrap();

            let utxos = *Vec::<Utxo>::decode_from_memory(memory, address).unwrap();

            let mut total_amount = NativeCurrencyAmount::coins(0);
            let mut timelocked_amount = NativeCurrencyAmount::coins(0);
            for utxo in utxos {
                let mut is_timelocked = false;
                let mut utxo_amount = NativeCurrencyAmount::coins(0);

                for coin in utxo.coins() {
                    if coin.type_script_hash == TimeLock.hash()
                        && Timestamp(coin.state[0]) > release_date
                    {
                        is_timelocked = true;
                    }

                    if coin.type_script_hash == self.type_script_hash {
                        let coin_amount = *NativeCurrencyAmount::decode(&coin.state).unwrap();
                        utxo_amount = utxo_amount.checked_add(&coin_amount).unwrap();
                    }
                }

                if is_timelocked {
                    timelocked_amount = timelocked_amount.checked_add(&utxo_amount).unwrap();
                }

                total_amount = total_amount.checked_add(&utxo_amount).unwrap();
            }

            for elm in [total_amount.encode(), timelocked_amount.encode()].concat() {
                stack.push(elm);
            }

            // The snippet uses static memory to pass this information on;
            // mimic that behavior here.
            memory.insert(STATIC_MEMORY_FIRST_ADDRESS, release_date.0);
        }

        fn pseudorandom_initial_state(
            &self,
            seed: [u8; 32],
            bench_case: Option<BenchmarkCase>,
        ) -> AlgorithmInitialState {
            let mut rng = StdRng::from_seed(seed);
            let list_length = match bench_case {
                Some(BenchmarkCase::CommonCase) => 2,
                Some(BenchmarkCase::WorstCase) => 20,
                None => rng.random_range(0..5),
            };

            let type_script_hash = rng.random::<Digest>();

            let bit = rng.random_range(0..=1);
            let utxos = (0..list_length)
                .map(|i| {
                    let mut coins = vec![];
                    coins.push(Coin {
                        type_script_hash,
                        state: NativeCurrencyAmount::coins(rng.random_range(0..100)).encode(),
                    });
                    if i == bit || rng.random_bool(0.5) {
                        coins.push(TimeLock::until(rng.random()));
                    }
                    Utxo::new(rng.random(), coins)
                })
                .collect_vec();

            let mut memory = HashMap::new();
            let utxos_list = utxos.encode();
            let utxos_address = rng.random_range(0..(u32::MAX - 1 - utxos_list.len() as u32));
            encode_to_memory(&mut memory, utxos_address.into(), &utxos);

            let nondeterminism = NonDeterminism::default().with_ram(memory);

            let release_date = rng.random::<BFieldElement>();
            let mut stack = empty_stack();
            stack.push(utxos_address.into());
            stack.push(release_date);

            AlgorithmInitialState {
                stack,
                nondeterminism,
            }
        }
    }

    #[test]
    fn unit_test() {
        let snippet = GetTotalAndTimeLockedAmounts {
            type_script_hash: rng().random(),
        };
        let shadowed_algorithm = ShadowedAlgorithm::new(snippet);
        shadowed_algorithm.test();
    }
}
