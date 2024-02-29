use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_kernel::{
    TransactionKernel, TransactionKernelField,
};
use crate::models::consensus::mast_hash::MastHash;
use crate::models::consensus::SecretWitness;
use crate::models::{
    blockchain::transaction::primitive_witness::SaltedUtxos,
    consensus::tasm::program::ConsensusProgram,
};

use crate::models::blockchain::type_scripts::BFieldCodec;
use crate::models::consensus::tasm::builtins as tasm;
use get_size::GetSize;
use serde::{Deserialize, Serialize};

use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::{NonDeterminism, Program, PublicInput};
use tasm_lib::triton_vm::triton_asm;
use tasm_lib::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use tasm_lib::{twenty_first::shared_math::b_field_element::BFieldElement, Digest};

use super::neptune_coins::NeptuneCoins;
use super::TypeScriptWitness;

#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct NativeCurrency {}

impl ConsensusProgram for NativeCurrency {
    #[allow(clippy::needless_return)]
    fn source() {
        // get in the current program's hash digest
        let self_digest: Digest = tasm::own_program_digest();

        // read standard input:
        //  - transaction kernel mast hash
        //  - input salted utxos digest
        //  - output salted utxos digest
        // (All type scripts take this triple as input.)
        let tx_kernel_digest: Digest = tasm::tasm_io_read_stdin___digest();
        let input_utxos_digest: Digest = tasm::tasm_io_read_stdin___digest();
        let output_utxos_digest: Digest = tasm::tasm_io_read_stdin___digest();

        // get coinbase, fee, inputs, and outputs
        // these objects live in non-deterministical initial memory,
        // so divine pointers and decode
        let coinbase_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let coinbase: Option<NeptuneCoins> = tasm::decode_from_memory(coinbase_pointer);
        let fee_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let fee: NeptuneCoins = tasm::decode_from_memory(fee_pointer);
        let input_salted_utxos_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let input_salted_utxos: SaltedUtxos = tasm::decode_from_memory(input_salted_utxos_pointer);
        let output_salted_utxos_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let output_salted_utxos: SaltedUtxos =
            tasm::decode_from_memory(output_salted_utxos_pointer);

        // authenticate coinbase against kernel mast hash
        let coinbase_leaf_index: u32 = 4;
        let coinbase_leaf: Digest = Hash::hash(&coinbase);
        let kernel_tree_height: u32 = 3;
        tasm::tasm_hashing_merkle_verify(
            tx_kernel_digest,
            coinbase_leaf_index,
            coinbase_leaf,
            kernel_tree_height,
        );

        // unpack coinbase
        let some_coinbase: NeptuneCoins = match coinbase {
            Some(coins) => coins,
            None => NeptuneCoins::new(0),
        };

        // authenticate fee against kernel mast hash
        let fee_leaf_index: u32 = 3;
        let fee_leaf: Digest = Hash::hash(&fee);
        tasm::tasm_hashing_merkle_verify(
            tx_kernel_digest,
            fee_leaf_index,
            fee_leaf,
            kernel_tree_height,
        );

        // authenticate inputs against salted commitment
        assert_eq!(input_utxos_digest, Hash::hash(&input_salted_utxos));

        // authenticate outputs against salted commitment
        assert_eq!(output_utxos_digest, Hash::hash(&output_salted_utxos));

        // get total input amount from inputs
        let mut total_input = NeptuneCoins::new(0);
        let mut i: u32 = 0;
        let num_inputs: u32 = input_salted_utxos.utxos.len() as u32;
        while i < num_inputs {
            let num_coins: u32 = input_salted_utxos.utxos[i as usize].coins.len() as u32;
            let mut j = 0;
            while j < num_coins {
                if input_salted_utxos.utxos[i as usize].coins[j as usize].type_script_hash
                    == self_digest
                {
                    let amount: NeptuneCoins = *NeptuneCoins::decode(
                        &input_salted_utxos.utxos[i as usize].coins[j as usize].state,
                    )
                    .unwrap();
                    total_input = total_input.safe_add(amount).unwrap();
                    j += 1;
                }
            }
            i += 1;
        }

        // get total output amount from outputs
        let mut total_output = NeptuneCoins::new(0);
        i = 0;
        let num_outputs: u32 = output_salted_utxos.utxos.len() as u32;
        while i < num_outputs {
            let num_coins: u32 = output_salted_utxos.utxos[i as usize].coins.len() as u32;
            let mut j = 0;
            while j < num_coins {
                if output_salted_utxos.utxos[i as usize].coins[j as usize].type_script_hash
                    == self_digest
                {
                    let amount: NeptuneCoins = *NeptuneCoins::decode(
                        &output_salted_utxos.utxos[i as usize].coins[j as usize].state,
                    )
                    .unwrap();
                    total_output = total_output.safe_add(amount).unwrap();
                    j += 1;
                }
            }
            i += 1;
        }

        // test no-inflation equation
        let total_input_plus_coinbase: NeptuneCoins = total_input.safe_add(some_coinbase).unwrap();
        let total_output_plus_coinbase: NeptuneCoins = total_output.safe_add(fee).unwrap();
        assert_eq!(total_input_plus_coinbase, total_output_plus_coinbase);
    }

    fn code() -> Vec<LabelledInstruction> {
        triton_asm! {
            push 1337
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct NativeCurrencyWitness {
    pub input_salted_utxos: SaltedUtxos,
    pub output_salted_utxos: SaltedUtxos,
    pub kernel: TransactionKernel,
}

impl TypeScriptWitness for NativeCurrencyWitness {
    fn transaction_kernel(&self) -> TransactionKernel {
        self.kernel.clone()
    }

    fn salted_input_utxos(&self) -> SaltedUtxos {
        self.input_salted_utxos.clone()
    }

    fn salted_output_utxos(&self) -> SaltedUtxos {
        self.output_salted_utxos.clone()
    }

    fn from_primitive_witness(primitive_transaction_witness: &PrimitiveWitness) -> Self {
        Self {
            input_salted_utxos: primitive_transaction_witness.input_utxos.clone(),
            output_salted_utxos: primitive_transaction_witness.output_utxos.clone(),
            kernel: primitive_transaction_witness.kernel.clone(),
        }
    }
}

impl SecretWitness for NativeCurrencyWitness {
    fn standard_input(&self) -> PublicInput {
        self.type_script_standard_input()
    }

    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        // memory
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let input_salted_utxos_address = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let output_salted_utxos_address = encode_to_memory(
            &mut memory,
            input_salted_utxos_address,
            self.salted_input_utxos(),
        );
        let coinbase_address = encode_to_memory(
            &mut memory,
            output_salted_utxos_address,
            self.salted_output_utxos(),
        );
        let fee_address = encode_to_memory(
            &mut memory,
            coinbase_address,
            self.transaction_kernel().coinbase,
        );
        encode_to_memory(&mut memory, fee_address, self.transaction_kernel().fee);
        let coinbase_path = self
            .transaction_kernel()
            .mast_path(TransactionKernelField::Coinbase)
            .clone();
        let fee_path = self
            .transaction_kernel()
            .mast_path(TransactionKernelField::Fee)
            .clone();

        // individual tokens
        let individual_tokens = vec![
            coinbase_address,
            fee_address,
            input_salted_utxos_address,
            output_salted_utxos_address,
        ];

        // digests
        let mast_paths = [coinbase_path, fee_path].concat();

        // put everything together
        NonDeterminism::new(individual_tokens)
            .with_digests(mast_paths)
            .with_ram(memory)
    }

    fn subprogram(&self) -> Program {
        NativeCurrency::program()
    }
}
