use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction;
use crate::models::blockchain::transaction::transaction_kernel::{
    TransactionKernel, TransactionKernelField,
};
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::SecretWitness;
use crate::models::{
    blockchain::transaction::primitive_witness::SaltedUtxos,
    proof_abstractions::tasm::program::ConsensusProgram,
};

use crate::models::blockchain::type_scripts::BFieldCodec;
use crate::models::proof_abstractions::tasm::builtins as tasm;
use get_size::GetSize;
use serde::{Deserialize, Serialize};

use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::{NonDeterminism, Program, PublicInput};
use tasm_lib::triton_vm::triton_asm;
use tasm_lib::twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use tasm_lib::{field, field_with_size, DIGEST_LENGTH};
use tasm_lib::{twenty_first::math::b_field_element::BFieldElement, Digest};

use super::neptune_coins::NeptuneCoins;
use super::TypeScriptWitness;

/// `NativeCurrency` is the type script that governs Neptune's native currency,
/// Neptune coins. The arithmetic for amounts are defined by the struct `NeptuneCoins`.
/// This type script is responsible for checking that transactions that tranfer
/// Neptune are balanced, *i.e.*,
///
///  sum inputs  +  (optional: coinbase)  ==  sum outputs  +  fee .
///
/// Transactions that are not balanced in this way are invalid. Furthermore, the
/// type script checks that no overflow occurs while computing the sums.
#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct NativeCurrency;

impl ConsensusProgram for NativeCurrency {
    #[allow(clippy::needless_return)]
    fn source(&self) {
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

        // divine witness from memory
        let start_address: BFieldElement = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let native_currency_witness: NativeCurrencyWitness =
            tasm::decode_from_memory(start_address);
        let coinbase: Option<NeptuneCoins> = native_currency_witness.kernel.coinbase;
        let fee: NeptuneCoins = native_currency_witness.kernel.fee;
        let input_salted_utxos: SaltedUtxos = native_currency_witness.input_salted_utxos;
        let output_salted_utxos: SaltedUtxos = native_currency_witness.output_salted_utxos;

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
                    // decode state to get amount
                    let amount: NeptuneCoins = *NeptuneCoins::decode(
                        &input_salted_utxos.utxos[i as usize].coins[j as usize].state,
                    )
                    .unwrap();

                    // safely add to total
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
                    // decode state to get amount
                    let amount: NeptuneCoins = *NeptuneCoins::decode(
                        &output_salted_utxos.utxos[i as usize].coins[j as usize].state,
                    )
                    .unwrap();

                    // make sure amount is positive (or zero)
                    assert!(!amount.is_negative());

                    // safely add to total
                    total_output = total_output.safe_add(amount).unwrap();
                    j += 1;
                }
            }
            i += 1;
        }

        // test no-inflation equation
        let total_input_plus_coinbase: NeptuneCoins = total_input.safe_add(some_coinbase).unwrap();
        assert!(!fee.is_negative());
        let total_output_plus_coinbase: NeptuneCoins = total_output.safe_add(fee).unwrap();
        assert_eq!(total_input_plus_coinbase, total_output_plus_coinbase);
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        let mut library = Library::new();
        let field_kernel = field!(NativeCurrencyWitness::kernel);
        let field_with_size_coinbase = field_with_size!(TransactionKernel::coinbase);

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));

        let assert_coinbase_size = triton_asm!(
            // _ coinbase_size

            dup 0
            push 1
            eq
            // _ coinbase_size (coinbase_size == 1)

            dup 1
            push 5
            eq
            // _ coinbase_size (coinbase_size == 1) (coinbase_size == 5)

            add
            assert
            // _ coinbase_size
        );

        let main_code = triton_asm!(
            read_io {DIGEST_LENGTH}
            hint txkmh: Digest = stack[0..5]
            // _ [txkmh]

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint native_currency_witness_ptr = stack[0]
            // _ [txkmh] *ncw

            /* Divine and authenticate coinbase field */
            dup 0
            {&field_kernel}
            hint kernel_ptr = stack[0]
            // _ [txkmh] *ncw *kernel

            dup 0
            {&field_with_size_coinbase}
            hint coinbase_ptr = stack[1]
            hint coinbase_size = stack[0]
            // _ [txkmh] *ncw *kernel *coinbase coinbase_size

            {&assert_coinbase_size}
            // _ [txkmh] *ncw *kernel *coinbase coinbase_size

            dup 8 dup 8 dup 8 dup 8 dup 8
            // _ [txkmh] *ncw *kernel *coinbase coinbase_size [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Coinbase as u32}
            // _ [txkmh] *ncw *kernel *coinbase coinbase_size [txkmh] h i

            dup 8 dup 8
            // _ [txkmh] *ncw *kernel *coinbase coinbase_size [txkmh] h i *coinbase coinbase_size

            call {hash_varlen}
            hint coinbase_hash: Digest = stack[0..5]
            // _ [txkmh] *ncw *kernel *coinbase coinbase_size [txkmh] h i [coinbase_digest]

            call {merkle_verify}
            // _ [txkmh] *ncw *kernel *coinbase coinbase_size


            /* Divine and authenticate fee field */

            halt
        );

        let subroutines = library.all_imports();

        triton_asm!(
            {&main_code}
            {&subroutines}
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq, TasmObject)]
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
}

impl From<transaction::primitive_witness::PrimitiveWitness> for NativeCurrencyWitness {
    fn from(primitive_witness: transaction::primitive_witness::PrimitiveWitness) -> Self {
        Self {
            input_salted_utxos: primitive_witness.input_utxos.clone(),
            output_salted_utxos: primitive_witness.output_utxos.clone(),
            kernel: primitive_witness.kernel.clone(),
        }
    }
}

impl SecretWitness for NativeCurrencyWitness {
    fn program(&self) -> Program {
        NativeCurrency.program()
    }

    fn standard_input(&self) -> PublicInput {
        self.type_script_standard_input()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );

        // individual tokens
        let individual_tokens = vec![];

        // digests
        let mast_paths = [
            self.kernel.mast_path(TransactionKernelField::Coinbase),
            self.kernel.mast_path(TransactionKernelField::Fee),
        ]
        .concat();

        // put everything together
        NonDeterminism::new(individual_tokens)
            .with_digests(mast_paths)
            .with_ram(memory)
    }
}

#[cfg(test)]
pub mod test {
    use crate::models::blockchain::transaction::{utxo::Utxo, PublicAnnouncement};
    use proptest::{
        arbitrary::Arbitrary, collection::vec, strategy::Strategy, test_runner::TestRunner,
    };
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;
    use transaction::utxo::LockScriptAndWitness;

    use self::transaction::primitive_witness::PrimitiveWitness;

    use super::*;

    #[test]
    fn native_currency_derived_witness_generates_accepting_tasm_program_unittest() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        let tasm_result = NativeCurrency
            .run_tasm(
                &native_currency_witness.standard_input(),
                native_currency_witness.nondeterminism(),
            )
            .unwrap();

        assert!(tasm_result.is_empty());
    }

    #[proptest(cases = 20)]
    fn balanced_transaction_is_valid(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with((#_num_inputs, #_num_outputs, #_num_public_announcements)))]
        primitive_witness: PrimitiveWitness,
    ) {
        // PrimitiveWitness::arbitrary_with already ensures the transaction is balanced
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert!(
            NativeCurrency
                .run_rust(
                    &native_currency_witness.standard_input(),
                    native_currency_witness.nondeterminism(),
                )
                .is_ok(),
            "native currency program did not halt gracefully"
        );
    }

    #[proptest(cases = 20)]
    fn unbalanced_transaction_without_coinbase_is_invalid(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(vec(arb::<Utxo>(), #_num_inputs))] _input_utxos: Vec<Utxo>,
        #[strategy(vec(arb::<LockScriptAndWitness>(), #_num_inputs))]
        _input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        #[strategy(vec(arb::<Utxo>(), #_num_outputs))] _output_utxos: Vec<Utxo>,
        #[strategy(vec(arb(), #_num_public_announcements))] _public_announcements: Vec<
            PublicAnnouncement,
        >,
        #[strategy(arb())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_primitive_witness_with(&#_input_utxos, &#_input_lock_scripts_and_witnesses, &#_output_utxos, &#_public_announcements, #_fee, None))]
        primitive_witness: PrimitiveWitness,
    ) {
        // with high probability the amounts (which are random) do not add up
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert!(
            NativeCurrency
                .run_rust(
                    &native_currency_witness.standard_input(),
                    native_currency_witness.nondeterminism(),
                )
                .is_err(),
            "native currency program failed to panic"
        );
    }

    #[proptest(cases = 20)]
    fn unbalanced_transaction_with_coinbase_is_invalid(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(arb())] _coinbase: NeptuneCoins,
        #[strategy(vec(arb::<Utxo>(), #_num_inputs))] _input_utxos: Vec<Utxo>,
        #[strategy(vec(arb::<LockScriptAndWitness>(), #_num_inputs))]
        _input_lock_scripts_and_witnesses: Vec<LockScriptAndWitness>,
        #[strategy(vec(arb::<Utxo>(), #_num_outputs))] _output_utxos: Vec<Utxo>,
        #[strategy(vec(arb(), #_num_public_announcements))] _public_announcements: Vec<
            PublicAnnouncement,
        >,
        #[strategy(arb())] _fee: NeptuneCoins,
        #[strategy(PrimitiveWitness::arbitrary_primitive_witness_with(&#_input_utxos, &#_input_lock_scripts_and_witnesses, &#_output_utxos, &#_public_announcements, #_fee, Some(#_coinbase)))]
        primitive_witness: PrimitiveWitness,
    ) {
        // with high probability the amounts (which are random) do not add up
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        assert!(
            NativeCurrency
                .run_rust(
                    &native_currency_witness.standard_input(),
                    native_currency_witness.nondeterminism(),
                )
                .is_err(),
            "native currency program failed to panic"
        );
    }
}
