use std::collections::HashMap;

use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_kernel::{
    TransactionKernel, TransactionKernelField,
};
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::SecretWitness;
use crate::models::{
    blockchain::transaction::primitive_witness::SaltedUtxos,
    proof_abstractions::tasm::program::ConsensusProgram,
};

use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::validity::tasm::coinbase_amount::CoinbaseAmount;
use crate::models::blockchain::type_scripts::BFieldCodec;
use crate::models::proof_abstractions::tasm::builtins as tasm;
use get_size::GetSize;
use serde::{Deserialize, Serialize};

use tasm_lib::data_type::DataType;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::{NonDeterminism, Program, PublicInput};
use tasm_lib::triton_vm::triton_asm;
use tasm_lib::twenty_first::bfe;
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
        let input_salted_utxos: SaltedUtxos = native_currency_witness.salted_input_utxos;
        let output_salted_utxos: SaltedUtxos = native_currency_witness.salted_output_utxos;

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
                }
                j += 1;
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
                }
                j += 1;
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
        let coin_size = NeptuneCoins::static_length().unwrap();
        let mut library = Library::new();
        let field_kernel = field!(NativeCurrencyWitness::kernel);
        let field_with_size_coinbase = field_with_size!(TransactionKernel::coinbase);
        let field_fee = field!(TransactionKernel::fee);
        let field_with_size_salted_input_utxos =
            field_with_size!(NativeCurrencyWitness::salted_input_utxos);
        let field_with_size_salted_output_utxos =
            field_with_size!(NativeCurrencyWitness::salted_output_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_coins = field!(Utxo::coins);
        let field_type_script_hash = field!(Coin::type_script_hash);
        let field_state = field!(Coin::state);

        let hash_varlen = library.import(Box::new(HashVarlen));
        let merkle_verify =
            library.import(Box::new(tasm_lib::hashing::merkle_verify::MerkleVerify));
        let hash_fee = library.import(Box::new(HashStaticSize { size: coin_size }));
        let u128_safe_add =
            library.import(Box::new(tasm_lib::arithmetic::u128::safe_add::SafeAddU128));
        let coinbase_pointer_to_amount = library.import(Box::new(CoinbaseAmount));

        let own_program_digest_ptr_write = library.kmalloc(DIGEST_LENGTH as u32);
        let own_program_digest_ptr_read =
            own_program_digest_ptr_write + bfe!(DIGEST_LENGTH as u32 - 1);

        let loop_utxos_add_amounts =
            "neptune_consensus_transaction_type_script_loop_utxos_add_amounts".to_string();
        let loop_coins_add_amounts =
            "neptune_consensus_transaction_type_script_loop_coins_add_amounts".to_string();
        let read_and_add_amount =
            "neptune_consensus_transaction_type_script_read_and_add_amount".to_string();

        let store_own_program_digest = triton_asm!(
            // _

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [own_program_digest]

            push {own_program_digest_ptr_write}
            write_mem {DIGEST_LENGTH}
            pop 1
            // _
        );

        let load_own_program_digest = triton_asm! {
            // _

            push {own_program_digest_ptr_read}
            read_mem {DIGEST_LENGTH}
            pop 1
            // _ [own_program_digest]
        };

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

        let digest_eq = DataType::Digest.compare();
        let u128_eq = DataType::U128.compare();

        let authenticate_salted_utxos = triton_asm! {
            // BEFORE:
            // _ *salted_utxos size

            dup 1 swap 1
            // _ *salted_utxos *salted_utxos size

            call {hash_varlen}
            // _ *salted_utxos [salted_utxos_hash]

            read_io 5
            // _ *salted_utxos [salted_utxos_hash] [sud]

            {&digest_eq} assert
            // _ *salted_utxos
        };

        let main_code = triton_asm! {
            // _

            {&store_own_program_digest}
            // _

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

            pop 1
            // _ [txkmh] *ncw *kernel *coinbase


            /* Divine and authenticate fee field */

            dup 1
            // _ [txkmh] *ncw *kernel *coinbase *kernel

            {&field_fee}
            // _ [txkmh] *ncw *kernel *coinbase *fee
            hint fee_ptr = stack[0]

            dup 8
            dup 8
            dup 8
            dup 8
            dup 8
            // _ [txkmh] *ncw *kernel *coinbase *fee [txkmh]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Fee as u32}
            // _ [txkmh] *ncw *kernel *coinbase *fee [txkmh] h i

            dup 7
            // _ [txkmh] *ncw *kernel *coinbase *fee [txkmh] h i *fee

            call {hash_fee} pop 1
            // _ [txkmh] *ncw *kernel *coinbase *fee [txkmh] h i [fee_digest]

            call {merkle_verify}
            // _ [txkmh] *ncw *kernel *coinbase *fee


            /* Divine and authenticate salted input and output UTXOs */

            dup 3 {&field_with_size_salted_input_utxos}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_input_utxos size

            {&authenticate_salted_utxos}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_input_utxos

            dup 4 {&field_with_size_salted_output_utxos}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_input_utxos *salted_output_utxos size

            {&authenticate_salted_utxos}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_input_utxos *salted_output_utxos


            /* Compute left-hand side: sum inputs + (optional coinbase) */

            swap 1 {&field_utxos}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos *input_utxos

            read_mem 1 push 2 add
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N *input_utxos[0]_si

            push 0 swap 1
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si

            push 0 push 0 push 0
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0

            dup 8
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 *coinbase

            call {coinbase_pointer_to_amount}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N 0 *input_utxos[0]_si 0 0 0 [coinbase]

            hint enn = stack[9]
            hint i = stack[8]
            hint utxos_i = stack[7]

            call {loop_utxos_add_amounts}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input]

            hint total_input : u128 = stack[0..4]


            /* Compute right-hand side: fee + sum outputs */

            dup 11 dup 11
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee *salted_output_utxos

            {&field_utxos}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee *output_utxos

            read_mem 1 push 2 add
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N *output_utxos[0]_si

            push 0 swap 1
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si

            push 0 push 0 push 0
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0

            dup 6
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0 *fee

            push {coin_size - 1} add
            read_mem {coin_size} pop 1
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N 0 *output_utxos[0]_si 0 0 0 [fee]

            hint utxos_i_si = stack[7]
            hint i = stack[8]
            hint enn = stack[9]

            call {loop_utxos_add_amounts}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] *fee N N *output_utxos[N]_si * * * [total_output]

            hint total_output : u128 = stack[0..4]

            swap 7 pop 1
            swap 7 pop 1
            swap 7 pop 1
            swap 7 pop 1
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] [total_output] * * *

            pop 3
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * [total_input] [total_output]

            {&u128_eq}
            // _ [txkmh] *ncw *kernel *coinbase *fee *salted_output_utxos N N *input_utxos[N]_si * * * (total_input == total_output)

            assert

            halt
        };

        let subroutines = triton_asm! {

            // INVARIANT: _ N i *utxos[i]_si * * * [amount]
            {loop_utxos_add_amounts}:

                dup 9 dup 9 eq
                // _ N i *utxos[i]_si * * * [amount] (N == i)

                skiz return
                // _ N i *utxos[i]_si * * * [amount]

                dup 7 push 1 add
                // _ N i *utxos[i]_si * * * [amount] *utxos[i]

                {&field_coins}
                // _ N i *utxos[i]_si * * * [amount] *coins

                read_mem 1 push 2 add
                // _ N i *utxos[i]_si * * * [amount] M *coins[0]_si

                swap 6 pop 1
                // _ N i *utxos[i]_si * * *coins[0]_si [amount] M

                swap 7 pop 1
                // _ N i *utxos[i]_si M * *coins[0]_si [amount]

                push 0 swap 6 pop 1
                // _ N i *utxos[i]_si M 0 *coins[0]_si [amount]

                hint coins_j_si = stack[4]
                hint j = stack[5]
                hint emm = stack[6]
                break

                call {loop_coins_add_amounts}
                // _ N i *utxos[i]_si M M *coins[M]_si [amount]

                dup 8 push 1 add
                // _ N i *utxos[i]_si M M *coins[M]_si [amount] (i+1)

                swap 9 pop 1
                // _ N (i+1) *utxos[i]_si M M *coins[M]_si [amount]

                dup 7 read_mem 1 push 2 add
                // _ N (i+1) *utxos[i]_si M M *coins[M]_si [amount] size(utxos[i]) *utxos[i]

                add swap 8 pop 1
                // _ N (i+1) *utxos[i+1]_si M M *coins[M]_si [amount]

                recurse

            // INVARIANT: _ M j *coins[j]_si [amount]
            {loop_coins_add_amounts}:

                dup 6 dup 6 eq
                // _ M j *coins[j]_si [amount] (M == j)

                skiz return
                // _ M j *coins[j]_si [amount]

                dup 4 push 1 add
                hint coins_j = stack[0]
                // _ M j *coins[j]_si [amount] *coins[j]

                {&field_type_script_hash}
                hint type_script_hash_ptr = stack[0]
                // _ M j *coins[j]_si [amount] *type_script_hash

                push {DIGEST_LENGTH-1} add read_mem {DIGEST_LENGTH} pop 1
                hint type_script_hash : Digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [type_script_hash]

                {&load_own_program_digest}
                hint own_program_digest = stack[0..5]
                // _ M j *coins[j]_si [amount] [type_script_hash] [own_program_digest]

                {&digest_eq}
                hint digests_are_equal = stack[0]
                // _ M j *coins[j]_si [amount] (type_script_hash == own_program_digest)

                skiz call {read_and_add_amount}
                // _ M j *coins[j]_si [amount']

                dup 5 push 1 add swap 6 pop 1
                // _ M (j+1) *coins[j]_si [amount']

                dup 4 read_mem 1 push 2 add
                // _ M (j+1) *coins[j]_si [amount'] size(coins[j]) *coins[j]

                add
                // _ M (j+1) *coins[j]_si [amount'] *coins[j+1]_si

                swap 5 pop 1
                // _ M (j+1) *coins[j+1]_si [amount']

                recurse

                // BEFORE: _ *coins[j]_si [amount]
                // AFTER: _ *coins[j]_si [amount']
                {read_and_add_amount}:
                    dup 4 push 1 add
                    // _ *coins[j]_si [amount] *coins[j]

                    {&field_state}
                    // _ *coins[j]_si [amount] *state

                    read_mem 1 push {coin_size+1} add
                    // _ *coins[j]_si [amount] state_size *state[last]

                    swap 1 push {coin_size} eq assert
                    // _ *coins[j]_si [amount] *state[last]

                    read_mem {coin_size} pop 1
                    // _ *coins[j]_si [amount] [coin_amount]

                    call {u128_safe_add}
                    // _ *coins[j]_si [amount']

                    return
        };

        let imports = library.all_imports();

        triton_asm!(
            {&main_code}
            {&subroutines}
            {&imports}
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq, TasmObject)]
pub struct NativeCurrencyWitness {
    pub salted_input_utxos: SaltedUtxos,
    pub salted_output_utxos: SaltedUtxos,
    pub kernel: TransactionKernel,
}

impl TypeScriptWitness for NativeCurrencyWitness {
    fn transaction_kernel(&self) -> TransactionKernel {
        self.kernel.clone()
    }

    fn salted_input_utxos(&self) -> SaltedUtxos {
        self.salted_input_utxos.clone()
    }

    fn salted_output_utxos(&self) -> SaltedUtxos {
        self.salted_output_utxos.clone()
    }
}

impl From<PrimitiveWitness> for NativeCurrencyWitness {
    fn from(primitive_witness: PrimitiveWitness) -> Self {
        Self {
            salted_input_utxos: primitive_witness.input_utxos.clone(),
            salted_output_utxos: primitive_witness.output_utxos.clone(),
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
    use proptest::prelude::*;
    use proptest::prop_assert;
    use proptest::{
        arbitrary::Arbitrary, collection::vec, strategy::Strategy, test_runner::TestRunner,
    };
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;
    use transaction::utxo::LockScriptAndWitness;

    use self::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::transaction::{utxo::Utxo, PublicAnnouncement};
    use crate::models::blockchain::type_scripts::time_lock::arbitrary_primitive_witness_with_timelocks;
    use crate::models::proof_abstractions::tasm::program::ConsensusError;
    use crate::triton_vm::prelude::InstructionError;

    use super::*;

    fn prop_positive(native_currency_witness: NativeCurrencyWitness) -> Result<(), TestCaseError> {
        let tasm_result = NativeCurrency
            .run_tasm(
                &native_currency_witness.standard_input(),
                native_currency_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert!(tasm_result.is_empty());

        let rust_result = NativeCurrency
            .run_rust(
                &native_currency_witness.standard_input(),
                native_currency_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert!(rust_result.is_empty());

        Ok(())
    }

    fn prop_negative(
        native_currency_witness: NativeCurrencyWitness,
        allowed_failure_codes: &[InstructionError],
    ) -> Result<(), TestCaseError> {
        let tasm_result = NativeCurrency.run_tasm(
            &native_currency_witness.standard_input(),
            native_currency_witness.nondeterminism(),
        );
        prop_assert!(tasm_result.is_err());
        let triton_vm_error_code = match tasm_result.unwrap_err() {
            ConsensusError::TritonVMPanic(_string, instruction_error) => instruction_error,
            _ => unreachable!(),
        };

        prop_assert!(allowed_failure_codes.contains(&triton_vm_error_code));

        let rust_result = NativeCurrency.run_rust(
            &native_currency_witness.standard_input(),
            native_currency_witness.nondeterminism(),
        );
        prop_assert!(rust_result.is_err());

        Ok(())
    }

    #[test]
    fn native_currency_derived_witness_generates_accepting_tasm_program_empty_tx() {
        let mut test_runner = TestRunner::deterministic();

        // Generate a tx with coinbase input, no outputs, fee-size is the same
        // as the coinbase, so tx is valid.
        let primitive_witness = PrimitiveWitness::arbitrary_with((0, 0, 0))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        prop_positive(native_currency_witness).unwrap();
    }

    #[test]
    fn native_currency_derived_witness_generates_accepting_tasm_program_unittest() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with((2, 2, 2))
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        prop_positive(native_currency_witness).unwrap();
    }

    #[proptest(cases = 10)]
    fn balanced_transaction_is_valid(
        #[strategy(0usize..=3)] _num_inputs: usize,
        #[strategy(0usize..=3)] _num_outputs: usize,
        #[strategy(0usize..=1)] _num_public_announcements: usize,
        #[strategy(PrimitiveWitness::arbitrary_with((#_num_inputs, #_num_outputs, #_num_public_announcements)))]
        primitive_witness: PrimitiveWitness,
    ) {
        // PrimitiveWitness::arbitrary_with already ensures the transaction is balanced
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        prop_positive(native_currency_witness)?;
    }

    #[proptest(cases = 10)]
    fn native_currency_is_valid_for_primitive_witness_with_timelock(
        #[strategy(0usize..=3)] _num_inputs: usize,
        #[strategy(0usize..=3)] _num_outputs: usize,
        #[strategy(0usize..=1)] _num_public_announcements: usize,
        #[strategy(arbitrary_primitive_witness_with_timelocks(#_num_inputs, #_num_outputs, #_num_public_announcements))]
        primitive_witness: PrimitiveWitness,
    ) {
        let native_currency_witness = NativeCurrencyWitness::from(primitive_witness);
        prop_positive(native_currency_witness)?;
    }

    #[proptest(cases = 20)]
    fn unbalanced_transaction_without_coinbase_is_invalid(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(0usize..=3)] _num_public_announcements: usize,
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
        prop_negative(
            native_currency_witness,
            &[InstructionError::AssertionFailed],
        )?;
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
        prop_negative(
            native_currency_witness,
            &[InstructionError::AssertionFailed],
        )?;
    }
}

#[cfg(test)]
mod bench {
    use crate::models::blockchain::type_scripts::time_lock::arbitrary_primitive_witness_with_timelocks;
    use crate::models::proof_abstractions::SecretWitness;
    use crate::tests::shared::bench_consensus_program;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use tasm_lib::snippet_bencher::BenchmarkCase;

    use super::*;

    #[test]
    fn bench_native_currency() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = arbitrary_primitive_witness_with_timelocks(2, 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let nc_witness = NativeCurrencyWitness::from(primitive_witness);
        bench_consensus_program(
            NativeCurrency,
            &nc_witness.standard_input(),
            nc_witness.nondeterminism(),
            "NativeCurrency-2in-2out",
            BenchmarkCase::CommonCase,
        );

        let primitive_witness = arbitrary_primitive_witness_with_timelocks(4, 4, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let nc_witness = NativeCurrencyWitness::from(primitive_witness);
        bench_consensus_program(
            NativeCurrency,
            &nc_witness.standard_input(),
            nc_witness.nondeterminism(),
            "NativeCurrency-4in-4out",
            BenchmarkCase::CommonCase,
        );
    }
}
