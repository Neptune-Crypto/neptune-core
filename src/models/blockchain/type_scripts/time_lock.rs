use std::collections::HashMap;

use crate::models::blockchain::transaction;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::type_scripts::TypeScriptAndWitness;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::SecretWitness;
use crate::Hash;
use get_size::GetSize;
use itertools::Itertools;
use num_traits::Zero;
use proptest::arbitrary::Arbitrary;
use proptest::collection::vec;
use proptest::strategy::BoxedStrategy;
use proptest::strategy::Strategy;
use proptest_arbitrary_interop::arb;
use serde::{Deserialize, Serialize};
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::triton_vm::program::Program;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::twenty_first::math::tip5::Tip5;
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::{
    triton_vm::{instruction::LabelledInstruction, program::NonDeterminism, triton_asm},
    twenty_first::math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
    Digest,
};

use crate::models::proof_abstractions::tasm::builtins as tasm;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;

use super::neptune_coins::NeptuneCoins;
use super::TypeScriptWitness;

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct TimeLock;

impl TimeLock {
    /// Create a `TimeLock` type-script-and-state-pair that releases the coins at the
    /// given release date, which corresponds to the number of milliseconds that passed
    /// since the unix epoch started (00:00 am UTC on Jan 1 1970).
    pub fn until(date: Timestamp) -> Coin {
        Coin {
            type_script_hash: TimeLock.hash(),
            state: vec![date.0],
        }
    }
}

impl ConsensusProgram for TimeLock {
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
        let _output_utxos_digest: Digest = tasm::tasm_io_read_stdin___digest();

        // divine the timestamp and authenticate it against the kernel mast hash
        let leaf_index: u32 = 5;
        let timestamp: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let leaf: Digest = Hash::hash_varlen(&timestamp.encode());
        let tree_height: u32 = 3;
        tasm::tasm_hashing_merkle_verify(tx_kernel_digest, leaf_index, leaf, tree_height);

        // get pointers to objects living in nondeterministic memory:
        //  - input Salted UTXOs
        let input_utxos_pointer: u64 = tasm::tasm_io_read_secin___bfe().value();

        // it's important to read the outputs digest too, but we actually don't care about
        // the output UTXOs (in this type script)
        let _output_utxos_pointer: u64 = tasm::tasm_io_read_secin___bfe().value();

        // authenticate salted input UTXOs against the digest that was read from stdin
        let input_salted_utxos: SaltedUtxos =
            tasm::decode_from_memory(BFieldElement::new(input_utxos_pointer));
        let input_salted_utxos_digest: Digest = Tip5::hash(&input_salted_utxos);
        assert_eq!(input_salted_utxos_digest, input_utxos_digest);

        // iterate over inputs
        let input_utxos = input_salted_utxos.utxos;
        let mut i = 0;
        while i < input_utxos.len() {
            // get coins
            let coins: &Vec<Coin> = &input_utxos[i].coins;

            // if this typescript is present
            let mut j: usize = 0;
            while j < coins.len() {
                let coin: &Coin = &coins[j];
                if coin.type_script_hash == self_digest {
                    // extract state
                    let state: &Vec<BFieldElement> = &coin.state;

                    // assert format
                    assert!(state.len() == 1);

                    // extract timestamp
                    let release_date: BFieldElement = state[0];

                    // test time lock
                    assert!(release_date.value() < timestamp.value());
                }
                j += 1;
            }
            i += 1;
        }

        return;
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        // Generated by tasm-lang compiler
        // `cargo test -- --nocapture typescript_timelock_test`
        // 2024-02-09
        // Adapted for dynamic unlock date.
        // Minor fix (divine_sibling + hash -> merkle step) applied 2024-07-05.
        triton_asm! {
            call main
            halt
            main:
            push 0 // hi
            push 1 // lo
            hint unlock_date = stack[0..2]
            call tasm_io_read_stdin___digest
            hint tx_kernel_digest = stack[0..5]
            call tasm_io_read_secin___bfe
            hint timestamp = stack[0]
            push 5
            hint leaf_index = stack[0]
            dup 1
            call encode_BField
            call tasm_langs_hash_varlen
            hint leaf = stack[0..5]
            push 3
            hint tree_height = stack[0]
            dup 12
            dup 12
            dup 12
            dup 12
            dup 12
            dup 11
            dup 11
            dup 11
            dup 11
            dup 11
            dup 11
            dup 11
            call tasm_hashing_merkle_verify
            dup 14
            dup 14
            dup 9
            split
            swap 3
            swap 1
            swap 3
            swap 2
            call tasm_arithmetic_u64_lt_standard
            assert
            pop 5
            pop 5
            pop 5
            return
            encode_BField:
            push 2
            call tasm_memory_dyn_malloc
            push 1
            swap 1
            write_mem 1
            write_mem 1
            push -2
            add
            return
            tasm_langs_hash_varlen:
            read_mem 1
            push 2
            add
            swap 1
            call tasm_hashing_algebraic_hasher_hash_varlen
            return
            tasm_arithmetic_u64_lt_standard:
            call tasm_arithmetic_u64_lt_standard_aux
            swap 4
            pop 4
            return
            tasm_arithmetic_u64_lt_standard_aux:
            dup 3
            dup 2
            lt
            dup 0
            skiz
            return
            dup 4
            dup 3
            eq
            skiz
            call tasm_arithmetic_u64_lt_standard_lo
            return
            tasm_arithmetic_u64_lt_standard_lo:
            pop 1
            dup 2
            dup 1
            lt
            return
            tasm_hashing_absorb_multiple:
            dup 0
            push 10
            swap 1
            div_mod
            swap 1
            pop 1
            swap 1
            dup 1
            push -1
            mul
            dup 3
            add
            add
            push -1
            add
            swap 1
            swap 2
            push -1
            add
            call tasm_hashing_absorb_multiple_hash_all_full_chunks
            pop 1
            push 9
            dup 2
            push -1
            mul
            add
            call tasm_hashing_absorb_multiple_pad_varnum_zeros
            pop 1
            push 1
            swap 2
            dup 1
            add
            call tasm_hashing_absorb_multiple_read_remainder
            pop 2
            sponge_absorb
            return
            tasm_hashing_absorb_multiple_hash_all_full_chunks:
            dup 1
            dup 1
            eq
            skiz
            return
            push 10
            add
            dup 0
            read_mem 5
            read_mem 5
            pop 1
            sponge_absorb
            recurse
            tasm_hashing_absorb_multiple_pad_varnum_zeros:
            dup 0
            push 0
            eq
            skiz
            return
            push 0
            swap 3
            swap 2
            swap 1
            push -1
            add
            recurse
            tasm_hashing_absorb_multiple_read_remainder:
            dup 1
            dup 1
            eq
            skiz
            return
            read_mem 1
            swap 1
            swap 2
            swap 1
            recurse
            tasm_hashing_algebraic_hasher_hash_varlen:
            sponge_init
            call tasm_hashing_absorb_multiple
            sponge_squeeze
            swap 5
            pop 1
            swap 5
            pop 1
            swap 5
            pop 1
            swap 5
            pop 1
            swap 5
            pop 1
            return
            tasm_hashing_merkle_verify:
            hint tree_height: u32 = stack[0]
            hint leaf: Digest = stack[1..6]
            hint leaf_index: u32 = stack[6]
            hint root: Digest = stack[7..12]
            push 2
            pow
            hint num_leaves: u32 = stack[0]
            dup 0
            dup 7
            lt
            assert
            dup 6
            add
            hint node_index: u32 = stack[0]
            swap 6
            pop 1
            call tasm_hashing_merkle_verify_traverse_tree
            swap 1
            swap 2
            swap 3
            swap 4
            swap 5
            pop 1
            assert_vector
            pop 5
            return
            tasm_hashing_merkle_verify_traverse_tree:
            dup 5
            push 1
            eq
            skiz
            return
            merkle_step
            recurse
            tasm_io_read_secin___bfe:
            divine 1
            return
            tasm_io_read_stdin___digest:
            read_io 5
            return
            tasm_memory_dyn_malloc:
            push 00000000004294967296
            read_mem 1
            pop 1
            dup 0
            push 0
            eq
            push 00000000004294967297
            mul
            add
            dup 0
            swap 2
            split
            swap 1
            push 0
            eq
            assert
            add
            dup 0
            split
            pop 1
            push 0
            eq
            push 0
            eq
            assert
            push 00000000004294967296
            write_mem 1
            pop 1
            return
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct TimeLockWitness {
    /// One timestamp for every input UTXO. Inputs that do not have a time lock are
    /// assigned timestamp 0, which is automatically satisfied.
    release_dates: Vec<u64>,
    input_utxos: SaltedUtxos,
    transaction_kernel: TransactionKernel,
}

impl TimeLockWitness {}

impl SecretWitness for TimeLockWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        let mut memory: HashMap<BFieldElement, BFieldElement> = HashMap::new();
        let input_salted_utxos_address = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        let output_salted_utxos_address = encode_to_memory(
            &mut memory,
            input_salted_utxos_address,
            self.input_utxos.clone(),
        );
        encode_to_memory(
            &mut memory,
            output_salted_utxos_address,
            SaltedUtxos::empty(),
        );
        let individual_tokens = vec![
            self.transaction_kernel.timestamp.0,
            input_salted_utxos_address,
            output_salted_utxos_address,
        ];
        let mast_path = self
            .transaction_kernel
            .mast_path(TransactionKernelField::Timestamp)
            .clone();
        NonDeterminism::new(individual_tokens)
            .with_digests(mast_path)
            .with_ram(memory)
    }

    fn standard_input(&self) -> PublicInput {
        self.type_script_standard_input()
    }

    fn program(&self) -> Program {
        TimeLock.program()
    }
}

impl TypeScriptWitness for TimeLockWitness {
    fn transaction_kernel(&self) -> TransactionKernel {
        self.transaction_kernel.clone()
    }

    fn salted_input_utxos(&self) -> SaltedUtxos {
        self.input_utxos.clone()
    }

    fn salted_output_utxos(&self) -> SaltedUtxos {
        SaltedUtxos::empty()
    }
}

impl From<transaction::primitive_witness::PrimitiveWitness> for TimeLockWitness {
    fn from(primitive_witness: transaction::primitive_witness::PrimitiveWitness) -> Self {
        let release_dates = primitive_witness
            .input_utxos
            .utxos
            .iter()
            .map(|utxo| {
                utxo.coins
                    .iter()
                    .find(|coin| coin.type_script_hash == TimeLock {}.hash())
                    .cloned()
                    .map(|coin| {
                        coin.state
                            .first()
                            .copied()
                            .unwrap_or_else(|| BFieldElement::new(0))
                    })
                    .unwrap_or_else(|| BFieldElement::new(0))
            })
            .map(|b| b.value())
            .collect_vec();
        let transaction_kernel = TransactionKernel::from(primitive_witness.clone());
        let input_utxos = primitive_witness.input_utxos.clone();
        Self {
            release_dates,
            input_utxos,
            transaction_kernel,
        }
    }
}

impl Arbitrary for TimeLockWitness {
    /// Parameters are:
    ///  - release_dates : Vec<u64> One release date per input UTXO. 0 if the time lock
    ///    coin is absent.
    ///  - num_outputs : usize Number of outputs.
    ///  - num_public_announcements : usize Number of public announcements.
    type Parameters = (Vec<Timestamp>, usize, usize);

    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
        let (release_dates, num_outputs, num_public_announcements) = parameters;
        let num_inputs = release_dates.len();
        (
            vec(arb::<Digest>(), num_inputs),
            vec(arb::<NeptuneCoins>(), num_inputs),
            vec(arb::<Digest>(), num_outputs),
            vec(arb::<NeptuneCoins>(), num_outputs),
            vec(arb::<PublicAnnouncement>(), num_public_announcements),
            arb::<Option<NeptuneCoins>>(),
            arb::<NeptuneCoins>(),
        )
            .prop_flat_map(
                move |(
                    input_address_seeds,
                    input_amounts,
                    output_address_seeds,
                    mut output_amounts,
                    public_announcements,
                    maybe_coinbase,
                    mut fee,
                )| {
                    // generate inputs
                    let (mut input_utxos, input_lock_scripts_and_witnesses) =
                        PrimitiveWitness::transaction_inputs_from_address_seeds_and_amounts(
                            &input_address_seeds,
                            &input_amounts,
                        );
                    let total_inputs = input_amounts.into_iter().sum::<NeptuneCoins>();

                    // add time locks to input UTXOs
                    for (utxo, release_date) in input_utxos.iter_mut().zip(release_dates.iter()) {
                        if !release_date.is_zero() {
                            let time_lock_coin = TimeLock::until(*release_date);
                            utxo.coins.push(time_lock_coin);
                        }
                    }

                    // generate valid output amounts
                    PrimitiveWitness::find_balanced_output_amounts_and_fee(
                        total_inputs,
                        maybe_coinbase,
                        &mut output_amounts,
                        &mut fee,
                    );

                    // generate output UTXOs
                    let output_utxos =
                        PrimitiveWitness::valid_transaction_outputs_from_amounts_and_address_seeds(
                            &output_amounts,
                            &output_address_seeds,
                        );

                    // generate primitive transaction witness and time lock witness from there
                    PrimitiveWitness::arbitrary_primitive_witness_with(
                        &input_utxos,
                        &input_lock_scripts_and_witnesses,
                        &output_utxos,
                        &public_announcements,
                        NeptuneCoins::zero(),
                        maybe_coinbase,
                    )
                    .prop_map(move |transaction_primitive_witness| {
                        TimeLockWitness::from(transaction_primitive_witness)
                    })
                    .boxed()
                },
            )
            .boxed()
    }
}

pub fn arbitrary_primitive_witness_with_timelocks(
    num_inputs: usize,
    num_outputs: usize,
    num_announcements: usize,
) -> BoxedStrategy<PrimitiveWitness> {
    // unwrap:
    //  - lock script preimages (inputs)
    //  - amounts (inputs)
    //  - lock script preimages (outputs)
    //  - amounts (outputs)
    //  - public announcements
    //  - fee
    //  - coinbase (option)
    //  - lock times
    (
        vec(arb::<Digest>(), num_inputs),
        vec(arb::<NeptuneCoins>(), num_inputs),
        vec(arb::<Digest>(), num_outputs),
        vec(arb::<NeptuneCoins>(), num_outputs),
        vec(arb::<PublicAnnouncement>(), num_announcements),
        arb::<NeptuneCoins>(),
        arb::<Option<NeptuneCoins>>(),
        vec(
            Timestamp::arbitrary_between(Timestamp::now(), Timestamp::now() + Timestamp::months(6)),
            num_inputs + num_outputs,
        ),
    )
        .prop_flat_map(
            |(
                input_address_seeds,
                input_amounts,
                output_address_seeds,
                mut output_amounts,
                public_announcements,
                mut fee,
                maybe_coinbase,
                lock_times,
            )| {
                let (mut input_utxos, input_lock_scripts_and_witnesses) =
                    PrimitiveWitness::transaction_inputs_from_address_seeds_and_amounts(
                        &input_address_seeds,
                        &input_amounts,
                    );
                let total_inputs = input_amounts.iter().copied().sum::<NeptuneCoins>();
                PrimitiveWitness::find_balanced_output_amounts_and_fee(
                    total_inputs,
                    maybe_coinbase,
                    &mut output_amounts,
                    &mut fee,
                );
                assert_eq!(
                    total_inputs + maybe_coinbase.unwrap_or(NeptuneCoins::new(0)),
                    output_amounts.iter().cloned().sum::<NeptuneCoins>() + fee
                );
                let mut output_utxos =
                    PrimitiveWitness::valid_transaction_outputs_from_amounts_and_address_seeds(
                        &output_amounts,
                        &output_address_seeds,
                    );
                let mut counter = 0usize;
                for utxo in input_utxos.iter_mut() {
                    let release_date = lock_times[counter];
                    let time_lock = TimeLock::until(release_date);
                    utxo.coins.push(time_lock);
                    counter += 1;
                }
                for utxo in output_utxos.iter_mut() {
                    utxo.coins.push(TimeLock::until(lock_times[counter]));
                    counter += 1;
                }
                PrimitiveWitness::arbitrary_primitive_witness_with(
                    &input_utxos,
                    &input_lock_scripts_and_witnesses,
                    &output_utxos,
                    &public_announcements,
                    fee,
                    maybe_coinbase,
                )
                .prop_map(move |primitive_witness_template| {
                    let mut primitive_witness = primitive_witness_template.clone();
                    let time_lock_witness = TimeLockWitness {
                        release_dates: lock_times.iter().map(|t| t.0.value()).collect_vec(),
                        input_utxos: primitive_witness_template.input_utxos,
                        transaction_kernel: primitive_witness_template.kernel,
                    };
                    primitive_witness.type_scripts_and_witnesses.push(
                        TypeScriptAndWitness::new_with_nondeterminism(
                            TimeLock.program(),
                            time_lock_witness.nondeterminism(),
                        ),
                    );
                    primitive_witness
                })
            },
        )
        .boxed()
}

#[cfg(test)]
mod test {
    use num_traits::Zero;
    use proptest::{collection::vec, prop_assert, strategy::Just};
    use test_strategy::proptest;
    use tokio::runtime::Runtime;

    use crate::models::{
        blockchain::{
            transaction::primitive_witness::PrimitiveWitness,
            type_scripts::time_lock::{arbitrary_primitive_witness_with_timelocks, TimeLock},
        },
        proof_abstractions::{
            tasm::program::ConsensusProgram, timestamp::Timestamp, SecretWitness,
        },
    };

    use super::TimeLockWitness;

    #[proptest(cases = 20)]
    fn test_unlocked(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(vec(Just(Timestamp::zero()), #_num_inputs))] _release_dates: Vec<Timestamp>,
        #[strategy(TimeLockWitness::arbitrary_with((#_release_dates, #_num_outputs, #_num_public_announcements)))]
        time_lock_witness: TimeLockWitness,
    ) {
        assert!(
            TimeLock {}
                .run_rust(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_ok(),
            "time lock program did not halt gracefully"
        );
    }

    #[proptest(cases = 20)]
    fn test_locked(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(vec(Timestamp::arbitrary_between(Timestamp::now()+Timestamp::days(1),Timestamp::now()+Timestamp::days(7)), #_num_inputs))]
        _release_dates: Vec<Timestamp>,
        #[strategy(TimeLockWitness::arbitrary_with((#_release_dates, #_num_outputs, #_num_public_announcements)))]
        time_lock_witness: TimeLockWitness,
    ) {
        println!("now: {}", Timestamp::now());
        assert!(
            TimeLock {}
                .run_rust(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_err(),
            "time lock program failed to panic"
        );
    }

    #[proptest(cases = 20)]
    fn test_released(
        #[strategy(1usize..=3)] _num_inputs: usize,
        #[strategy(1usize..=3)] _num_outputs: usize,
        #[strategy(1usize..=3)] _num_public_announcements: usize,
        #[strategy(vec(Timestamp::arbitrary_between(Timestamp::now()-Timestamp::days(7),Timestamp::now()-Timestamp::days(1)), #_num_inputs))]
        _release_dates: Vec<Timestamp>,
        #[strategy(TimeLockWitness::arbitrary_with((#_release_dates, #_num_outputs, #_num_public_announcements)))]
        time_lock_witness: TimeLockWitness,
    ) {
        println!("now: {}", Timestamp::now());
        prop_assert!(
            TimeLock
                .run_rust(
                    &time_lock_witness.standard_input(),
                    time_lock_witness.nondeterminism(),
                )
                .is_ok(),
            "time lock program did not halt gracefully"
        );
    }

    #[proptest(cases = 5)]
    fn primitive_witness_with_timelocks_is_valid(
        #[strategy(arbitrary_primitive_witness_with_timelocks(2, 2, 2))]
        primitive_witness: PrimitiveWitness,
    ) {
        prop_assert!(Runtime::new()
            .unwrap()
            .block_on(primitive_witness.validate()));
    }
}
