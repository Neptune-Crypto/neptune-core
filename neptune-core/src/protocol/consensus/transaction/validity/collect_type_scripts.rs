use std::collections::HashMap;
use std::sync::OnceLock;

use get_size2::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::library::Library;
use tasm_lib::list::contains::Contains;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::PublicInput;

use crate::prelude::triton_vm;
use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::utxo::Coin;
use crate::protocol::consensus::transaction::utxo::Utxo;
use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

/// Maximum number of inputs/outputs allowed. Number of UTXOs must be strictly
/// less than this number.
const MAX_NUM_INPUTS_AND_OUTPUTS: usize = 100_000;

/// Maximum number of coins per UTXO allowed. Number of coins must be strictly
/// less than this number.
const MAX_NUM_COINS_PER_UTXOS: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct CollectTypeScriptsWitness {
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
}

impl SecretWitness for CollectTypeScriptsWitness {
    fn standard_input(&self) -> PublicInput {
        [&self.salted_input_utxos, &self.salted_output_utxos]
            .map(|utxos| Tip5::hash(utxos).reversed().values().to_vec())
            .concat()
            .into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        let type_script_hashes = Utxo::type_script_hashes(
            self.salted_input_utxos
                .utxos
                .iter()
                .chain(&self.salted_output_utxos.utxos),
        );
        type_script_hashes
            .into_iter()
            .flat_map(|d| d.values())
            .collect_vec()
    }

    fn program(&self) -> Program {
        CollectTypeScripts.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        NonDeterminism::default().with_ram(memory)
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct CollectTypeScripts;

impl CollectTypeScripts {
    // cannot be triggered
    const EMPTY_TYPE_SCRIPT_HASH_LIST: i128 = 1_000_510;

    // cannot be triggered
    const FIRST_TYPE_SCRIPT_HASH_NOT_NATIVE_CURRENCY: i128 = 1_000_511;

    // cannot be triggered
    const SALTED_UTXOS_TOO_SMALL: i128 = 1_000_512;

    const NON_INTEGRAL_SALTED_UTXOS: i128 = 1_000_513;

    const TOO_MANY_INPUTS_OR_OUTPUTS: i128 = 1_000_514;

    const TOO_MANY_COINS: i128 = 1_000_515;
}

impl ConsensusProgram for CollectTypeScripts {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let field_with_size_salted_input_utxos =
            field_with_size!(CollectTypeScriptsWitness::salted_input_utxos);
        let field_with_size_salted_output_utxos =
            field_with_size!(CollectTypeScriptsWitness::salted_output_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_coins = field!(Utxo::coins);
        let field_type_script_hash = field!(Coin::type_script_hash);
        let contains = library.import(Box::new(Contains::new(DataType::Digest)));
        let new_list = library.import(Box::new(New));
        let push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let eq_digest = DataType::Digest.compare();

        let collect_type_script_hashes_from_utxos =
            "neptune_consensus_transaction_collect_type_script_hashes_from_utxo".to_string();
        let collect_type_script_hashes_from_coins =
            "neptune_consensus_transaction_collect_type_script_hashes_from_coin".to_string();
        let push_digest_from_coin_to_list =
            "neptune_consensus_transaction_push_digest_to_list".to_string();
        let write_all_digests = "netpune_consensus_transaction_write_all_digests".to_string();
        let authenticate_salted_utxos_and_collect_hashes = triton_asm! {
            // BEFORE:
            // _ *ctsw *type_script_hashes *salted_utxos size

            dup 1 swap 1
            // _ *ctsw *type_script_hashes *salted_utxos *salted_utxos size


            /* Sanity check: Ensure salted utxos struct not too small */
            dup 0
            push 2
            lt
            assert error_id {Self::SALTED_UTXOS_TOO_SMALL}
            // _ *ctsw *type_script_hashes *salted_utxos *salted_utxos size


            call {hash_varlen}
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash]

            read_io 5
            // _ *ctsw *type_script_hashes *salted_utxos [salted_utxos_hash] [sud]

            {&eq_digest}
            assert error_id {Self::NON_INTEGRAL_SALTED_UTXOS}
            // _ *ctsw *type_script_hashes *salted_utxos

            /* Verify not too many UTXOs */
            {&field_utxos}
            // _ *ctsw *type_script_hashes *utxos_li

            read_mem 1 addi 2
            // _ *ctsw *type_script_hashes N *utxos[0]_si

            push {MAX_NUM_INPUTS_AND_OUTPUTS}
            dup 2
            lt
            // _ *ctsw *type_script_hashes N *utxos[0]_si (max_num_puts > N)

            assert error_id {Self::TOO_MANY_INPUTS_OR_OUTPUTS}
            // _ *ctsw *type_script_hashes N *utxos[0]_si

            push 0 swap 1
            // _ *ctsw *type_script_hashes N 0 *utxos[0]_si

            call {collect_type_script_hashes_from_utxos}
            // _ *ctsw *type_script_hashes N N *utxos[N]_si

            /* Ensure pointer is inside allowed ND-memory region */
            pop_count

            pop 3
            // _ *ctsw *type_script_hashes
        };

        let push_native_currency_hash_to_stack = NativeCurrency
            .hash()
            .values()
            .iter()
            .rev()
            .map(|elem| triton_instr!(push elem.value()))
            .collect_vec();

        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            CollectTypeScriptsWitness,
        >::default()));
        let payload = triton_asm! {

            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            // _ *ctsw

            dup 0
            call {audit_preloaded_data}
            // _ *ctsw witness_size

            pop 1
            // _ *ctsw

            call {new_list}
            // _ *ctsw *type_script_hashes

            /* Push native currency hash which must always be present */
            dup 0
            {&push_native_currency_hash_to_stack}
            call {push_digest}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_input_utxos}
            // _ *ctsw *type_script_hashes *salted_input_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            dup 1 {&field_with_size_salted_output_utxos}
            // _ *ctsw *type_script_hashes *salted_output_utxos size

            {&authenticate_salted_utxos_and_collect_hashes}
            // _ *ctsw *type_script_hashes

            read_mem 1 addi 2 swap 1
            // _ *ctsw *type_script_hashes[0] len


            /* Sanity checks of generated list of type script hashes */
            dup 0
            push 0
            lt
            assert error_id {Self::EMPTY_TYPE_SCRIPT_HASH_LIST}
            // _ *ctsw *type_script_hashes[0] len

            dup 1
            addi {Digest::LEN-1}
            read_mem {Digest::LEN}
            pop 1
            // _ *ctsw *type_script_hashes[0] len [hashes[0]]

            {&push_native_currency_hash_to_stack}
            // _ *ctsw *type_script_hashes[0] len [hashes[0]] [native_currency_hash]

            {&DataType::Digest.compare()}
            assert error_id {Self::FIRST_TYPE_SCRIPT_HASH_NOT_NATIVE_CURRENCY}
            // _ *ctsw *type_script_hashes[0] len


            /* Write all hashes to std-out */
            push {Digest::LEN} mul
            // _ *ctsw *type_script_hashes[0] size

            dup 1 add
            // _ *ctsw *type_script_hashes[0] *type_script_hashes[N+1]

            call {write_all_digests}
            // _ *ctsw *type_script_hashes[N+1] *type_script_hashes[N+1]

            pop 3
            // _

            halt

            // INVARIANT: _ *type_script_hashes N i *utxos[i]_si
            {collect_type_script_hashes_from_utxos}:
                dup 2 dup 2 eq
                // _ *type_script_hashes N i *utxos[i]_si (N==i)

                skiz return
                // _ *type_script_hashes N i *utxos[i]_si

                dup 0 addi 1 {&field_coins}
                // _ *type_script_hashes N i *utxos[i]_si *coins

                read_mem 1 addi 2
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si

                /* Verify not too many coins */
                push {MAX_NUM_COINS_PER_UTXOS}
                dup 2
                lt
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si (max_num_coins > len)

                assert error_id {Self::TOO_MANY_COINS}
                // _ *type_script_hashes N i *utxos[i]_si len *coins[0]_si

                push 0 swap 1
                // _ *type_script_hashes N i *utxos[i]_si len 0 *coins[0]_si

                call {collect_type_script_hashes_from_coins}
                // _ *type_script_hashes N i *utxos[i]_si len len *coins[len]_si


                /* Ensure pointer is inside allowed ND-memory region */
                pop_count


                pop 3
                // _ *type_script_hashes N i *utxos[i]_si

                read_mem 1 addi 2
                // _ *type_script_hashes N i size *utxos[i]

                /* Ensure forward jump, by ensuring size is u32 */
                dup 1
                pop_count
                pop 1

                add
                // _ *type_script_hashes N i *utxos[i+1]_si

                swap 1 addi 1 swap 1
                // _ *type_script_hashes N (i+1) *utxos[i+1]_si

                recurse

            // INVARIANT: _ *type_script_hashes * * * len j *coin[j]_si
            {collect_type_script_hashes_from_coins}:
                dup 2 dup 2 eq
                // _ *type_script_hashes * * * len j *coin[j]_si (len==j)

                skiz return
                // _ *type_script_hashes * * * len j *coin[j]_si

                read_mem 1 addi 2
                // _ *type_script_hashes * * * len j size *coin[j]

                dup 7 dup 0 dup 2 {&field_type_script_hash}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes *type_script_hashes [digest]

                call {contains}
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] in type_script_hashes)

                push 0 eq
                // _ *type_script_hashes * * * len j size *coin[j] *type_script_hashes ([digest] not in type_script_hashes)

                skiz call {push_digest_from_coin_to_list}
                // _ *type_script_hashes * * * len j size *coin[j] garbage

                /* Ensure forward jump, by ensuring size is u32 */
                dup 2
                pop_count
                pop 2
                // _ *type_script_hashes * * * len j size *coin[j]

                add
                // _ *type_script_hashes * * * len j *coin[j+1]_si

                swap 1 addi 1 swap 1
                // _ *type_script_hashes * * * len (j+1) *coin[j+1]_si

                recurse

            // BEFORE: _ *coin[j] *type_script_hashes
            // AFTER:  _ *coin[j] *
            {push_digest_from_coin_to_list}:
                dup 1
                // _ *coin[j] *type_script_hashes *coin[j]

                {&field_type_script_hash}
                // _ *coin[j] *type_script_hashes *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ *coin[j] *type_script_hashes [digest]

                call {push_digest}
                // _ *coin[j]

                push {0x2b00b5}

                return

            // INVARIANT: _ *type_script_hashes[i] *type_script_hashes[N+1]
            {write_all_digests}:

                dup 1 dup 1 eq
                // _ *type_script_hashes[i] *type_script_hashes[N+1] (i==N+1)

                skiz return
                // _ *type_script_hashes[i] *type_script_hashes[N+1]

                dup 1 addi {Digest::LEN-1} read_mem {Digest::LEN}
                // _ *type_script_hashes[i] *type_script_hashes[N+1] [type_script_hashes[i]] (*type_script_hashes[i]-1)

                addi {Digest::LEN+1} swap 7 pop 1
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1] [type_script_hashes[i]]

                write_io 5
                // _ *type_script_hashes[i+1] *type_script_hashes[N+1]

                recurse

        };

        let code = triton_asm! {
            {&payload}
            {&library.all_imports()}
        };

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

impl From<&PrimitiveWitness> for CollectTypeScriptsWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            salted_input_utxos: primitive_witness.input_utxos.clone(),
            salted_output_utxos: primitive_witness.output_utxos.clone(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestCaseError;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
    use tasm_lib::triton_vm;
    use tasm_lib::triton_vm::stark::Stark;
    use test_strategy::proptest;

    use super::*;
    use crate::protocol::consensus::type_scripts::native_currency::NativeCurrency;
    use crate::protocol::consensus::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_active_timelocks;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::protocol::proof_abstractions::timestamp::Timestamp;

    impl ConsensusProgramSpecification for CollectTypeScripts {
        fn source(&self) {
            let siu_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let sou_digest: Digest = tasm::tasmlib_io_read_stdin___digest();
            let start_address: BFieldElement =
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let ctsw: CollectTypeScriptsWitness = tasm::decode_from_memory(start_address);

            // divine in the salted input UTXOs with hash
            let salted_input_utxos: &SaltedUtxos = &ctsw.salted_input_utxos;
            let input_utxos: &Vec<Utxo> = &salted_input_utxos.utxos;

            assert!(input_utxos.len() < MAX_NUM_INPUTS_AND_OUTPUTS);

            // verify that the divined data matches with the explicit input digest
            let salted_input_utxos_hash: Digest = Tip5::hash(salted_input_utxos);
            assert_eq!(siu_digest, salted_input_utxos_hash);

            // divine in the salted output UTXOs with hash
            let salted_output_utxos: &SaltedUtxos = &ctsw.salted_output_utxos;
            let output_utxos: &Vec<Utxo> = &salted_output_utxos.utxos;

            assert!(output_utxos.len() < MAX_NUM_INPUTS_AND_OUTPUTS);

            // verify that the divined data matches with the explicit input digest
            let salted_output_utxos_hash: Digest = Tip5::hash(salted_output_utxos);
            assert_eq!(sou_digest, salted_output_utxos_hash);

            // iterate over all input UTXOs and collect the type script hashes
            // Because of fees, the native currency type script must *always*
            // be present.
            let mut type_script_hashes: Vec<Digest> = vec![NativeCurrency.hash()];
            let mut i = 0;
            while i < input_utxos.len() {
                let utxo: &Utxo = &input_utxos[i];

                let num_coins = utxo.coins().len();
                assert!(num_coins < MAX_NUM_COINS_PER_UTXOS);

                let mut j = 0;
                while j < num_coins {
                    let coin: &Coin = &utxo.coins()[j];
                    if !type_script_hashes.contains(&coin.type_script_hash) {
                        type_script_hashes.push(coin.type_script_hash);
                    }
                    j += 1;
                }

                i += 1;
            }

            // iterate over all output UTXOs and collect the type script hashes
            i = 0;
            while i < output_utxos.len() {
                let utxo: &Utxo = &output_utxos[i];

                let num_coins = utxo.coins().len();
                assert!(num_coins < MAX_NUM_COINS_PER_UTXOS);

                let mut j = 0;
                while j < num_coins {
                    let coin: &Coin = &utxo.coins()[j];
                    if !type_script_hashes.contains(&coin.type_script_hash) {
                        type_script_hashes.push(coin.type_script_hash);
                    }
                    j += 1;
                }

                i += 1;
            }

            // output all type script hashes
            i = 0;
            while i < type_script_hashes.len() {
                tasm::tasmlib_io_write_to_stdout___digest(type_script_hashes[i]);
                i += 1;
            }
        }
    }

    fn prop(primitive_witness: PrimitiveWitness) -> std::result::Result<(), TestCaseError> {
        let collect_type_scripts_witness = CollectTypeScriptsWitness::from(&primitive_witness);

        let expected_output = collect_type_scripts_witness.output();

        let rust_result = CollectTypeScripts
            .run_rust(
                &collect_type_scripts_witness.standard_input(),
                collect_type_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(expected_output, rust_result.clone());

        let tasm_result = CollectTypeScripts
            .run_tasm(
                &collect_type_scripts_witness.standard_input(),
                collect_type_scripts_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(rust_result, tasm_result);

        Ok(())
    }

    #[proptest(cases = 8)]
    fn native_currency_type_script_is_present_when_num_puts_are_zero(
        #[strategy(0usize..5)] _num_pub_announcements: usize,
        #[strategy(
            PrimitiveWitness::arbitrary_with_size_numbers(Some(0), 0, #_num_pub_announcements)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        let collect_type_scripts = CollectTypeScriptsWitness::from(&primitive_witness);
        let tasm_result = CollectTypeScripts
            .run_tasm(
                &collect_type_scripts.standard_input(),
                collect_type_scripts.nondeterminism(),
            )
            .unwrap();
        assert_eq!(NativeCurrency.hash().values().to_vec(), tasm_result);
    }

    #[proptest(cases = 8)]
    fn native_currency_type_script_is_always_present(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(
            PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        let collect_type_scripts = CollectTypeScriptsWitness::from(&primitive_witness);
        let tasm_result = CollectTypeScripts
            .run_tasm(
                &collect_type_scripts.standard_input(),
                collect_type_scripts.nondeterminism(),
            )
            .unwrap();

        // additionally (besides presence) verify the native currency hash comes
        // first
        assert_eq!(
            NativeCurrency.hash().values().to_vec(),
            tasm_result.into_iter().take(5).collect_vec()
        );
    }

    #[proptest(cases = 8)]
    fn derived_witness_generates_accepting_program_proptest(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(
            PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), #_num_outputs, 2)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        prop(primitive_witness)?;
    }

    #[proptest(cases = 8)]
    fn derived_witness_with_timelocks_generates_accepting_program_proptest(
        #[strategy(0usize..5)] _num_outputs: usize,
        #[strategy(0usize..5)] _num_inputs: usize,
        #[strategy(arb())] _now: Timestamp,
        #[strategy(
            arbitrary_primitive_witness_with_active_timelocks(#_num_inputs, #_num_outputs, 2, #_now)
        )]
        primitive_witness: PrimitiveWitness,
    ) {
        prop(primitive_witness)?;
    }

    #[test]
    fn small_transaction_unit() {
        for num_inputs in 0..=2 {
            for num_outputs in 0..=2 {
                let mut test_runner = TestRunner::deterministic();
                let primitive_witness =
                    PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), num_outputs, 2)
                        .new_tree(&mut test_runner)
                        .unwrap()
                        .current();
                prop(primitive_witness).unwrap();
            }
        }
    }

    #[test]
    fn derived_edge_case_witnesses_with_timelock_generate_accepting_programs_unit() {
        let mut test_runner = TestRunner::deterministic();
        let deterministic_now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let primitive_witness =
            arbitrary_primitive_witness_with_active_timelocks(1, 1, 2, deterministic_now)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();
        prop(primitive_witness).unwrap();
    }

    #[test]
    fn disallow_too_many_coins() {
        let too_many_coins = Utxo::dummy_with_num_coins(MAX_NUM_COINS_PER_UTXOS);
        let too_many_coins = SaltedUtxos {
            utxos: vec![too_many_coins],
            salt: [bfe!(0); 3],
        };

        let too_many_coins_in_input = CollectTypeScriptsWitness {
            salted_input_utxos: too_many_coins.clone(),
            salted_output_utxos: SaltedUtxos::empty(),
        };
        let too_many_coins_in_output = CollectTypeScriptsWitness {
            salted_input_utxos: SaltedUtxos::empty(),
            salted_output_utxos: too_many_coins,
        };

        for witness in [too_many_coins_in_input, too_many_coins_in_output] {
            CollectTypeScripts
                .test_assertion_failure(
                    witness.standard_input(),
                    witness.nondeterminism(),
                    &[CollectTypeScripts::TOO_MANY_COINS],
                )
                .unwrap();
        }
    }

    #[test]
    fn disallow_too_many_inputs_and_too_many_outputs() {
        let an_input_utxo = Utxo::empty_dummy();
        let too_many_utxos = SaltedUtxos {
            utxos: vec![an_input_utxo; MAX_NUM_INPUTS_AND_OUTPUTS],
            salt: [bfe!(0); 3],
        };

        let too_many_inputs = CollectTypeScriptsWitness {
            salted_input_utxos: too_many_utxos.clone(),
            salted_output_utxos: SaltedUtxos::empty(),
        };
        let too_many_outputs = CollectTypeScriptsWitness {
            salted_input_utxos: SaltedUtxos::empty(),
            salted_output_utxos: too_many_utxos,
        };

        for witness in [too_many_inputs, too_many_outputs] {
            CollectTypeScripts
                .test_assertion_failure(
                    witness.standard_input(),
                    witness.nondeterminism(),
                    &[CollectTypeScripts::TOO_MANY_INPUTS_OR_OUTPUTS],
                )
                .unwrap();
        }
    }

    #[test]
    fn collect_type_scripts_proof_generation() {
        let mut test_runner = TestRunner::deterministic();
        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let collect_type_scripts = CollectTypeScriptsWitness::from(&primitive_witness);
        let tasm_result = CollectTypeScripts
            .run_tasm(
                &collect_type_scripts.standard_input(),
                collect_type_scripts.nondeterminism(),
            )
            .unwrap();

        assert_eq!(
            collect_type_scripts.output(),
            tasm_result.clone(),
            "incorrect output"
        );

        let claim = collect_type_scripts.claim();
        let proof = triton_vm::prove(
            Stark::default(),
            &claim,
            CollectTypeScripts.program(),
            collect_type_scripts.nondeterminism(),
        )
        .expect("could not produce proof");
        assert!(
            triton_vm::verify(Stark::default(), &claim, &proof),
            "proof fails"
        );
    }

    test_program_snapshot!(
        CollectTypeScripts,
        "e225dd7103d93eda3b674d9a6bcb3da0d67fbd7d0026d2b5e85178f95f1dc04a18be2e9fbe31ffa8"
    );
}
