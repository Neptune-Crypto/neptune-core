use crate::models::blockchain::transaction::primitive_witness::arbitrary_primitive_witness_with;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernelField;
use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::consensus::mast_hash::MastHash;
use crate::models::consensus::SecretWitness;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_kernel::get_swbf_indices;
use crate::util_types::mutator_set::shared::NUM_TRIALS;
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
use tasm_lib::twenty_first::prelude::AlgebraicHasher;
use tasm_lib::{
    triton_vm::{
        instruction::LabelledInstruction,
        program::{NonDeterminism, Program},
        triton_asm,
    },
    twenty_first::shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec},
    Digest,
};

use crate::models::consensus::tasm::builtins as tasm;
use crate::models::consensus::tasm::program::ConsensusProgram;

use super::neptune_coins::NeptuneCoins;

#[derive(Debug, Clone, Deserialize, Serialize, BFieldCodec, GetSize, PartialEq, Eq)]
pub struct TimeLock {}

impl TimeLock {
    /// Create a `TimeLock` type-script-and-state-pair that releases the coins at the
    /// given release date, which corresponds to the number of milliseconds that passed
    /// since the unix epoch started (00:00 am UTC on Jan 1 1970).
    pub fn until(date: u64) -> Coin {
        Coin {
            type_script_hash: Self::hash(),
            state: vec![BFieldElement::new(date)],
        }
    }
}

impl ConsensusProgram for TimeLock {
    #[allow(clippy::needless_return)]
    fn source() {
        // get in the current program's hash digest
        let self_digest: Digest = tasm::own_program_digest();

        // read standard input: the transaction kernel mast hash
        let tx_kernel_digest: Digest = tasm::tasm_io_read_stdin___digest();

        // divine the timestamp and authenticate it against the kernel mast hash
        let leaf_index: u32 = 5;
        let timestamp: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let leaf: Digest = Hash::hash_varlen(&timestamp.encode());
        let tree_height: u32 = 3;
        tasm::tasm_hashing_merkle_verify(tx_kernel_digest, leaf_index, leaf, tree_height);

        // get pointers to objects living in nondeterministic memory:
        //  - list of input UTXOs
        //  - list of input UTXOs' membership proofs in the mutator set
        //  - transaction kernel
        let input_utxos_pointer: u64 = tasm::tasm_io_read_secin___bfe().value();
        let input_utxos: Vec<Utxo> =
            tasm::decode_from_memory(BFieldElement::new(input_utxos_pointer));
        let input_mps_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let input_mps: Vec<MsMembershipProof> = tasm::decode_from_memory(input_mps_pointer);
        let transaction_kernel_pointer: BFieldElement = tasm::tasm_io_read_secin___bfe();
        let transaction_kernel: TransactionKernel =
            tasm::decode_from_memory(transaction_kernel_pointer);

        // authenticate kernel
        let transaction_kernel_hash = Hash::hash(&transaction_kernel);
        assert_eq!(transaction_kernel_hash, tx_kernel_digest);

        // compute the inputs (removal records' absolute index sets)
        let mut inputs_derived: Vec<Digest> = Vec::with_capacity(input_utxos.len());
        let mut i: usize = 0;
        while i < input_utxos.len() {
            let aocl_leaf_index: u64 = input_mps[i].auth_path_aocl.leaf_index;
            let receiver_preimage: Digest = input_mps[i].receiver_preimage;
            let sender_randomness: Digest = input_mps[i].sender_randomness;
            let item: Digest = Hash::hash(&input_utxos[i]);
            let index_set: [u128; NUM_TRIALS as usize] =
                get_swbf_indices(item, sender_randomness, receiver_preimage, aocl_leaf_index);
            inputs_derived.push(Hash::hash(&index_set));
            i += 1;
        }

        // read inputs (absolute index sets) from kernel
        let mut inputs_kernel: Vec<Digest> = Vec::with_capacity(transaction_kernel.inputs.len());
        i = 0;
        while i < transaction_kernel.inputs.len() {
            let index_set = transaction_kernel.inputs[i].absolute_indices.to_vec();
            inputs_kernel.push(Hash::hash(&index_set));
            i += 1;
        }

        // authenticate inputs
        tasm::tasm_list_unsafeimplu32_multiset_equality(inputs_derived, inputs_kernel);

        // iterate over inputs
        i = 0;
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

    fn code() -> Vec<LabelledInstruction> {
        // Generated by tasm-lang compiler
        // `cargo test -- --nocapture typescript_timelock_test`
        // 2024-02-09
        // Adapted for dynamic unlock date
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
            divine_sibling
            hash
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
    input_utxos: Vec<Utxo>,
    input_membership_proofs: Vec<MsMembershipProof>,
    transaction_kernel: TransactionKernel,
}

impl TimeLockWitness {
    pub fn from_primitive_witness(transaction_primitive_witness: &PrimitiveWitness) -> Self {
        let release_dates = transaction_primitive_witness
            .input_utxos
            .iter()
            .map(|utxo| {
                utxo.coins
                    .iter()
                    .find(|coin| coin.type_script_hash == TimeLock::hash())
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
        let transaction_kernel =
            TransactionKernel::from_primitive_witness(transaction_primitive_witness);
        let input_utxos = transaction_primitive_witness.input_utxos.clone();
        let input_mps = transaction_primitive_witness
            .input_membership_proofs
            .clone();
        Self {
            release_dates,
            input_utxos,
            input_membership_proofs: input_mps,
            transaction_kernel,
        }
    }
}

impl SecretWitness for TimeLockWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        NonDeterminism::new(self.release_dates.encode()).with_digests(
            self.transaction_kernel
                .mast_path(TransactionKernelField::Timestamp)
                .clone(),
        )
    }

    fn subprogram(&self) -> Program {
        Program::new(&TimeLock::code())
    }
}

impl Arbitrary for TimeLockWitness {
    type Parameters = (Vec<u64>, usize, usize);

    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(parameters: Self::Parameters) -> Self::Strategy {
        let (release_dates, num_outputs, num_public_announcements) = parameters;
        let num_inputs = release_dates.len();
        (
            vec(arb::<Utxo>(), num_inputs),
            vec(arb::<Utxo>(), num_outputs),
            vec(arb::<PublicAnnouncement>(), num_public_announcements),
        )
            .prop_flat_map(
                move |(mut input_utxos, output_utxos, public_announcements)| {
                    // add time locks to input utxos
                    for (utxo, release_date) in input_utxos.iter_mut().zip(release_dates.iter()) {
                        if *release_date != 0 {
                            let time_lock_coin = TimeLock::until(*release_date);
                            utxo.coins.push(time_lock_coin);
                        }
                    }

                    // generate primitive transaction witness and time lock witness from there
                    arbitrary_primitive_witness_with(
                        &input_utxos,
                        &[],
                        &[],
                        &output_utxos,
                        &public_announcements,
                        NeptuneCoins::zero(),
                        None,
                    )
                    .prop_map(move |transaction_primitive_witness| {
                        TimeLockWitness::from_primitive_witness(&transaction_primitive_witness)
                    })
                    .boxed()
                },
            )
            .boxed()
    }
}
