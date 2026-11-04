//! The vault type script in Triton assembly, and its witness.
//!
//! The program checks the rules of [`Vault::validate`] over the transaction's
//! salted inputs and outputs and two fields of its kernel, its outputs and its
//! announcements. The witness writes all four to non-deterministic memory, and
//! the program hashes each one and compares the hash with the standard input
//! or authenticates it against the kernel MAST hash before reading it. So the
//! memory the program reads is the honest encoding of each.
//!
//! The witness also supplies, for every output that carries a vault marker,
//! the index of the vault's announcement, which the program checks.

use std::collections::HashMap;

use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::primitive_witness::SaltedUtxos;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelField;
use neptune_consensus::transaction::utxo::Coin;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_consensus::type_scripts::TypeScriptAndWitness;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::arithmetic::u128::lt::Lt;
use tasm_lib::arithmetic::u128::safe_add::SafeAdd;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::neptune::mutator_set::commit::Commit;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::prelude::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;

use super::vault_lock_script;
use super::Vault;
use super::VaultAnnouncement;
use super::VaultState;
use super::AMOUNT_LEN;
use super::VAULT_FLAG;

/// A salted UTXO list does not hash to its digest in the standard input.
pub(super) const BAD_SALTED_UTXOS_ERROR: i128 = 1_000_590;

/// A coin of the vault type script carries a state that is neither a token
/// nor a marker, or an amount has a limb that is not a `u32`, or a coin of
/// `Vaultee` in a vault carries a state that is not an amount.
pub(super) const INVALID_STATE_ERROR: i128 = 1_000_591;

/// An amount, or a sum of amounts, lies outside the range from zero to the
/// largest amount.
pub(super) const OUT_OF_RANGE_ERROR: i128 = 1_000_593;

/// An output carries a vault marker but is not a vault.
pub(super) const NOT_A_VAULT_ERROR: i128 = 1_000_594;

/// The announcement at the divined index is not the vault's announcement, or
/// its randomnesses do not give the vault's addition record.
pub(super) const MISSING_ANNOUNCEMENT_ERROR: i128 = 1_000_595;

/// More than one vault is among the inputs, or among the outputs.
pub(super) const TOO_MANY_VAULTS_ERROR: i128 = 1_000_596;

/// The tokens minted less those burnt differ from the holding added less that
/// taken.
pub(super) const UNBACKED_ERROR: i128 = 1_000_597;

/// The part of the witness that the program reads from memory.
#[derive(Debug, Clone, BFieldCodec, TasmObject)]
struct VaultWitnessMemory {
    salted_input_utxos: SaltedUtxos,
    salted_output_utxos: SaltedUtxos,
    outputs: Vec<AdditionRecord>,
    announcements: Vec<Announcement>,
}

/// The encodings of a marker's state and of a token's discriminant.
///
/// The program compares states element by element, so it fixes their layout
/// here, where a change to [`VaultState`]'s encoding would show.
fn state_encoding() -> (BFieldElement, BFieldElement) {
    let marker = VaultState::Marker.encode();
    let amount = NativeCurrencyAmount::from_nau(1);
    let token = VaultState::Token(amount).encode();
    assert_eq!(1, marker.len(), "a marker is its discriminant");
    assert_eq!(
        amount.encode(),
        token[1..],
        "a token is its discriminant followed by its amount"
    );

    (marker[0], token[0])
}

fn push_digest(digest: Digest) -> Vec<LabelledInstruction> {
    digest
        .values()
        .iter()
        .rev()
        .flat_map(|element| triton_asm!(push {element.value()}))
        .collect()
}

/// Push a `u128` in the layout of tasm-lib's `u128` snippets: the most
/// significant limb deepest.
fn push_u128(value: u128) -> Vec<LabelledInstruction> {
    (0..4)
        .rev()
        .flat_map(|i| triton_asm!(push {(value >> (32 * i)) as u32}))
        .collect()
}

pub(super) fn program(vaultee: Digest) -> Program {
    Program::new(&code(vaultee))
}

fn code(vaultee: Digest) -> Vec<LabelledInstruction> {
    let (marker, token) = state_encoding();
    let max_plus_one = u128::try_from(NativeCurrencyAmount::MAX_NAU).unwrap() + 1;

    let mut library = Library::new();
    let audit = library.import(Box::new(
        VerifyNdSiIntegrity::<VaultWitnessMemory>::default(),
    ));
    let hash_varlen = library.import(Box::new(HashVarlen));
    let authenticate_outputs = library.import(Box::new(AuthenticateTxkField(
        TransactionKernelField::Outputs,
    )));
    let authenticate_announcements = library.import(Box::new(AuthenticateTxkField(
        TransactionKernelField::Announcements,
    )));
    let safe_add = library.import(Box::new(SafeAdd));
    let lt = library.import(Box::new(Lt));
    let commit = library.import(Box::new(Commit));

    let own_digest = library.kmalloc(Digest::LEN as u32);
    let kernel_outputs = library.kmalloc(1);
    let kernel_announcements = library.kmalloc(1);
    let tokens = library.kmalloc(4);
    let holding = library.kmalloc(4);
    let num_vaults = library.kmalloc(1);

    let digest_eq = DataType::Digest.compare();
    let u128_eq = DataType::U128.compare();
    let field_salted_inputs = field_with_size!(VaultWitnessMemory::salted_input_utxos);
    let field_salted_outputs = field_with_size!(VaultWitnessMemory::salted_output_utxos);
    let field_outputs = field_with_size!(VaultWitnessMemory::outputs);
    let field_announcements = field_with_size!(VaultWitnessMemory::announcements);
    let field_utxos = field!(SaltedUtxos::utxos);
    let field_coins = field!(Utxo::coins);
    let field_lock_script_hash = field!(Utxo::lock_script_hash);
    let field_type_script_hash = field!(Coin::type_script_hash);
    let field_state = field!(Coin::state);
    let field_message = field!(Announcement::message);

    let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
    let read_own_digest =
        triton_asm!(push {own_digest.read_address()} read_mem {Digest::LEN} pop 1);

    let authenticate_salted_utxos = triton_asm!(
        // _ *salted_utxos size
        dup 1 swap 1
        call {hash_varlen}
        read_io {Digest::LEN}
        {&digest_eq}
        assert error_id {BAD_SALTED_UTXOS_ERROR}
        // _ *salted_utxos
    );

    let main = triton_asm!(
        // The program's own digest lies at the bottom of the stack.
        dup 15 dup 15 dup 15 dup 15 dup 15
        push {own_digest.write_address()} write_mem {Digest::LEN} pop 1

        read_io {Digest::LEN}
        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        dup 0 call {audit} pop 1
        // _ [txkmh] *w

        dup 0 {&field_salted_inputs} {&authenticate_salted_utxos}
        dup 1 {&field_salted_outputs} {&authenticate_salted_utxos}
        // _ [txkmh] *w *salted_inputs *salted_outputs

        dup 7 dup 7 dup 7 dup 7 dup 7
        dup 7 {&field_outputs}
        dup 1 push {kernel_outputs.write_address()} write_mem 1 pop 1
        call {authenticate_outputs}

        dup 7 dup 7 dup 7 dup 7 dup 7
        dup 7 {&field_announcements}
        dup 1 push {kernel_announcements.write_address()} write_mem 1 pop 1
        call {authenticate_announcements}
        // _ [txkmh] *w *salted_inputs *salted_outputs

        swap 1 {&field_utxos}
        push 0 swap 1 call tally
        // _ [txkmh] *w *salted_outputs [t_in] [h_in] v_in

        pick 9 {&field_utxos}
        push 1 swap 1 call tally
        // _ [txkmh] *w [t_in] [h_in] v_in [t_out] [h_out] v_out

        push 2 swap 1 lt assert error_id {TOO_MANY_VAULTS_ERROR}
        pick 8 push 2 swap 1 lt assert error_id {TOO_MANY_VAULTS_ERROR}
        // _ [txkmh] *w [t_in] [h_in] [t_out] [h_out]

        pick 7 pick 7 pick 7 pick 7
        // _ [txkmh] *w [t_in] [h_in] [h_out] [t_out]
        pick 11 pick 11 pick 11 pick 11
        call {safe_add}
        // _ [txkmh] *w [t_in] [h_out] [t_out + h_in]
        pick 11 pick 11 pick 11 pick 11
        pick 11 pick 11 pick 11 pick 11
        call {safe_add}
        // _ [txkmh] *w [t_out + h_in] [h_out + t_in]
        {&u128_eq}
        assert error_id {UNBACKED_ERROR}

        pop 5 pop 1
        halt
    );

    let tally = triton_asm!(
        // BEFORE: _ is_outputs *utxos
        // AFTER:  _ [tokens] [holding] num_vaults
        tally:
            push 0 push 0 push 0 push 0
            push {tokens.write_address()} write_mem 4 pop 1
            push 0 push 0 push 0 push 0
            push {holding.write_address()} write_mem 4 pop 1
            push 0
            push {num_vaults.write_address()} write_mem 1 pop 1

            read_mem 1 addi 2
            push 0 swap 1
            // _ is_outputs N 0 *utxos[0]_si
            call tally_loop
            pop 4

            push {tokens.read_address()} read_mem 4 pop 1
            call assert_in_range
            push {holding.read_address()} read_mem 4 pop 1
            call assert_in_range
            push {num_vaults.read_address()} read_mem 1 pop 1
            return

        // INVARIANT: _ is_outputs N i *utxos[i]_si
        tally_loop:
            dup 2 dup 2 eq skiz return

            dup 0 addi 1 call coin_scan
            // _ is_outputs N i *utxos[i]_si markers [utxo_tokens]
            push {tokens.read_address()} read_mem 4 pop 1
            call {safe_add}
            push {tokens.write_address()} write_mem 4 pop 1
            // _ is_outputs N i *utxos[i]_si markers

            dup 0 push 0 eq push 0 eq
            skiz call vault_part
            pop 1

            pick 1 addi 1 place 1
            read_mem 1 addi 2 add
            // _ is_outputs N (i+1) *utxos[i+1]_si
            recurse

        // _ is_outputs N i *utxos[i]_si markers
        vault_part:
            dup 0 push {num_vaults.read_address()} read_mem 1 pop 1 add
            push {num_vaults.write_address()} write_mem 1 pop 1

            dup 4 skiz call check_vault

            dup 1 addi 1 call vaultee_sum
            push {holding.read_address()} read_mem 4 pop 1
            call {safe_add}
            push {holding.write_address()} write_mem 4 pop 1
            return

        // BEFORE: _ [amount]
        // AFTER:  _ [amount]
        assert_in_range:
            {&push_u128(max_plus_one)}
            dup 7 dup 7 dup 7 dup 7
            call {lt}
            assert error_id {OUT_OF_RANGE_ERROR}
            return

        // BEFORE: _ *amount
        // AFTER:  _ [amount]
        read_amount:
            addi 3 read_mem 4 pop 1
            dup 3 split pop 1 push 0 eq assert error_id {INVALID_STATE_ERROR}
            dup 2 split pop 1 push 0 eq assert error_id {INVALID_STATE_ERROR}
            dup 1 split pop 1 push 0 eq assert error_id {INVALID_STATE_ERROR}
            dup 0 split pop 1 push 0 eq assert error_id {INVALID_STATE_ERROR}
            call assert_in_range
            return
    );

    let coin_scan = triton_asm!(
        // BEFORE: _ *utxo
        // AFTER:  _ markers [tokens]
        coin_scan:
            {&field_coins}
            read_mem 1 addi 2
            push 0 swap 1
            push 0 push 0 push 0 push 0 push 0
            // _ M 0 *coins[0]_si 0 [0]
            call coin_scan_loop
            pick 5 pop 1 pick 5 pop 1 pick 5 pop 1
            return

        // INVARIANT: _ M j *coins[j]_si markers [tokens]
        coin_scan_loop:
            dup 7 dup 7 eq skiz return

            dup 5 addi 1 {&field_type_script_hash} {&read_digest}
            {&read_own_digest}
            {&digest_eq}
            skiz call own_coin

            pick 6 addi 1 place 6
            pick 5 read_mem 1 addi 2 add place 5
            recurse

        // _ M j *coins[j]_si markers [tokens]
        own_coin:
            dup 5 addi 1 {&field_state}
            read_mem 1 addi 1
            dup 0 addi 1 read_mem 1 pop 1
            // _ M j *coins[j]_si markers [tokens] L *state s0

            dup 2 push 1 eq dup 1 push {marker} eq mul
            dup 3 push 5 eq dup 2 push {token} eq mul
            // _ M j *coins[j]_si markers [tokens] L *state s0 is_marker is_token
            dup 1 dup 1 add push 1 eq assert error_id {INVALID_STATE_ERROR}

            pick 1 pick 9 add place 8
            // _ M j *coins[j]_si markers' [tokens] L *state s0 is_token
            skiz call add_token
            pop 3
            return

        // _ [tokens] L *state s0
        add_token:
            dup 1 addi 2 call read_amount
            pick 10 pick 10 pick 10 pick 10
            call {safe_add}
            pick 6 pick 6 pick 6
            // _ [tokens'] L *state s0
            return
    );

    let vaultee_sum = triton_asm!(
        // BEFORE: _ *utxo
        // AFTER:  _ [holding]
        vaultee_sum:
            {&field_coins}
            read_mem 1 addi 2
            push 0 swap 1
            push 0 push 0 push 0 push 0
            // _ M 0 *coins[0]_si [0]
            call vaultee_loop
            pick 4 pop 1 pick 4 pop 1 pick 4 pop 1
            return

        // INVARIANT: _ M j *coins[j]_si [holding]
        vaultee_loop:
            dup 6 dup 6 eq skiz return

            dup 4 addi 1 {&field_type_script_hash} {&read_digest}
            {&push_digest(vaultee)}
            {&digest_eq}
            skiz call vaultee_coin

            pick 5 addi 1 place 5
            pick 4 read_mem 1 addi 2 add place 4
            recurse

        // _ M j *coins[j]_si [holding]
        vaultee_coin:
            dup 4 addi 1 {&field_state}
            read_mem 1 addi 1
            // _ M j *coins[j]_si [holding] L *state
            pick 1 push {AMOUNT_LEN} eq assert error_id {INVALID_STATE_ERROR}
            addi 1 call read_amount
            call {safe_add}
            return
    );

    let check_vault = triton_asm!(
        // _ is_outputs N i *utxos[i]_si markers
        check_vault:
            dup 1 addi 1
            // _ is_outputs N i *utxos[i]_si markers *utxo

            dup 0 {&field_lock_script_hash} {&read_digest}
            {&push_digest(vault_lock_script().hash())}
            {&digest_eq}
            assert error_id {NOT_A_VAULT_ERROR}

            {&field_coins}
            read_mem 1 addi 2
            pick 1 push 2 eq assert error_id {NOT_A_VAULT_ERROR}
            // _ is_outputs N i *utxos[i]_si markers *coins[0]_si

            dup 0 addi 1 {&field_type_script_hash} {&read_digest}
            {&push_digest(vaultee)}
            {&digest_eq}
            assert error_id {NOT_A_VAULT_ERROR}
            dup 0 addi 1 {&field_state} read_mem 1 pop 1
            push {AMOUNT_LEN} eq assert error_id {NOT_A_VAULT_ERROR}

            read_mem 1 addi 2 add addi 1
            // _ is_outputs N i *utxos[i]_si markers *coins[1]
            dup 0 {&field_type_script_hash} {&read_digest}
            {&read_own_digest}
            {&digest_eq}
            assert error_id {NOT_A_VAULT_ERROR}
            {&field_state} addi 1 read_mem 2 pop 1
            // _ is_outputs N i *utxos[i]_si markers s0 L
            push 1 eq assert error_id {NOT_A_VAULT_ERROR}
            push {marker} eq assert error_id {NOT_A_VAULT_ERROR}

            dup 2 dup 2 call check_announcement
            return

        // BEFORE: _ i *utxos[i]_si
        // AFTER:  _
        check_announcement:
            divine 1
            push {kernel_announcements.read_address()} read_mem 1 pop 1
            read_mem 1 addi 2
            // _ i *utxos[i]_si k num_announcements *announcements[0]_si
            pick 1 dup 2 lt assert error_id {MISSING_ANNOUNCEMENT_ERROR}
            call skip_elements
            pick 1 pop 1
            addi 1 {&field_message}
            // _ i *utxos[i]_si *message

            dup 0 read_mem 1 pop 1
            dup 2 read_mem 1 pop 1
            addi {1 + 2 * Digest::LEN} eq assert error_id {MISSING_ANNOUNCEMENT_ERROR}
            dup 0 addi 1 read_mem 1 pop 1
            push {VAULT_FLAG} eq assert error_id {MISSING_ANNOUNCEMENT_ERROR}

            dup 0 addi {2 + 2 * Digest::LEN}
            dup 2 read_mem 1 pop 1
            call {hash_varlen}
            // _ i *utxos[i]_si *message [announced_utxo_hash]
            dup 6 addi 1 dup 7 read_mem 1 pop 1
            call {hash_varlen}
            dup 9 dup 9 dup 9 dup 9 dup 9
            {&digest_eq}
            assert error_id {MISSING_ANNOUNCEMENT_ERROR}
            // _ i *utxos[i]_si *message [item]

            push 0 push 0 push 0 push 0 push 0
            dup 10 addi {1 + 2 * Digest::LEN} read_mem {Digest::LEN} pop 1
            hash
            // _ i *utxos[i]_si *message [item] [receiver_digest]
            dup 10 addi {1 + Digest::LEN} read_mem {Digest::LEN} pop 1
            dup 14 dup 14 dup 14 dup 14 dup 14
            call {commit}
            // _ i *utxos[i]_si *message [item] [addition_record]

            push {kernel_outputs.read_address()} read_mem 1 pop 1
            dup 0 read_mem 1 pop 1
            dup 14 lt assert error_id {MISSING_ANNOUNCEMENT_ERROR}
            dup 13 push {Digest::LEN} mul add addi {Digest::LEN}
            read_mem {Digest::LEN} pop 1
            // _ i *utxos[i]_si *message [item] [addition_record] [outputs[i]]
            {&digest_eq}
            assert error_id {MISSING_ANNOUNCEMENT_ERROR}

            pop 5 pop 3
            return

        // BEFORE: _ k *list[0]_si
        // AFTER:  _ 0 *list[k]_si
        skip_elements:
            dup 1 push 0 eq skiz return
            read_mem 1 addi 2 add
            pick 1 addi -1 place 1
            recurse
    );

    [
        main,
        tally,
        coin_scan,
        vaultee_sum,
        check_vault,
        library.all_imports(),
    ]
    .concat()
}

pub(super) fn type_script_and_witness(
    vault: &Vault,
    kernel: &TransactionKernel,
    salted_inputs: &SaltedUtxos,
    salted_outputs: &SaltedUtxos,
) -> TypeScriptAndWitness {
    let memory = VaultWitnessMemory {
        salted_input_utxos: salted_inputs.clone(),
        salted_output_utxos: salted_outputs.clone(),
        outputs: kernel.outputs.clone(),
        announcements: kernel.announcements.clone(),
    };
    let mut ram = HashMap::default();
    encode_to_memory(
        &mut ram,
        FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
        &memory,
    );

    // For every output that carries a vault marker, in order, the index of its
    // announcement, or zero if it has none, in which case the program crashes.
    let announcement_indices: Vec<BFieldElement> = salted_outputs
        .utxos
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            vault
                .states(output)
                .is_ok_and(|states| states.contains(&VaultState::Marker))
        })
        .map(|(i, output)| {
            kernel
                .announcements
                .iter()
                .position(|announcement| {
                    VaultAnnouncement::decode(announcement).is_some_and(|announced| {
                        announced.utxo == *output
                            && kernel.outputs.get(i) == Some(&announced.addition_record())
                    })
                })
                .unwrap_or(0)
        })
        .map(|k| bfe!(k as u64))
        .collect();

    let mast_paths = [
        kernel.mast_path(TransactionKernelField::Outputs),
        kernel.mast_path(TransactionKernelField::Announcements),
    ]
    .concat();

    let nondeterminism = NonDeterminism::new(announcement_indices)
        .with_digests(mast_paths)
        .with_ram(ram);
    TypeScriptAndWitness::new_with_nondeterminism(vault.program(), nondeterminism)
}
