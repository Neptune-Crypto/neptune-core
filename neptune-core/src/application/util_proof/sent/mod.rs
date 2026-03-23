//! The idea is to disclose the info which we want to prove so it could be checked and manipulated by any tool down stream, and to back up / constrain that info with a proof concealing
//! the parts which are not in direct regard of the facts to be proven. The intuition for the constraints used for developing this proof is the following.
//! - output the address lock part
//! - output the ammount(s)
//! - check the UTXO canonical commitment is in the AOCL
//! - output the digest of the AOCL
//! - output the digest of the `sender_randomness` (as reusing it won't allow to put the UTXO again, and its sole role is shifting the AR)
//! - the recipient digest is in the public inputs

#[cfg(test)]
mod spec;
#[cfg(test)]
mod tests;

use std::sync::OnceLock;

use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::prelude::{Digest, Library, TasmStruct};
use tasm_lib::triton_vm::isa::triton_asm;
use tasm_lib::triton_vm::prelude::{BFieldCodec, LabelledInstruction, Program};
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::vm::{NonDeterminism, PublicInput};
use tasm_lib::twenty_first::prelude::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::{field as rustfield, mmr};

use crate::api::export::{NativeCurrencyAmount, Utxo};
use crate::application::util_proof::{ProofOfTransfer, ProofOfTransferWitness};
use crate::protocol::consensus::type_scripts;
use crate::protocol::proof_abstractions::{tasm::program::TritonProgram, SecretWitness};

const ERROR_AOCL_PROOF_VERIFICATION_FAILED: i128 = 1_000_521;

/// add the inputs to the claim
pub fn claim_inputs(
    c: Claim,
    receiver_digest: Digest,
    release_date: crate::api::export::Timestamp,
) -> Claim {
    c.with_input(
        [
            receiver_digest.reversed().values().as_slice(),
            [release_date.0].as_slice(),
        ]
        .concat(),
    )
}
/// add the outputs to the claim
///
/// `aocl_digest` part of `Claim` is not mandatory for proving per se, but a comfort facility so that if the prover have not communicated which AOCL instance (i.e. the block) had he used to make the argument, then a verifier
/// could search the block by this `Digest` instead of trying all canonical blocks
pub fn claim_outputs(
    c: Claim,
    sender_randomness_digest: Digest,
    aocl_digest: Digest,
    lock_postimage: Digest,
    amount: NativeCurrencyAmount,
) -> Claim {
    c.with_output(
        [
            lock_postimage.values().into(),
            sender_randomness_digest.values().to_vec(),
            aocl_digest.values().into(),
            amount.encode(),
        ]
        .concat(),
    )
}

fn library_and_code() -> (Library, Vec<LabelledInstruction>) {
    let u64_stack_size: u32 = tasm_lib::prelude::DataType::U64
        .stack_size()
        .try_into()
        .unwrap();
    // will be needed for timestamps in time locks
    let _u128_stack_size: u32 = tasm_lib::prelude::DataType::U128
        .stack_size()
        .try_into()
        .unwrap();

    let mut library = Library::new();
    let lib_hash_varlen = library.import(Box::new(
        tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen,
    ));
    let lib_ms_commit = library.import(Box::new(tasm_lib::neptune::mutator_set::commit::Commit));
    let lib_mmr_verify = library.import(Box::new(mmr::verify_from_memory::MmrVerifyFromMemory));
    let lib_bagpeaks = library.import(Box::new(mmr::bag_peaks::BagPeaks));
    let release_date = library.kmalloc(1);
    let lib_add_all_amounts_and_check_time_lock = library.import(Box::new(
        type_scripts::amount::add_all_amounts_and_check_time_lock::AddAllAmountsAndCheckTimeLock {
            digest_source: type_scripts::amount::total_amount_main_loop::DigestSource::Hardcode(
                type_scripts::native_currency::NativeCurrency.hash(),
            ),
            release_date,
        },
    ));

    let rustfield_utxo = rustfield!(ProofOfTransferWitness::utxo);

    let main = triton_asm! {
        /* Regarding `addi 0`. It's consistent pattern for `read_mem` to be between two `addi`;
        @skaunov could not find a construction which would fold/capture this pattern, and I feel it's
        too foundational (at least for my perception) to change it when the length is `1`. So for
        the negligible cost (if any) I preserve the pattern even when [first step of it does nothing](https://github.com/Neptune-Crypto/neptune-core/pull/799#discussion_r2787593534). */

        // _
        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        {&rustfield_utxo}
        {&Utxo::get_field("lock_script_hash")}
        addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
        // _ [lock_script_digest]
        write_io 5
        // _

        // the AOCL will end up hashed and outputted to check the used block
        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        // _ *w
        {&ProofOfTransferWitness::get_field("aocl")}
        // _ *aocl

        // the peaks will be needed for the membership verification
        dup 0
        {&MmrAccumulator::get_field("peaks")}
        // _ *aocl *aocl_peaks

        // read `receiver_digest`
        read_io 5
        // _ *aocl *aocl_peaks [receiver_digest]

        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        // _ *aocl *aocl_peaks [receiver_digest] *w
        {&ProofOfTransferWitness::get_field("sender_randomness")}
        addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
        // _ *aocl *aocl_peaks [receiver_digest] [sender_randomness]

        // hash `sender_randomness_digest` and output the digest
        push 0
        push 0
        push 0
        push 0
        push 0
        dup 9
        dup 9
        dup 9
        dup 9
        dup 9
        hash
        write_io 5
        // _ *aocl *aocl_peaks [receiver_digest] [sender_randomness]

        // hash varlen the UTXO from the witness
        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        {&ProofOfTransferWitness::get_field_with_size("utxo")}
        call {lib_hash_varlen}
        hint utxo_hash = stack[0..5]
        // _ *aocl *aocl_peaks [receiver_digest] [sender_randomness] [utxo_hash]

        call {lib_ms_commit}
        // _ *aocl *aocl_peaks [canonical_commitment]

        dup 6 {&MmrAccumulator::get_field("leaf_count")}
        // _ *aocl *aocl_peaks [canonical_commitment] *num_leafs
        addi {u64_stack_size - 1} read_mem {u64_stack_size} pop 1
        // _ *aocl *aocl_peaks [canonical_commitment] [num_leafs]

        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        {&ProofOfTransferWitness::get_field("aocl_leaf_index")}
        addi {u64_stack_size - 1} read_mem {u64_stack_size} pop 1
        // _ *aocl *aocl_peaks [canonical_commitment] [num_leafs] [aocl_leaf_index]

        pick {u64_stack_size * 2 + 5 - 1}
        pick {u64_stack_size * 2 + 5 - 1}
        pick {u64_stack_size * 2 + 5 - 1}
        pick {u64_stack_size * 2 + 5 - 1}
        pick {u64_stack_size * 2 + 5 - 1}
        // _ *aocl *aocl_peaks [num_leafs] [aocl_leaf_index] [canonical_commitment]

        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        {&ProofOfTransferWitness::get_field("aocl_membership_proof")}
        {&MmrMembershipProof::get_field("authentication_path")}
        // _ *aocl *aocl_peaks [num_leafs] [aocl_leaf_index] [canonical_commitment] *auth_path

        call {lib_mmr_verify}
        assert error_id {ERROR_AOCL_PROOF_VERIFICATION_FAILED}
        // _ *aocl

        // output the AOCL digest
        call {lib_bagpeaks}
        write_io 5
        // _

        /* Put `release_date` into the memory for
        `type_scripts::amount::add_all_amounts_and_check_time_lock::AddAllAmountsAndCheckTimeLock`
        to find it. And output the value.  */
        read_io 1
        // _ release_date
        // https://github.com/Neptune-Crypto/neptune-core/blob/5c1c6ef2ca1e282a05c7dc5300e742c92758fbfb/neptune-core/src/protocol/consensus/type_scripts/native_currency.rs#L133C13-L135C18
        push {release_date.write_address()}
        write_mem 1
        pop 1
        // _

        // prepare the stack and call the `BasicSnippet` to get the UTXO amount
        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
        {&rustfield_utxo}
        {&Utxo::get_field("coins")}
        // _ *coins
        addi 0 read_mem 1 addi 1
        addi 1
        // _ SI_coins *coins[0]_si
        push 0 swap 1
        // _ SI_coins 0 *coins[0]_si
        push 0 push 0 push 0 push 0
        // _ SI_coins 0 *coins[0]_si [amount]
        push 0 push 0 push 0 push 0
        // _ SI_coins 0 *coins[0]_si [amount] [timelocked_amount]
        push 0 push 0 push 0 push 0
        // _ SI_coins 0 *coins[0]_si [amount] [timelocked_amount] [utxo_amount]
        push 0
        // _ SI_coins 0 *coins[0]_si [amount] [timelocked_amount] [utxo_amount] utxo_is_timelocked
        call {lib_add_all_amounts_and_check_time_lock}
        // _ num_coins num_coins *eof [amount] [timelocked_amount] [utxo_amount'] utxo_is_timelocked'

        // output the UTXO amount
        pop 1 write_io 4
        // num_coins num_coins *eof [amount] [timelocked_amount]

        // wipe the op stack back
        pop 5
        pop 5
        pop 1
        // [program digest] [0; 11] .

        halt
    };

    let imports = library.all_imports();
    let code = triton_asm!(
        {&main}
        {&imports}
    );
    (library, code)
}

/// returns the digest of `Program` of this module
pub fn hash() -> Digest {
    static DIGEST: OnceLock<Digest> = OnceLock::new();

    *DIGEST.get_or_init(|| Program::new(&library_and_code().1).hash())
}

impl ProofOfTransfer {
    pub fn new(
        c: Claim,
        witness_aocl: MmrAccumulator,
        witness_senderrandomness: Digest,
        witness_aoclleafindex: u64,
        witness_utxo: Utxo,
        witness_membershipproof: MmrMembershipProof,
    ) -> ProofOfTransfer {
        ProofOfTransfer(
            ProofOfTransferWitness {
                aocl: witness_aocl,
                aocl_membership_proof: witness_membershipproof,
                utxo: witness_utxo,
                sender_randomness: witness_senderrandomness,
                aocl_leaf_index: witness_aoclleafindex,
            },
            c,
        )
    }
}
impl SecretWitness for ProofOfTransfer {
    fn standard_input(&self) -> PublicInput {
        PublicInput {
            individual_tokens: self.claim().input,
        }
    }
    fn output(&self) -> Vec<tasm_lib::triton_vm::prelude::BFieldElement> {
        self.claim().output
    }
    fn claim(&self) -> Claim {
        self.1.clone()
    }

    fn program(&self) -> Program {
        TritonProgram::program(self)
    }

    fn nondeterminism(&self) -> NonDeterminism {
        NonDeterminism {
            individual_tokens: vec![],
            digests: vec![],
            ram: {
                let mut m = std::collections::HashMap::default();
                encode_to_memory(
                    &mut m,
                    FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                    &self.0,
                );
                m
            },
        }
    }
}

impl TritonProgram for ProofOfTransfer {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        library_and_code()
    }

    fn hash(&self) -> Digest {
        hash()
    }
}
