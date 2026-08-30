use std::cmp::max;

use itertools::Itertools;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::timestamp::Timestamp;
use num_traits::CheckedAdd;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::library::StaticAllocation;
use tasm_lib::list::higher_order::inner_function::InnerFunction;
use tasm_lib::list::higher_order::inner_function::RawCode;
use tasm_lib::list::higher_order::map::ChainMap;
use tasm_lib::list::higher_order::map::Map;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::verifier::stark_verify::StarkVerify;

use crate::chaintx::authenticate_link_kernel_field::AuthenticateLinkKernelField;
use crate::chaintx::generate_link_proof_claim::GenerateLinkProofClaim;
use crate::chaintx::link_kernel::LinkKernel;
use crate::chaintx::link_kernel::LinkKernelField;
use crate::chaintx::link_proof::link_proof_public_input;
use crate::chaintx::link_proof::link_proof_public_output;
use crate::chaintx::link_proof::no_coinbase_leaf;
use crate::chaintx::link_proof::LinkProof;
use crate::chaintx::link_tx::LinkTx;
use crate::chaintx::link_tx::LinkTxProof;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelField;
use crate::transaction::transaction_kernel::TransactionKernelProxy;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::validity::single_proof::DISCRIMINANT_FOR_WELD;
use crate::transaction::validity::tasm::authenticate_txk_field::AuthenticateTxkField;
use crate::transaction::validity::tasm::claims::generate_single_proof_claim::GenerateSingleProofClaim;
use crate::transaction::validity::tasm::hash_removal_record_index_sets::HashRemovalRecordIndexSets;
use crate::transaction::Transaction;
use crate::transaction::TransactionProof;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

const INPUTS_ARE_NOT_THE_OPERANDS_INPUTS_ERROR: i128 = 1_000_080;
const THRUPUTS_ARE_NOT_A_SUBSET_OF_THE_TRANSACTION_OUTPUTS_ERROR: i128 = 1_000_081;
const OUTPUTS_ARE_NOT_THE_SURVIVORS_PLUS_THE_LINK_OUTPUTS_ERROR: i128 = 1_000_082;
const ANNOUNCEMENTS_ARE_NOT_THE_OPERANDS_ANNOUNCEMENTS_ERROR: i128 = 1_000_083;
const FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR: i128 = 1_000_084;
const FEE_IS_NOT_SUM_OF_OPERAND_FEES_ERROR: i128 = 1_000_085;
const TIMESTAMP_IS_NOT_MAX_OF_OPERAND_TIMESTAMPS_ERROR: i128 = 1_000_086;
const MUTATOR_SET_HASH_MISMATCH_ERROR: i128 = 1_000_087;

/// The witness consumed by [`WeldBranch`].
///
/// Holds both operands:
///  1. a `SingleProof`-backed [`Transaction`]'s kernel and proof, and
///  2. a [`LinkTx`]'s kernel and proof;
///
/// as well as the welded kernel they produce, and the outputs of the
/// transaction that survive cut-through.
///
/// Like [`ChainWitness`](crate::chaintx::chain::ChainWitness) this witness *is*
/// its own memory image: everything the branch reads, it reads from RAM.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
pub struct WeldWitness {
    /// Operand A: the kernel of the `SingleProof`-backed transaction.
    pub(crate) singleproof_kernel: TransactionKernel,

    /// Operand B: the kernel of the link transaction being welded in.
    pub(crate) link_kernel: LinkKernel,

    /// The welded kernel. Its MAST hash is the branch's public input, so it is
    /// not carried as a digest: every field is authenticated against the digest
    /// the dispatcher read off stdin.
    pub(crate) new_kernel: TransactionKernel,

    /// The outputs of `singleproof_kernel` that are *not* cut through, i.e. the
    /// multiset difference `A.outputs - B.thruputs`.
    ///
    /// Prover-supplied, because multiset difference is not a primitive. The two
    /// equations in [`WeldBranch`] pin it from both sides: it is what is left of
    /// A's outputs once B's thruputs are taken out, and it is what the welded
    /// outputs are once B's outputs are taken out.
    pub(crate) surviving_outputs: Vec<AdditionRecord>,

    /// Operand A's kernel MAST hash. See the type-level note.
    pub(crate) transaction_kernel_mast_hash: Digest,

    /// Operand B's link kernel MAST hash. See the type-level note.
    pub(crate) link_kernel_mast_hash: Digest,

    pub(crate) single_proof: Proof,
    pub(crate) link_proof: Proof,
}

impl WeldWitness {
    /// Weld a `SingleProof`-backed transaction and a link transaction into one
    /// `SingleProof`-backed transaction.
    ///
    /// Mirrors the assertions [`WeldBranch`] makes about the *kernels*, so a
    /// witness that could never be proven fails here in milliseconds rather
    /// than after a proof. The operand proofs are the exception: the claims
    /// they answer name `D`, the running `SingleProof` program's digest, which
    /// is not known here. They are checked in
    /// `populate_nd_streams`, which receives it.
    ///
    /// # Panics
    ///
    /// - if either operand is not proof-backed;
    /// - if the transaction carries a coinbase;
    /// - if a thruput of the link transaction is not among the transaction's
    ///   outputs, which is to say the weld would leave a thruput unresolved;
    /// - if the operands name different mutator sets, or their fees do not sum
    ///   to a valid amount.
    pub fn weld(singleproof_tx: Transaction, link_tx: LinkTx, shuffle_seed: [u8; 32]) -> Self {
        let TransactionProof::SingleProof(single_proof) = singleproof_tx.proof else {
            panic!("cannot weld a transaction that is not backed by a single proof");
        };
        let LinkTxProof::Proof(link_proof) = link_tx.proof else {
            panic!("cannot weld a link transaction that is not backed by a link proof");
        };

        let singleproof_kernel = singleproof_tx.kernel;
        let link_kernel = link_tx.kernel;

        let (new_kernel, surviving_outputs) =
            Self::welded_kernel(&singleproof_kernel, &link_kernel, shuffle_seed);

        Self {
            transaction_kernel_mast_hash: singleproof_kernel.mast_hash(),
            link_kernel_mast_hash: link_kernel.mast_hash(),
            singleproof_kernel,
            link_kernel,
            new_kernel,
            surviving_outputs,
            single_proof,
            link_proof,
        }
    }

    /// The kernel the two operands weld into, and the transaction outputs that
    /// survive cut-through.
    ///
    /// Every field is the concatenation of the operands', up to shuffling and
    /// cut-through. The welded kernel has no thruputs to carry: a
    /// [`TransactionKernel`] has no such field, which is what makes an
    /// unresolved thruput unprovable rather than merely rejected.
    fn welded_kernel(
        transaction_kernel: &TransactionKernel,
        link_kernel: &LinkKernel,
        shuffle_seed: [u8; 32],
    ) -> (TransactionKernel, Vec<AdditionRecord>) {
        assert_eq!(
            transaction_kernel.mutator_set_hash, link_kernel.kernel.mutator_set_hash,
            "attempted to weld operands with non-matching mutator set hashes"
        );
        assert!(
            transaction_kernel.coinbase.is_none(),
            "a coinbase transaction cannot be welded"
        );
        assert!(
            link_kernel.kernel.coinbase.is_none() && !link_kernel.kernel.merge_bit,
            "a link transaction is never a coinbase transaction and never carries the merge bit"
        );

        let fee = transaction_kernel
            .fee
            .checked_add(&link_kernel.kernel.fee)
            .expect("welded fee must be a non-negative amount within range");

        // Cut-through, one-sided: a thruput may cancel only against an output of
        // the transaction, never against an output of the link transaction
        // itself.
        //
        // ponytail: quadratic pairing, as in `Chain::chained_kernel`. A weld
        // carries tens of records, not millions.
        let mut thruputs = link_kernel.thruputs.clone();
        let mut surviving_outputs = vec![];
        for output in &transaction_kernel.outputs {
            match thruputs.iter().position(|thruput| thruput == output) {
                Some(i) => {
                    thruputs.swap_remove(i);
                }
                None => surviving_outputs.push(*output),
            }
        }
        assert!(
            thruputs.is_empty(),
            "every thruput must be an output of the transaction being welded in"
        );

        let mut rng: StdRng = SeedableRng::from_seed(shuffle_seed);
        let mut inputs = [
            transaction_kernel.inputs.clone(),
            link_kernel.kernel.inputs.clone(),
        ]
        .concat();
        let mut outputs = [
            surviving_outputs.clone(),
            link_kernel.kernel.outputs.clone(),
        ]
        .concat();
        let mut announcements = [
            transaction_kernel.announcements.clone(),
            link_kernel.kernel.announcements.clone(),
        ]
        .concat();
        inputs.shuffle(&mut rng);
        outputs.shuffle(&mut rng);
        announcements.shuffle(&mut rng);

        let kernel = TransactionKernelProxy {
            inputs,
            outputs,
            announcements,
            fee,
            coinbase: None,
            timestamp: max(transaction_kernel.timestamp, link_kernel.kernel.timestamp),
            mutator_set_hash: transaction_kernel.mutator_set_hash,
            // Carried, not cleared: the merge bit is what makes a kernel a
            // `BlockTransactionKernel`, so a weld into an already-merged
            // transaction stays block-eligible. The link operand's is false by
            // induction over the `LinkProof` branches, so A's is the whole of it.
            merge_bit: transaction_kernel.merge_bit,
        }
        .into_kernel();

        (kernel, surviving_outputs)
    }

    /// MAST hash of the welded kernel -- the public input of the `SingleProof`
    /// claim this witness is proven against.
    pub(crate) fn kernel_mast_hash(&self) -> Digest {
        self.new_kernel.mast_hash()
    }

    /// The claim operand A's single proof is verified against: this very
    /// program, on A's kernel MAST hash.
    ///
    /// `single_proof_digest` is `own_program_digest()` at run time, exactly as
    /// in [`Cast`](crate::chaintx::cast::Cast), which builds the mirror image of
    /// this claim: the branch names no rule set, it names the digest the
    /// dispatcher read.
    fn single_proof_claim(&self, single_proof_digest: Digest) -> Claim {
        Claim::new(single_proof_digest)
            .with_input(self.transaction_kernel_mast_hash.reversed().values())
    }

    /// The claim operand B's link proof is verified against.
    ///
    /// `D` is `own_program_digest()` at run time, exactly as in
    /// [`FixBranch`](super::fix_branch::FixBranch): `Weld` is the second point
    /// where the `LinkProof` family is instantiated at a concrete `SingleProof`.
    fn link_proof_claim(&self, single_proof_digest: Digest) -> Claim {
        let input = link_proof_public_input(self.link_kernel_mast_hash, single_proof_digest);
        Claim::new(LinkProof.hash())
            .with_input(input.individual_tokens)
            .with_output(link_proof_public_output(single_proof_digest))
    }

    pub(crate) fn populate_nd_streams(
        &self,
        nondeterminism: &mut NonDeterminism,
        single_proof_program_hash: Digest,
    ) {
        // The digest stream is consumed in program order: one authentication
        // path per `merkle_verify`, in the order the branch runs them. That is
        // per assertion, and within an assertion in the order its operands are
        // authenticated, which is not the same order throughout -- cut-through
        // takes A's outputs against B's thruputs first and the weld's outputs
        // against B's outputs second, so B is authenticated twice with the weld
        // in between. Reordering an assertion in `code` means reordering this
        // list; nothing checks the correspondence but the branch failing to run.
        //
        // The branch divines nothing, so there are no individual tokens to
        // supply: both operands' kernel MAST hashes are witness fields, and the
        // merge-bit leaf is hashed out of the witness rather than guessed.
        let a = |field| self.singleproof_kernel.mast_path(field);
        let b = |field| self.link_kernel.mast_path(field);
        let w = |field| self.new_kernel.mast_path(field);
        nondeterminism.digests.extend(
            [
                /* the inputs are the operands' inputs */
                a(TransactionKernelField::Inputs),
                b(LinkKernelField::Inputs),
                w(TransactionKernelField::Inputs),
                /* B's thruputs are cut against A's outputs */
                a(TransactionKernelField::Outputs),
                b(LinkKernelField::Thruputs),
                /* and what survives, plus B's outputs, is the weld's */
                w(TransactionKernelField::Outputs),
                b(LinkKernelField::Outputs),
                /* the announcements are the operands' announcements */
                a(TransactionKernelField::Announcements),
                b(LinkKernelField::Announcements),
                w(TransactionKernelField::Announcements),
                /* the fee is the sum */
                a(TransactionKernelField::Fee),
                b(LinkKernelField::Fee),
                w(TransactionKernelField::Fee),
                /* the timestamp is the later */
                a(TransactionKernelField::Timestamp),
                b(LinkKernelField::Timestamp),
                w(TransactionKernelField::Timestamp),
                /* all three kernels name one mutator set */
                a(TransactionKernelField::MutatorSetHash),
                b(LinkKernelField::MutatorSetHash),
                w(TransactionKernelField::MutatorSetHash),
                /* neither A nor the weld is a coinbase transaction */
                a(TransactionKernelField::Coinbase),
                w(TransactionKernelField::Coinbase),
                /* and the merge bit is A's, one leaf in both trees */
                a(TransactionKernelField::MergeBit),
                w(TransactionKernelField::MergeBit),
            ]
            .concat(),
        );

        // Then the recursive verifications, which the branch does last.
        let stark_verify = StarkVerify::new_with_dynamic_layout(Stark::default());

        for (claim, proof) in [
            (
                self.single_proof_claim(single_proof_program_hash),
                &self.single_proof,
            ),
            (
                self.link_proof_claim(single_proof_program_hash),
                &self.link_proof,
            ),
        ] {
            // A mock proof, which is what regtest mode runs on, has no proof
            // stream to extract nondeterminism from, and never reaches a real
            // `StarkVerify` either.
            if proof.is_mock() {
                continue;
            }

            // Any other proof that does not answer its claim is a witness that
            // cannot be proven, and the branch would only discover it inside the
            // recursive verification, an expensive way to learn it. Assert
            // rather than bail: bailing mid-loop would leave the nondeterminism
            // holding the first operand's stream and not the second's.
            assert!(
                triton_vm::verify(Stark::default(), &claim, proof),
                "operand proof must answer its claim"
            );
            stark_verify.update_nondeterminism(nondeterminism, proof, &claim);
        }
    }
}

/// `Weld: Transaction * LinkTx -> Transaction`: fold a link transaction into a
/// `SingleProof`-backed one, resolving every thruput against that transaction's
/// outputs, in a single program.
///
/// What `Fix(Chain(Cast(A), B))` computes in three proofs and four recursive
/// verifications, this computes in one proof and two: A's `SingleProof` against
/// `{ program: own_program_digest(), input: [txkmh_A] }` and B's `LinkProof`
/// against `{ program: LinkProof, input: [lkmh_B, own_program_digest()] }`. One
/// digest, read once by the dispatcher, named in both claims --
/// [`FixBranch`](super::fix_branch::FixBranch)'s cycle break applied twice.
///
/// It is deliberately *not* the decomposition, in both directions:
///
/// - **more permissive**: [`Cast`](crate::chaintx::cast::Cast) refuses a
///   transaction carrying the merge bit, so the three-step route never accepts
///   one. `Weld` does, and the welded kernel's merge bit is A's. The bit must
///   be set in order for the transaction kernel to become a
///   [`BlockTransactionKernel`](crate::block::block_transaction::BlockTransactionKernel).
///   So this path applies cut-through to transactions closer to their promotion
///   to block transaction kernel.
///   
/// - **more restrictive**: [`Chain`](crate::chaintx::chain::Chain) cancels a
///   thruput against its own operand's output as readily as against the
///   other's. `Weld` cuts B's thruputs against A's outputs only. No
///   self-cut-throughs.
///
/// Cut-through needs no witness-supplied cut multiset and no maximality check.
/// Both fall out of the restriction above and of the output type:
///
/// ```text
/// A.outputs     ≡ surviving_outputs ⊎ B.thruputs
/// weld.outputs  ≡ surviving_outputs ⊎ B.outputs
/// ```
///
/// A [`TransactionKernel`] has no thruputs field, so an unresolved thruput is
/// not representable; it is *unprovable*. A thruput of B absent from A's
/// outputs fails the first equation, and that is the entirety of the check that
/// "the thruputs must be empty after cut-through".
///
/// The welded fee is the sum of the operands' fees, and all three are
/// non-negative amounts within range; only the sum is asserted to be in range,
/// because bounding it bounds the operands too, by the argument spelled out
/// where it is asserted.
///
/// The one check neither operand's proof supplies is **no coinbase on A**. The
/// `LinkProof` induction covers B, and a `SingleProof`-backed transaction is
/// entitled to a coinbase; on the decomposition path `Cast` is what refuses
/// one, and `Weld` deletes `Cast` from the path. Without this artificial check,
/// a coinbase-bearing A would weld into a kernel declaring no coinbase while
/// its outputs still carry the block subsidy, and nothing re-runs a type script
/// over the welded kernel.
///
/// B's coinbase and merge-bit leafs are *not* re-checked: they hold on the link
/// kernel by induction over the `LinkProof` branches, exactly as
/// [`Chain`](crate::chaintx::chain::Chain) relies on them.
///
/// This branch exists only from hardfork delta onwards; see
/// [`ConsensusRuleSet::has_chain_branches`].
#[derive(Debug, Copy, Clone)]
pub struct WeldBranch {
    /// Where the `SingleProof` program shared the slot holding `D`, this
    /// program's own digest. Shared with
    /// [`FixBranch`](super::fix_branch::FixBranch): both branches instantiate
    /// the `LinkProof` family at the same digest, and one slot serves both.
    ///
    /// The whole allocation, not one of its ends: `write_mem` fills it upwards
    /// from the low word and `read_mem` empties it downwards from the high one,
    /// so a slot this size has two addresses and every use has to pick the
    /// right one.
    single_proof_digest_alloc: StaticAllocation,
}

impl WeldBranch {
    pub(crate) fn new(single_proof_digest_alloc: StaticAllocation) -> Self {
        Self {
            single_proof_digest_alloc,
        }
    }
}

impl BasicSnippet for WeldBranch {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "single_proof_program_digest".to_string()),
            (DataType::Digest, "txk_digest".to_string()),
            (DataType::VoidPointer, "single_proof_witness".to_string()),
            (DataType::Bfe, "discriminant".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "single_proof_program_digest".to_string()),
            (DataType::Digest, "txk_digest".to_string()),
            (DataType::VoidPointer, "single_proof_witness".to_string()),
            (DataType::Bfe, "minus_1".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_transaction_single_proof_weld_branch".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let audit_preloaded_data =
            library.import(Box::new(VerifyNdSiIntegrity::<WeldWitness>::default()));
        // Delta, not the running program's rule set: this branch exists under
        // no other, and the rule set picks nothing here but the proof version
        // stamped on the claim. `Cast`, which builds the mirror image of this
        // claim, hardcodes it the same way.
        let generate_single_proof_claim = library.import(Box::new(GenerateSingleProofClaim::new(
            ConsensusRuleSet::HardforkDelta,
        )));
        let generate_link_proof_claim = library.import(Box::new(GenerateLinkProofClaim {
            single_proof_digest_address: self.single_proof_digest_alloc.read_address(),
        }));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let multiset_equality = library.import(Box::new(MultisetEqualityDigests));
        let hash_1_removal_record_index_set =
            library.import(Box::new(HashRemovalRecordIndexSets::<1>));
        let hash_2_removal_record_index_sets =
            library.import(Box::new(HashRemovalRecordIndexSets::<2>));
        let overflowing_add_u128 = library.import(Box::new(
            tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd,
        ));
        let lt_u128 = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let lt_u64 = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));
        let compare_u128 = DataType::U128.compare();
        let compare_digests = DataType::Digest.compare();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();

        // Leaf authentication comes in two flavours here, the two operands
        // living in differently shaped trees: A and the weld are
        // `TransactionKernel`s, B is a `LinkKernel`, one leaf and one level
        // taller.
        let mut auth_txk = |f: TransactionKernelField| -> String {
            library.import(Box::new(AuthenticateTxkField(f)))
        };
        let authenticate_txk_inputs = auth_txk(TransactionKernelField::Inputs);
        let authenticate_txk_outputs = auth_txk(TransactionKernelField::Outputs);
        let authenticate_txk_announcements = auth_txk(TransactionKernelField::Announcements);
        let authenticate_txk_fee = auth_txk(TransactionKernelField::Fee);
        let authenticate_txk_timestamp = auth_txk(TransactionKernelField::Timestamp);
        let authenticate_txk_mutator_set_hash = auth_txk(TransactionKernelField::MutatorSetHash);

        let mut auth_lk = |f: LinkKernelField| -> String {
            library.import(Box::new(AuthenticateLinkKernelField(f)))
        };
        let authenticate_lk_inputs = auth_lk(LinkKernelField::Inputs);
        let authenticate_lk_outputs = auth_lk(LinkKernelField::Outputs);
        let authenticate_lk_thruputs = auth_lk(LinkKernelField::Thruputs);
        let authenticate_lk_announcements = auth_lk(LinkKernelField::Announcements);
        let authenticate_lk_fee = auth_lk(LinkKernelField::Fee);
        let authenticate_lk_timestamp = auth_lk(LinkKernelField::Timestamp);
        let authenticate_lk_mutator_set_hash = auth_lk(LinkKernelField::MutatorSetHash);

        // Addition records and announcements are compared as multisets of
        // digests, so both get hashed into digest lists first. The same shape
        // `Chain` and `merge_branch` use, for the same two field types.
        debug_assert!(AdditionRecord::static_length().is_some());
        let hash_addition_record = RawCode::new(
            triton_asm! {
                // BEFORE: _ [addition_record; 5]
                // AFTER:  _ [digest; 5]
                //
                // Computes
                // `Tip5::hash_pair(addition_record, Digest::default())`.
                neptune_transaction_weld_hash_addition_record:
                    push 0 push 0 push 0 push 0 push 0
                    // _ [addition_record; 5] [0; 5]

                    pick 9 pick 9 pick 9 pick 9 pick 9
                    // _ [0; 5] [addition_record; 5]

                    hash
                    // _ [digest; 5]

                    return
            },
            DataType::Digest,
            DataType::Digest,
        );
        let hash_1_list_of_addition_records = library.import(Box::new(Map::new(
            InnerFunction::RawCode(hash_addition_record.clone()),
        )));
        let hash_2_lists_of_addition_records = library.import(Box::new(ChainMap::<2>::new(
            InnerFunction::RawCode(hash_addition_record),
        )));
        let hash_announcement = RawCode::new(
            triton_asm! {
                neptune_transaction_weld_hash_announcement:
                    call {hash_varlen}
                    return
            },
            DataType::Tuple(vec![DataType::VoidPointer, DataType::Bfe]),
            DataType::Digest,
        );
        let hash_1_list_of_announcements = library.import(Box::new(Map::new(
            InnerFunction::RawCode(hash_announcement.clone()),
        )));
        let hash_2_lists_of_announcements = library.import(Box::new(ChainMap::<2>::new(
            InnerFunction::RawCode(hash_announcement),
        )));

        let field_singleproof_kernel = field!(WeldWitness::singleproof_kernel);
        let field_link_kernel = field!(WeldWitness::link_kernel);
        let field_new_kernel = field!(WeldWitness::new_kernel);
        let field_surviving_outputs = field!(WeldWitness::surviving_outputs);
        let field_transaction_kernel_mast_hash = field!(WeldWitness::transaction_kernel_mast_hash);
        let field_link_kernel_mast_hash = field!(WeldWitness::link_kernel_mast_hash);
        let field_single_proof = field!(WeldWitness::single_proof);
        let field_link_proof = field!(WeldWitness::link_proof);

        // A `LinkKernel` composes a `TransactionKernel`, so B's inner fields are
        // reached through one extra hop.
        let field_inner_kernel = field!(LinkKernel::kernel);
        let field_with_size_thruputs = field_with_size!(LinkKernel::thruputs);
        let field_with_size_inputs = field_with_size!(TransactionKernel::inputs);
        let field_with_size_outputs = field_with_size!(TransactionKernel::outputs);
        let field_with_size_announcements = field_with_size!(TransactionKernel::announcements);
        let field_fee = field!(TransactionKernel::fee);
        let field_timestamp = field!(TransactionKernel::timestamp);
        let field_mutator_set_hash = field!(TransactionKernel::mutator_set_hash);
        let field_merge_bit = field!(TransactionKernel::merge_bit);

        let fee_size = NativeCurrencyAmount::static_length().unwrap();
        let timestamp_size = Timestamp::static_length().unwrap();
        let merge_bit_size = bool::static_length().unwrap();

        // Push a compile-time-known digest such that its 0th element ends up on
        // top -- the layout `merkle_verify` expects for a leaf.
        let push_digest = |digest: Digest| {
            digest
                .reversed()
                .values()
                .into_iter()
                .flat_map(|v| triton_asm!(push { v }))
                .collect_vec()
        };

        // The dispatcher's frame is untouched from entry to exit, so with `k`
        // words pushed on top, `*witness` is at `dup k`, the welded kernel's
        // MAST hash (which *is* `txk_digest`) has its deepest word at `dup k+5`,
        // and the own program digest is out of reach past `k == 4`. That last
        // one is why `D` is read from its slot rather than dup'ed: the
        // dispatcher's copy is too deep by the time a claim is being built.
        let read_d = triton_asm!(
            push {self.single_proof_digest_alloc.read_address()}
            read_mem {Digest::LEN}
            pop 1
        );

        // Read the MAST root from the witness and copy it to the top of the
        // stack. Works for any of the two operands. Note that the witness lives
        // at variable stack depth.
        //
        // BEFORE: _ [own_program_digest] disc [txk_digest] *witness .. (k words)
        // AFTER:  _ [own_program_digest] disc [txk_digest] *witness .. (k words) [root; 5]
        let root_of_operand = |field: &[LabelledInstruction]| {
            let field = field.to_vec();
            move |k: usize| {
                triton_asm!(
                    dup {k}
                    {&field}
                    addi {Digest::LEN - 1}
                    read_mem {Digest::LEN}
                    pop 1
                )
            }
        };
        let root_a = root_of_operand(&field_transaction_kernel_mast_hash);
        let root_b = root_of_operand(&field_link_kernel_mast_hash);
        let root_w = |k: usize| {
            let depth = k + Digest::LEN;
            (0..Digest::LEN)
                .flat_map(|_| triton_asm!(dup { depth }))
                .collect_vec()
        };

        // Authenticate one variable-length field of one operand and leave the
        // field's pointer behind, for the multiset comparison that follows.
        //
        // BEFORE: _ [own_program_digest] disc [txk_digest] *witness .. (k words)
        // AFTER:  _ [own_program_digest] disc [txk_digest] *witness .. *field (k+1 words)
        let authenticated_field = |k: usize,
                                   root: &[LabelledInstruction],
                                   accessor: &[LabelledInstruction],
                                   authenticate: &str| {
            triton_asm!(
                // _ .. (k)
                {&root}
                // _ .. [root] (k+5)

                dup {k + Digest::LEN}
                {&accessor}
                // _ .. [root] *field size (k+7)

                dup 1
                place 7
                // _ .. *field [root] *field size

                call {authenticate}
                // _ .. *field (k+1)
            )
        };

        // Same, for a fixed-size field read straight onto the stack.
        //
        // BEFORE: _ .. (k words)
        // AFTER:  _ .. [value; size] (k+size words)
        let authenticated_value = |k: usize,
                                   root: &[LabelledInstruction],
                                   accessor: &[LabelledInstruction],
                                   authenticate: &str,
                                   size: usize| {
            triton_asm!(
                // _ .. (k)
                dup {k}
                {&accessor}
                // _ .. *value (k+1)

                {&root}
                // _ .. *value [root] (k+6)

                dup {Digest::LEN}
                push {size}
                call {authenticate}
                // _ .. *value (k+1)

                addi {size - 1}
                read_mem {size}
                pop 1
                // _ .. [value; size] (k+size)
            )
        };

        // BEFORE: _ *witness
        // AFTER:  _ *field           (`accessor` a `field!`)
        // AFTER:  _ *field size      (`accessor` a `field_with_size!`)
        let a =
            |accessor: &[LabelledInstruction]| triton_asm!({&field_singleproof_kernel} {&accessor});
        let b = |accessor: &[LabelledInstruction]| triton_asm!({&field_link_kernel} {&field_inner_kernel} {&accessor});
        let b_outer =
            |accessor: &[LabelledInstruction]| triton_asm!({&field_link_kernel} {&accessor});
        let w = |accessor: &[LabelledInstruction]| triton_asm!({&field_new_kernel} {&accessor});

        // The welded inputs are exactly the operands' inputs, in any order.
        // Removal records are compared by their absolute index sets: that is
        // what a double spend collides on.
        let assert_inputs_are_the_operands_inputs = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&authenticated_field(0, &root_a(0), &a(&field_with_size_inputs), &authenticate_txk_inputs)}
            {&authenticated_field(1, &root_b(1), &b(&field_with_size_inputs), &authenticate_lk_inputs)}
            {&authenticated_field(2, &root_w(2), &w(&field_with_size_inputs), &authenticate_txk_inputs)}
            // _ [own_program_digest] disc [txk_digest] *witness *a_in *b_in *w_in

            call {hash_1_removal_record_index_set}
            place 2
            call {hash_2_removal_record_index_sets}
            call {multiset_equality}
            assert error_id {INPUTS_ARE_NOT_THE_OPERANDS_INPUTS_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        // Cut-through (1)
        //
        // `surviving` is what is left of A's outputs, after cutting away B's
        // thruputs. So, check that `A.outputs == B.thruputs + surviving`, as
        // multisets.
        let assert_thruputs_are_cut_against_the_transaction_outputs = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&authenticated_field(0, &root_a(0), &a(&field_with_size_outputs), &authenticate_txk_outputs)}
            {&authenticated_field(1, &root_b(1), &b_outer(&field_with_size_thruputs), &authenticate_lk_thruputs)}
            // _ [own_program_digest] disc [txk_digest] *witness *a_out *b_thru

            dup 2
            {&field_surviving_outputs}
            // _ [own_program_digest] disc [txk_digest] *witness *a_out *b_thru *surviving

            call {hash_2_lists_of_addition_records}
            // _ [own_program_digest] disc [txk_digest] *witness *a_out *thru_and_surviving_digests

            place 1
            call {hash_1_list_of_addition_records}
            // _ [own_program_digest] disc [txk_digest] *witness *thru_and_surviving_digests *a_out_digests

            call {multiset_equality}
            assert error_id {THRUPUTS_ARE_NOT_A_SUBSET_OF_THE_TRANSACTION_OUTPUTS_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        // Cut-through (2)
        //
        // `surviving` is what is left of A's outputs, after cutting away B's
        // thruputs. So, check that `W.outputs == B.outputs + surviving`, as
        // multisets.
        let assert_outputs_are_the_survivors_plus_the_link_outputs = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&authenticated_field(0, &root_w(0), &w(&field_with_size_outputs), &authenticate_txk_outputs)}
            {&authenticated_field(1, &root_b(1), &b(&field_with_size_outputs), &authenticate_lk_outputs)}
            // _ [own_program_digest] disc [txk_digest] *witness *w_out *b_out

            dup 2
            {&field_surviving_outputs}
            // _ [own_program_digest] disc [txk_digest] *witness *w_out *b_out *surviving

            call {hash_2_lists_of_addition_records}
            place 1
            call {hash_1_list_of_addition_records}
            call {multiset_equality}
            assert error_id {OUTPUTS_ARE_NOT_THE_SURVIVORS_PLUS_THE_LINK_OUTPUTS_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        let assert_announcements_are_the_operands_announcements = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&authenticated_field(0, &root_a(0), &a(&field_with_size_announcements), &authenticate_txk_announcements)}
            {&authenticated_field(1, &root_b(1), &b(&field_with_size_announcements), &authenticate_lk_announcements)}
            {&authenticated_field(2, &root_w(2), &w(&field_with_size_announcements), &authenticate_txk_announcements)}
            // _ [own_program_digest] disc [txk_digest] *witness *a_pa *b_pa *w_pa

            call {hash_1_list_of_announcements}
            place 2
            call {hash_2_lists_of_announcements}
            call {multiset_equality}
            assert error_id {ANNOUNCEMENTS_ARE_NOT_THE_OPERANDS_ANNOUNCEMENTS_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        // The welded fee is the sum of the operands' fees, and all three of
        // them are non-negative amounts in range. Only the sum is compared
        // against `MAX_NAU`: as long as the addition does not
        // carry, each operand is at most the sum.
        let assert_fee_is_sum_of_operand_fees = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&authenticated_value(0, &root_a(1), &a(&field_fee), &authenticate_txk_fee, fee_size)}
            {&authenticated_value(4, &root_b(5), &b(&field_fee), &authenticate_lk_fee, fee_size)}
            // _ [own_program_digest] disc [txk_digest] *witness [a_fee; 4] [b_fee; 4]

            call {overflowing_add_u128}
            // _ [own_program_digest] disc [txk_digest] *witness [sum; 4] overflow

            push 0 eq
            assert error_id {FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness [sum; 4]

            dup 3 dup 3 dup 3 dup 3
            {&push_max_amount}
            call {lt_u128}
            push 0 eq
            assert error_id {FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness [sum; 4]

            {&authenticated_value(4, &root_w(5), &w(&field_fee), &authenticate_txk_fee, fee_size)}
            // _ [own_program_digest] disc [txk_digest] *witness [sum; 4] [w_fee; 4]

            {&compare_u128}
            assert error_id {FEE_IS_NOT_SUM_OF_OPERAND_FEES_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        // The welded timestamp is the later of the two, computed branchlessly --
        // `Chain`'s handling, which is `merge_branch`'s.
        let assert_timestamp_is_max_of_operand_timestamps = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&authenticated_value(0, &root_a(1), &a(&field_timestamp), &authenticate_txk_timestamp, timestamp_size)}
            {&authenticated_value(1, &root_b(2), &b(&field_timestamp), &authenticate_lk_timestamp, timestamp_size)}
            // _ [own_program_digest] disc [txk_digest] *witness a_timestamp b_timestamp

            dup 1 split
            dup 2 split
            call {lt_u64}
            // _ [own_program_digest] disc [txk_digest] *witness a_timestamp b_timestamp (b < a)

            pick 2 dup 1 mul place 2
            push 0 eq mul
            add
            // _ [own_program_digest] disc [txk_digest] *witness max_timestamp

            {&authenticated_value(1, &root_w(2), &w(&field_timestamp), &authenticate_txk_timestamp, timestamp_size)}
            // _ [own_program_digest] disc [txk_digest] *witness max_timestamp w_timestamp

            eq
            assert error_id {TIMESTAMP_IS_NOT_MAX_OF_OPERAND_TIMESTAMPS_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        // All three kernels must name one and the same mutator set; otherwise
        // the operands' removal records would be pooled across incompatible
        // mutator-set states.
        let assert_all_kernels_agree_on_mutator_set_hash = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&authenticated_value(0, &root_a(1), &a(&field_mutator_set_hash), &authenticate_txk_mutator_set_hash, Digest::LEN)}
            {&authenticated_value(5, &root_b(6), &b(&field_mutator_set_hash), &authenticate_lk_mutator_set_hash, Digest::LEN)}
            // _ [own_program_digest] disc [txk_digest] *witness [a_msh] [b_msh]

            dup 9 dup 9 dup 9 dup 9 dup 9
            {&compare_digests}
            assert error_id {MUTATOR_SET_HASH_MISMATCH_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness [a_msh]

            {&authenticated_value(5, &root_w(6), &w(&field_mutator_set_hash), &authenticate_txk_mutator_set_hash, Digest::LEN)}
            // _ [own_program_digest] disc [txk_digest] *witness [a_msh] [w_msh]

            dup 9 dup 9 dup 9 dup 9 dup 9
            {&compare_digests}
            assert error_id {MUTATOR_SET_HASH_MISMATCH_ERROR}
            // _ [own_program_digest] disc [txk_digest] *witness [a_msh]

            pop {Digest::LEN}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        // Authenticate a constant leaf against one root, which asserts the
        // field's *value* at the same time: only one preimage hashes to it.
        let authenticate_constant_leaf =
            |root: &[LabelledInstruction], leaf_index: usize, height: usize, leaf: Digest| {
                triton_asm!(
                    // _ ..
                    {&root}
                    // _ .. [root]

                    push {height}
                    push {leaf_index as u32}
                    {&push_digest(leaf)}
                    // _ .. [root] height index [leaf]

                    call {merkle_verify}
                    // _ ..
                )
            };

        // Neither operand's proof says A is not a coinbase transaction: the
        // `LinkProof` induction covers B only, and a `SingleProof` is entitled
        // to a coinbase. `Cast` is what refuses one on the decomposition path.
        let assert_neither_kernel_is_a_coinbase_transaction = triton_asm!(
            {&authenticate_constant_leaf(
                &root_a(0),
                TransactionKernelField::Coinbase.discriminant(),
                <TransactionKernel as MastHash>::MAST_HEIGHT,
                no_coinbase_leaf(),
            )}
            {&authenticate_constant_leaf(
                &root_w(0),
                TransactionKernelField::Coinbase.discriminant(),
                <TransactionKernel as MastHash>::MAST_HEIGHT,
                no_coinbase_leaf(),
            )}
        );

        // The welded merge bit is A's. One leaf serves both trees: it is hashed
        // out of A's merge-bit field in the witness, and a leaf that both trees
        // commit to at the merge-bit index is both kernels' merge-bit field,
        // whatever its value. So this is one hash and two `merkle_verify`s, and
        // the value itself is never decoded -- nothing here needs it. B's bit is
        // false by induction over the `LinkProof` branches.
        //
        // The leaf is read from RAM rather than divined so that the witness
        // stays its own memory image and `populate_nd_streams` has nothing to
        // supply for this assertion.
        let assert_merge_bit_is_carried_from_the_transaction = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            dup 0
            {&a(&field_merge_bit)}
            // _ [own_program_digest] disc [txk_digest] *witness *merge_bit

            push {merge_bit_size}
            call {hash_varlen}
            hint merge_bit_leaf = stack[0..5]
            // _ [own_program_digest] disc [txk_digest] *witness [leaf]

            {&root_a(Digest::LEN)}
            push {<TransactionKernel as MastHash>::MAST_HEIGHT}
            push {TransactionKernelField::MergeBit.discriminant() as u32}
            dup 11 dup 11 dup 11 dup 11 dup 11
            call {merkle_verify}
            // _ [own_program_digest] disc [txk_digest] *witness [leaf]

            {&root_w(Digest::LEN)}
            push {<TransactionKernel as MastHash>::MAST_HEIGHT}
            push {TransactionKernelField::MergeBit.discriminant() as u32}
            dup 11 dup 11 dup 11 dup 11 dup 11
            call {merkle_verify}
            // _ [own_program_digest] disc [txk_digest] *witness [leaf]

            pop {Digest::LEN}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        // Recursively verify one operand. Deliberately the *last* thing the
        // branch does, as in `Chain`: everything above is cheap and
        // self-contained, so running it first lets a negative test drive any of
        // those assertions with a proofless witness.
        let verify_singleproof_transaction = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&root_a(0)}
            {&read_d}
            // _ [own_program_digest] disc [txk_digest] *witness [txkmh_a] [own_program_digest]

            call {generate_single_proof_claim}
            // _ [own_program_digest] disc [txk_digest] *witness *claim

            dup 1
            {&field_single_proof}
            // _ [own_program_digest] disc [txk_digest] *witness *claim *proof

            call {stark_verify}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        let verify_link_transaction = triton_asm!(
            // _ [own_program_digest] disc [txk_digest] *witness
            {&root_b(0)}
            {&push_digest(LinkProof.hash())}
            // _ [own_program_digest] disc [txk_digest] *witness [lkmh_b] [link_proof_digest]

            call {generate_link_proof_claim}
            // _ [own_program_digest] disc [txk_digest] *witness *claim

            dup 1
            {&field_link_proof}
            // _ [own_program_digest] disc [txk_digest] *witness *claim *proof

            call {stark_verify}
            // _ [own_program_digest] disc [txk_digest] *witness
        );

        triton_asm!(
            {self.entrypoint()}:
            // _ [own_program_digest] [txk_digest] *single_proof_witness disc

            place 6
            // _ [own_program_digest] disc [txk_digest] *single_proof_witness

            addi 2
            hint witness = stack[0]
            // _ [own_program_digest] disc [txk_digest] *witness

            dup 0 call {audit_preloaded_data} pop 1
            // _ [own_program_digest] disc [txk_digest] *witness

            // Stash the SingleProof program digest, where the `LinkProof` claim
            // generator reads it.
            dup 11 dup 11 dup 11 dup 11 dup 11
            push {self.single_proof_digest_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ [own_program_digest] disc [txk_digest] *witness

            {&assert_inputs_are_the_operands_inputs}
            {&assert_thruputs_are_cut_against_the_transaction_outputs}
            {&assert_outputs_are_the_survivors_plus_the_link_outputs}
            {&assert_announcements_are_the_operands_announcements}
            {&assert_fee_is_sum_of_operand_fees}
            {&assert_timestamp_is_max_of_operand_timestamps}
            {&assert_all_kernels_agree_on_mutator_set_hash}
            {&assert_neither_kernel_is_a_coinbase_transaction}
            {&assert_merge_bit_is_carried_from_the_transaction}
            // _ [own_program_digest] disc [txk_digest] *witness

            {&verify_singleproof_transaction}
            {&verify_link_transaction}
            // _ [own_program_digest] disc [txk_digest] *witness

            pick 6
            // _ [own_program_digest] [txk_digest] *witness disc

            addi {-(DISCRIMINANT_FOR_WELD as isize) - 1}
            // _ [own_program_digest] [txk_digest] *witness -1

            return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use tasm_lib::prelude::Tip5;

    use super::*;
    use crate::chaintx::test_helpers::deterministic_chainable_link_primitive_witnesses;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::TritonError;
    use crate::transaction::validity::single_proof::SingleProof;
    use crate::transaction::validity::single_proof::SingleProofWitness;

    /// The rule set whose `SingleProof` program has this branch. `Weld` runs
    /// under no other.
    const CONSENSUS_RULE_SET: ConsensusRuleSet = ConsensusRuleSet::HardforkDelta;

    /// The branch runs, on a well-formed witness, all the way to the recursion.
    ///
    /// Mock proofs stand in for the operands', so the two `stark_verify`s at the
    /// end cannot pass, and are not meant to. What this pins is everything
    /// before them: every field authentication, both multiset comparisons, and
    /// the fee, timestamp, mutator-set, coinbase and merge-bit assertions -- and
    /// above all that [`WeldWitness::populate_nd_streams`] hands over the
    /// authentication paths in the order the `merkle_verify`s consume them. A
    /// path out of place fails one of those instead, earlier and with a
    /// different message, which is what the assertion below distinguishes.
    ///
    /// Costs no proving: the operands are mock-backed, and the branch reaches
    /// the recursion only after everything else has held.
    #[test]
    fn weld_runs_to_the_recursion_on_a_well_formed_witness() {
        let (predecessor, successor) = deterministic_chainable_link_primitive_witnesses(2, 1);

        // A is the predecessor's transaction kernel -- it carries no thruputs --
        // and B is the successor, whose one thruput is an output of A.
        let transaction = Transaction {
            kernel: predecessor.kernel.kernel.clone(),
            proof: TransactionProof::SingleProof(Proof::valid_mock()),
        };
        let link_tx = LinkTx {
            kernel: successor.kernel.clone(),
            proof: LinkTxProof::Proof(Proof::valid_mock()),
        };

        let witness =
            SingleProofWitness::from_weld(WeldWitness::weld(transaction, link_tx, [0u8; 32]));
        let single_proof = SingleProof::new(CONSENSUS_RULE_SET);

        let Err(TritonError::TritonVMPanic(vm_state, _)) = single_proof.run_tasm(
            &witness.standard_input(),
            witness.nondeterminism(CONSENSUS_RULE_SET),
        ) else {
            panic!("mock operand proofs cannot pass the recursive verification");
        };
        assert!(
            vm_state.contains("stark_verify"),
            "`Weld` must reach the recursion, failing there and nowhere earlier:\n{vm_state}"
        );
    }

    impl WeldWitness {
        /// The `Weld` branch of the `SingleProof` rust shadow, called by
        /// [`SingleProof::source`](crate::transaction::validity::single_proof::SingleProof)
        /// once it has read the own program digest and `txk_digest` -- mirroring
        /// the tasm, where the dispatcher does exactly that before `call`ing
        /// this branch.
        pub fn branch_source(&self, single_proof_program_digest: Digest, txk_digest: Digest) {
            let a = &self.singleproof_kernel;
            let b = &self.link_kernel;
            let w = &self.new_kernel;
            let a_root = self.transaction_kernel_mast_hash;
            let b_root = self.link_kernel_mast_hash;

            let txk_height = <TransactionKernel as MastHash>::MAST_HEIGHT as u32;
            let lk_height = <LinkKernel as MastHash>::MAST_HEIGHT as u32;
            let auth_txk = |root: Digest, field: TransactionKernelField, leaf: Digest| {
                tasm::tasmlib_hashing_merkle_verify(
                    root,
                    field.discriminant() as u32,
                    leaf,
                    txk_height,
                );
            };
            let auth_lk = |field: LinkKernelField, leaf: Digest| {
                tasm::tasmlib_hashing_merkle_verify(
                    b_root,
                    field.discriminant() as u32,
                    leaf,
                    lk_height,
                );
            };

            /* inputs: the concatenation, in any order, compared by index set --
            that is what a double spend collides on */
            auth_txk(
                a_root,
                TransactionKernelField::Inputs,
                Tip5::hash(&a.inputs),
            );
            auth_lk(LinkKernelField::Inputs, Tip5::hash(&b.kernel.inputs));
            auth_txk(
                txk_digest,
                TransactionKernelField::Inputs,
                Tip5::hash(&w.inputs),
            );
            let index_sets = |kernel: &TransactionKernel| {
                kernel
                    .inputs
                    .iter()
                    .map(|rr| Tip5::hash(&rr.absolute_indices.to_vec()))
                    .collect_vec()
            };
            assert_eq!(
                [index_sets(a), index_sets(&b.kernel)]
                    .concat()
                    .into_iter()
                    .sorted()
                    .collect_vec(),
                index_sets(w).into_iter().sorted().collect_vec(),
            );

            /* cut-through */
            let hashed = |records: &[AdditionRecord]| records.iter().map(Tip5::hash).collect_vec();
            let sorted = |digests: Vec<Digest>| digests.into_iter().sorted().collect_vec();
            let surviving = hashed(&self.surviving_outputs);

            auth_txk(
                a_root,
                TransactionKernelField::Outputs,
                Tip5::hash(&a.outputs),
            );
            auth_lk(LinkKernelField::Thruputs, Tip5::hash(&b.thruputs));
            assert_eq!(
                sorted(hashed(&a.outputs)),
                sorted([hashed(&b.thruputs), surviving.clone()].concat()),
            );

            auth_txk(
                txk_digest,
                TransactionKernelField::Outputs,
                Tip5::hash(&w.outputs),
            );
            auth_lk(LinkKernelField::Outputs, Tip5::hash(&b.kernel.outputs));
            assert_eq!(
                sorted(hashed(&w.outputs)),
                sorted([hashed(&b.kernel.outputs), surviving].concat()),
            );

            /* announcements: the concatenation, in any order */
            auth_txk(
                a_root,
                TransactionKernelField::Announcements,
                Tip5::hash(&a.announcements),
            );
            auth_lk(
                LinkKernelField::Announcements,
                Tip5::hash(&b.kernel.announcements),
            );
            auth_txk(
                txk_digest,
                TransactionKernelField::Announcements,
                Tip5::hash(&w.announcements),
            );
            let announcement_digests = |kernel: &TransactionKernel| {
                kernel
                    .announcements
                    .iter()
                    .map(|pa| Tip5::hash_varlen(&pa.encode()))
                    .collect_vec()
            };
            assert_eq!(
                sorted([announcement_digests(a), announcement_digests(&b.kernel)].concat()),
                sorted(announcement_digests(w)),
            );

            /* fee: the sum, which being in `[0, MAX_NAU]` puts both operands
            there too -- neither is bounded on its own */
            auth_txk(a_root, TransactionKernelField::Fee, Tip5::hash(&a.fee));
            auth_lk(LinkKernelField::Fee, Tip5::hash(&b.kernel.fee));
            let raw = |amount: NativeCurrencyAmount| amount.to_nau() as u128;
            let (sum, carry) = raw(a.fee).overflowing_add(raw(b.kernel.fee));
            assert!(!carry);
            assert!(sum <= NativeCurrencyAmount::MAX_NAU as u128);
            auth_txk(txk_digest, TransactionKernelField::Fee, Tip5::hash(&w.fee));
            assert_eq!(sum, raw(w.fee));

            /* timestamp: the later of the two */
            auth_txk(
                a_root,
                TransactionKernelField::Timestamp,
                Tip5::hash(&a.timestamp),
            );
            auth_lk(LinkKernelField::Timestamp, Tip5::hash(&b.kernel.timestamp));
            auth_txk(
                txk_digest,
                TransactionKernelField::Timestamp,
                Tip5::hash(&w.timestamp),
            );
            assert_eq!(max(a.timestamp, b.kernel.timestamp), w.timestamp);

            /* one mutator set across all three */
            auth_txk(
                a_root,
                TransactionKernelField::MutatorSetHash,
                Tip5::hash(&a.mutator_set_hash),
            );
            auth_lk(
                LinkKernelField::MutatorSetHash,
                Tip5::hash(&b.kernel.mutator_set_hash),
            );
            auth_txk(
                txk_digest,
                TransactionKernelField::MutatorSetHash,
                Tip5::hash(&w.mutator_set_hash),
            );
            assert_eq!(a.mutator_set_hash, b.kernel.mutator_set_hash);
            assert_eq!(a.mutator_set_hash, w.mutator_set_hash);

            /* no coinbase on the transaction, nor on the weld. B's is false by
            induction over the `LinkProof` branches. */
            auth_txk(a_root, TransactionKernelField::Coinbase, no_coinbase_leaf());
            auth_txk(
                txk_digest,
                TransactionKernelField::Coinbase,
                no_coinbase_leaf(),
            );

            /* the merge bit is carried from the transaction, whatever it is: one
            leaf, committed to by both trees */
            let merge_bit_leaf = Tip5::hash(&a.merge_bit);
            auth_txk(a_root, TransactionKernelField::MergeBit, merge_bit_leaf);
            auth_txk(txk_digest, TransactionKernelField::MergeBit, merge_bit_leaf);

            /* recursively verify both operands, each against a claim naming the
            digest the dispatcher read: this very program */
            let single_proof_claim =
                Claim::new(single_proof_program_digest).with_input(a_root.reversed().values());
            tasm::verify_stark(Stark::default(), &single_proof_claim, &self.single_proof);

            let input = link_proof_public_input(b_root, single_proof_program_digest);
            let link_proof_claim = Claim::new(LinkProof.hash())
                .with_input(input.individual_tokens)
                .with_output(link_proof_public_output(single_proof_program_digest));
            tasm::verify_stark(Stark::default(), &link_proof_claim, &self.link_proof);
        }
    }
}
