use std::cmp::max;
use std::collections::HashMap;

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
use tasm_lib::list::contains::Contains;
use tasm_lib::list::higher_order::all::All;
use tasm_lib::list::higher_order::inner_function::InnerFunction;
use tasm_lib::list::higher_order::inner_function::RawCode;
use tasm_lib::list::higher_order::map::ChainMap;
use tasm_lib::list::higher_order::map::Map;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::authenticate_link_kernel_field::AuthenticateLinkKernelField;
use super::generate_link_proof_claim::GenerateLinkProofClaim;
use super::link_kernel::LinkKernel;
use super::link_kernel::LinkKernelField;
use super::link_proof::link_proof_public_input;
use super::link_proof::merge_bit_false_leaf;
use super::link_proof::no_coinbase_leaf;
use super::link_proof::LinkProof;
use super::link_proof_witness::LinkProofWitnessMemory;
use super::link_proof_witness::DISCRIMINANT_FOR_CHAIN;
use super::link_tx::LinkTx;
use super::link_tx::LinkTxProof;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::transaction_kernel::TransactionKernelProxy;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::validity::tasm::hash_removal_record_index_sets::HashRemovalRecordIndexSets;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

// 1_000_540 and 1_000_541 were the per-operand fee bounds; the two asserts on
// the sum imply them. Not reused: error IDs are how a failed proof is diagnosed
// in the field, and a recycled one reads as the old check.
const NEW_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR: i128 = 1_000_542;
const NEW_FEE_IS_NOT_SUM_OF_OPERAND_FEES_ERROR: i128 = 1_000_543;
const INPUTS_ARE_NOT_THE_OPERANDS_INPUTS_ERROR: i128 = 1_000_544;
const OUTPUTS_ARE_NOT_CUT_THROUGH_ERROR: i128 = 1_000_545;
const THRUPUTS_ARE_NOT_CUT_THROUGH_ERROR: i128 = 1_000_546;
const CUT_THROUGH_IS_NOT_MAXIMAL_ERROR: i128 = 1_000_547;
const ANNOUNCEMENTS_ARE_NOT_THE_OPERANDS_ANNOUNCEMENTS_ERROR: i128 = 1_000_548;
const TIMESTAMP_IS_NOT_MAX_OF_OPERAND_TIMESTAMPS_ERROR: i128 = 1_000_549;
const MUTATOR_SET_HASH_MISMATCH_ERROR: i128 = 1_000_550;

/// The witness consumed by [`Chain`].
///
/// Consists of the two operand [`LinkTx`]es (kernels plus link proofs), the
/// chained kernel they produce, and the addition records cut through along the
/// way.
///
/// Transaction-chaining analog of
/// [`MergeWitness`](crate::transaction::validity::tasm::single_proof::merge_branch::MergeWitness),
/// and laid out the same way: the witness *is* its own memory image (everything
/// it carries is read from RAM), so -- unlike
/// [`ForgeWitness`](super::forge::ForgeWitness) -- it needs no separate
/// projection.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
pub struct ChainWitness {
    pub(super) left_kernel: LinkKernel,
    pub(super) right_kernel: LinkKernel,
    pub(super) new_kernel: LinkKernel,

    /// The addition records cancelled by cut-through: each is simultaneously an
    /// output of one operand and a thruput of one operand, and is removed from
    /// *both* sides together. That pairing is what conserves value -- an
    /// addition record dropped from the outputs without also being dropped from
    /// the thruputs (or vice versa) would create or destroy funds -- and
    /// matching on the addition record itself means the pairing is on the
    /// UTXO's canonical commitment.
    ///
    /// Cut-through must be maximal: no output of the chained kernel may equal
    /// one of its thruputs. [`Self::chained_kernel`] cancels everything it can,
    /// and the branch asserts the result, which the two cut-through equations
    /// on their own would not -- they are satisfied by any sub-multiset of the
    /// intersection, a short one included.
    pub(super) cut_through: Vec<AdditionRecord>,

    pub(super) left_proof: Proof,
    pub(super) right_proof: Proof,

    /// The `SingleProof` program digest `D` this chain is claimed under, and
    /// which both operand proofs must have been made under too.
    ///
    /// Rust-side only: it is here to build the public input and the two operand
    /// claims. The tasm branch reads `D` off the public input instead.
    pub(super) single_proof_digest: Digest,
}

impl ChainWitness {
    /// Chain two link transactions, cutting through every thruput of the one
    /// that is an output of the other -- every one, since the branch rejects a
    /// cut-through that is not maximal.
    ///
    /// Both arguments must be proof-backed and valid; the `Chain` branch is
    /// what actually establishes that, and this constructor assumes it. Takes
    /// randomness for shuffling the concatenations, mirroring
    /// [`MergeWitness::from_transactions`](crate::transaction::validity::tasm::single_proof::merge_branch::MergeWitness::from_transactions).
    ///
    /// Both operands must already be proven under `single_proof_digest`: it goes
    /// into their claims verbatim, so an operand proven under any other one
    /// simply fails to verify. A `LinkTx` does not carry the digest it was proven
    /// under, so there is nothing to check here.
    pub fn chain(
        left: LinkTx,
        right: LinkTx,
        single_proof_digest: Digest,
        shuffle_seed: [u8; 32],
    ) -> Self {
        let LinkTxProof::Proof(left_proof) = left.proof else {
            panic!("cannot chain a link transaction that is not backed by a link proof");
        };
        let LinkTxProof::Proof(right_proof) = right.proof else {
            panic!("cannot chain a link transaction that is not backed by a link proof");
        };

        let (new_kernel, cut_through) =
            Self::chained_kernel(&left.kernel, &right.kernel, shuffle_seed);

        Self {
            left_kernel: left.kernel,
            right_kernel: right.kernel,
            new_kernel,
            cut_through,
            left_proof,
            right_proof,
            single_proof_digest,
        }
    }

    /// The [`LinkKernel`] the chained transaction carries.
    ///
    /// Mirrors [`CastWitness::link_kernel`](crate::chaintx::cast::CastWitness::link_kernel):
    /// the caller that proved this witness needs the kernel to pair with the
    /// proof into a [`LinkTx`].
    pub fn link_kernel(&self) -> LinkKernel {
        self.new_kernel.clone()
    }

    /// The [`LinkKernel`] two operands chain into, and the addition records cut
    /// through in the process.
    ///
    /// Every field is the concatenation of the operands' -- shuffled, so the
    /// chained transaction does not leak which operand contributed what --
    /// except that the outputs and the thruputs each lose the cut-through set.
    ///
    /// Cut-through is the *full* multiset intersection of the concatenated
    /// outputs with the concatenated thruputs: a thruput is an unconfirmed
    /// input, so pairing it with the output it spends resolves both, and
    /// maximality demands every such pair be taken. Note that this treats the
    /// two operands symmetrically, and even cancels an operand's thruput against
    /// its own output; that pairing resolves the thruput like any other, so it
    /// is taken like any other.
    fn chained_kernel(
        left: &LinkKernel,
        right: &LinkKernel,
        shuffle_seed: [u8; 32],
    ) -> (LinkKernel, Vec<AdditionRecord>) {
        assert_eq!(
            left.kernel.mutator_set_hash, right.kernel.mutator_set_hash,
            "attempted to chain link kernels with non-matching mutator set hashes"
        );
        assert!(
            left.kernel.coinbase.is_none() && right.kernel.coinbase.is_none(),
            "a link transaction is never a coinbase transaction"
        );
        assert!(
            !left.kernel.merge_bit && !right.kernel.merge_bit,
            "a link transaction never carries the merge bit"
        );

        let fee = left
            .kernel
            .fee
            .checked_add(&right.kernel.fee)
            .expect("chained fee must be a non-negative amount within range");

        let mut rng: StdRng = SeedableRng::from_seed(shuffle_seed);

        // ponytail: quadratic pairing. A chain carries tens of records, not
        // millions; swap in a commitment->count map if that ever changes.
        let mut thruputs = [left.thruputs.clone(), right.thruputs.clone()].concat();
        let mut cut_through = vec![];
        let mut outputs = vec![];
        for output in [left.kernel.outputs.clone(), right.kernel.outputs.clone()].concat() {
            match thruputs.iter().position(|thruput| *thruput == output) {
                Some(i) => {
                    thruputs.swap_remove(i);
                    cut_through.push(output);
                }
                None => outputs.push(output),
            }
        }

        let mut inputs = [left.kernel.inputs.clone(), right.kernel.inputs.clone()].concat();
        let mut announcements = [
            left.kernel.announcements.clone(),
            right.kernel.announcements.clone(),
        ]
        .concat();
        inputs.shuffle(&mut rng);
        outputs.shuffle(&mut rng);
        announcements.shuffle(&mut rng);
        thruputs.shuffle(&mut rng);

        let kernel = TransactionKernelProxy {
            inputs,
            outputs,
            announcements,
            fee,
            coinbase: None,
            timestamp: max(left.kernel.timestamp, right.kernel.timestamp),
            mutator_set_hash: left.kernel.mutator_set_hash,
            merge_bit: false,
        }
        .into_kernel();

        (LinkKernel { kernel, thruputs }, cut_through)
    }

    /// MAST hash of the chained [`LinkKernel`]: the public input of the
    /// `LinkProof` claim this witness is proven against.
    pub(super) fn kernel_mast_hash(&self) -> Digest {
        self.new_kernel.mast_hash()
    }

    /// The claim an operand's link proof is verified against: this very
    /// program, on the operand's kernel MAST hash, under the same `D`.
    fn operand_claim(&self, kernel: &LinkKernel) -> Claim {
        let input = link_proof_public_input(kernel.mast_hash(), self.single_proof_digest);
        Claim::new(LinkProof.hash()).with_input(input.individual_tokens)
    }
}

impl SecretWitness for ChainWitness {
    fn standard_input(&self) -> PublicInput {
        link_proof_public_input(self.kernel_mast_hash(), self.single_proof_digest)
    }

    fn output(&self) -> Vec<BFieldElement> {
        std::vec![]
    }

    fn program(&self) -> Program {
        LinkProof.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // `Chain` is a branch of `LinkProof`, so the memory image is that of
        // the enum variant's associated data: field size, then the payload.
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &LinkProofWitnessMemory::Chain(Box::new(self.clone())),
        );

        // The operands' kernel MAST hashes are divined -- each is bound to its
        // operand by the recursive proof verification, and to the fields read
        // out of the witness by the authentication paths below.
        let individual_tokens = [
            self.left_kernel.mast_hash().reversed().values().to_vec(),
            self.right_kernel.mast_hash().reversed().values().to_vec(),
        ]
        .concat();

        // The digest stream is consumed in program order: first the
        // authentication paths, in the order of the `merkle_verify` calls -- per
        // field, left operand then right operand then the chained kernel, and
        // finally the chained kernel's two constant leafs.
        let path = |kernel: &LinkKernel, field: LinkKernelField| kernel.mast_path(field);
        let per_kernel = |field: LinkKernelField| {
            [
                path(&self.left_kernel, field),
                path(&self.right_kernel, field),
                path(&self.new_kernel, field),
            ]
            .concat()
        };
        let mut nondeterminism = NonDeterminism::new(individual_tokens).with_ram(memory);
        nondeterminism.digests.extend(
            [
                per_kernel(LinkKernelField::Inputs),
                per_kernel(LinkKernelField::Outputs),
                per_kernel(LinkKernelField::Thruputs),
                per_kernel(LinkKernelField::Announcements),
                per_kernel(LinkKernelField::Fee),
                per_kernel(LinkKernelField::Timestamp),
                per_kernel(LinkKernelField::MutatorSetHash),
                path(&self.new_kernel, LinkKernelField::Coinbase),
                path(&self.new_kernel, LinkKernelField::MergeBit),
            ]
            .concat(),
        );

        // Then the recursive link-proof verifications, which the branch does
        // last.
        let stark_verify = StarkVerify::new_with_dynamic_layout(Stark::default());
        for (kernel, proof) in [
            (&self.left_kernel, &self.left_proof),
            (&self.right_kernel, &self.right_proof),
        ] {
            // A mock proof has no proof stream to extract nondeterminism from.
            // It never reaches a real `StarkVerify` either: on a mock-proof
            // network nothing runs the program, and in the negative tests some
            // earlier assertion fires first -- the recursion is this branch's
            // last act.
            if proof.is_mock() {
                continue;
            }
            stark_verify.update_nondeterminism(
                &mut nondeterminism,
                proof,
                &self.operand_claim(kernel),
            );
        }

        nondeterminism
    }
}

/// `Chain: LinkTx * LinkTx -> LinkTx`: chain two link transactions into one,
/// cutting through the thruputs that the operands' outputs resolve.
///
/// `Chain` recursively verifies both operands' link proofs -- against claims
/// that name `LinkProof` *itself*, taken from the dispatcher's copy of the own
/// program digest -- and then establishes that the chained kernel is the
/// operands' kernels combined:
///
/// - inputs and announcements are the concatenations, in any order;
/// - outputs and thruputs are the concatenations minus the same cut-through
///   multiset, removed from both sides together, so cut-through neither creates
///   nor destroys value; and that cut-through is maximal -- the chained outputs
///   and the chained thruputs are disjoint;
/// - the fee is the sum, both operand fees being non-negative and in range;
/// - the timestamp is the larger of the two;
/// - all three kernels share one mutator-set hash;
/// - the chained kernel carries no coinbase and no merge bit.
///
/// The operands' coinbase and merge-bit leafs are deliberately *not* re-checked:
/// every branch producing a `LinkProof` asserts both on the kernel it produces,
/// so an operand that verifies has them by induction. Any branch added later
/// owes the same assertion.
#[derive(Debug, Copy, Clone)]
pub struct Chain {
    /// Where the dispatcher stashed the `SingleProof` program digest `D` it read
    /// off the public input. `Chain` copies it verbatim into both operand
    /// claims; see [`LinkProof`].
    pub(super) single_proof_digest_address: BFieldElement,
}

impl BasicSnippet for Chain {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "link_kernel_mast_hash".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "discriminant".to_string()),
        ]
    }

    /// The digest slot is the dispatcher's scratch space, not a return value;
    /// this branch leaves the chained kernel's MAST hash there. See `LinkProof`.
    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "dispatcher_scratch".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "minus_1".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_chaintx_link_proof_chain_branch".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let audit_preloaded_data =
            library.import(Box::new(VerifyNdSiIntegrity::<ChainWitness>::default()));
        let generate_link_proof_claim = library.import(Box::new(GenerateLinkProofClaim {
            single_proof_digest_address: self.single_proof_digest_address,
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

        let authenticate_inputs = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Inputs,
        )));
        let authenticate_outputs = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Outputs,
        )));
        let authenticate_thruputs = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Thruputs,
        )));
        let authenticate_announcements = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Announcements,
        )));
        let authenticate_fee =
            library.import(Box::new(AuthenticateLinkKernelField(LinkKernelField::Fee)));
        let authenticate_timestamp = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Timestamp,
        )));
        let authenticate_mutator_set_hash = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::MutatorSetHash,
        )));

        // Addition records and announcements are compared as multisets of
        // digests, so both get hashed into digest lists first. Copied from
        // `merge_branch`, which compares the same two field types the same way.
        debug_assert!(AdditionRecord::static_length().is_some());
        let hash_addition_record = RawCode::new(
            triton_asm! {
                neptune_consensus_chaintx_chain_hash_addition_record:
                    push 0 push 0 push 0 push 0 push 0
                    pick 9 pick 9 pick 9 pick 9 pick 9
                    hash
                    return
            },
            DataType::Digest,
            DataType::Digest,
        );
        let hash_2_lists_of_addition_records = library.import(Box::new(ChainMap::<2>::new(
            InnerFunction::RawCode(hash_addition_record),
        )));
        let hash_announcement = RawCode::new(
            triton_asm! {
                neptune_consensus_chaintx_chain_hash_announcement:
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

        // Maximality is a disjointness check, and disjointness does not reduce
        // to a multiset equation, so it gets its own quadratic scan: for each
        // chained thruput, is it among the chained outputs? An `AdditionRecord`
        // is a `Digest` in a one-field struct, so it is its own commitment and
        // compares as one -- no hashing pass first, unlike the multiset
        // comparisons above, which need digests because that is what
        // `MultisetEqualityDigests` eats.
        //
        // The inner function takes only its element, so the list being scanned
        // reaches it through static memory.
        let contains_addition_record = library.import(Box::new(Contains::new(DataType::Digest)));
        let chained_outputs_alloc = library.kmalloc(1);
        let thruput_is_not_a_chained_output = RawCode::new(
            triton_asm! {
                neptune_consensus_chaintx_chain_thruput_is_not_a_chained_output:
                    // _ [thruput]
                    push {chained_outputs_alloc.read_address()}
                    read_mem 1
                    pop 1
                    // _ [thruput] *n_out

                    place 5
                    // _ *n_out [thruput]

                    call {contains_addition_record}
                    // _ (thruput in n_out)

                    push 0
                    eq
                    // _ (thruput not in n_out)

                    return
            },
            DataType::Digest,
            DataType::Bool,
        );
        let no_thruput_is_a_chained_output = library.import(Box::new(All::new(
            InnerFunction::RawCode(thruput_is_not_a_chained_output),
        )));

        let overflowing_add_u128 = library.import(Box::new(
            tasm_lib::arithmetic::u128::overflowing_add::OverflowingAdd,
        ));
        let lt_u128 = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let lt_u64 = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));
        let compare_u128 = DataType::U128.compare();
        let compare_digests = DataType::Digest.compare();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();

        let digest_len = u32::try_from(Digest::LEN).unwrap();
        let left_lkmh_alloc = library.kmalloc(digest_len);
        let right_lkmh_alloc = library.kmalloc(digest_len);
        let new_lkmh_alloc = library.kmalloc(digest_len);
        let left_lkmh = left_lkmh_alloc.read_address();
        let right_lkmh = right_lkmh_alloc.read_address();
        let new_lkmh = new_lkmh_alloc.read_address();

        let field_left_kernel = field!(ChainWitness::left_kernel);
        let field_right_kernel = field!(ChainWitness::right_kernel);
        let field_new_kernel = field!(ChainWitness::new_kernel);
        let field_cut_through = field!(ChainWitness::cut_through);
        let field_left_proof = field!(ChainWitness::left_proof);
        let field_right_proof = field!(ChainWitness::right_proof);

        // A `LinkKernel` composes a legacy `TransactionKernel`, so every legacy
        // field is reached through this one extra hop.
        let field_inner_kernel = field!(LinkKernel::kernel);
        let field_thruputs = field!(LinkKernel::thruputs);
        let field_with_size_thruputs = field_with_size!(LinkKernel::thruputs);
        let field_with_size_inputs = field_with_size!(TransactionKernel::inputs);
        let field_outputs = field!(TransactionKernel::outputs);
        let field_with_size_outputs = field_with_size!(TransactionKernel::outputs);
        let field_with_size_announcements = field_with_size!(TransactionKernel::announcements);
        let field_fee = field!(TransactionKernel::fee);
        let field_timestamp = field!(TransactionKernel::timestamp);
        let field_mutator_set_hash = field!(TransactionKernel::mutator_set_hash);

        let fee_size = NativeCurrencyAmount::static_length().unwrap();
        let timestamp_size = Timestamp::static_length().unwrap();

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

        // Authenticate the same variable-length field of all three kernels,
        // leaving the three field pointers behind for the multiset comparison
        // that follows. `accessor` turns a `*link_kernel` into `*field size`.
        //
        // BEFORE: _ *witness *l_lk *r_lk *n_lk
        // AFTER:  _ *witness *l_lk *r_lk *n_lk *l_field *r_field *n_field
        let authenticate_in_all_three =
            |accessor: &[LabelledInstruction], authenticate: &str| -> Vec<LabelledInstruction> {
                // The stack grows by one pointer per kernel, and the kernel
                // pointer being read sinks by one at the same rate, so the same
                // `dup 7` reaches `*l_lk`, then `*r_lk`, then `*n_lk`.
                let one = |mast_hash_address| {
                    triton_asm!(
                        // _ *witness *l_lk *r_lk *n_lk [*field..]
                        push {mast_hash_address}
                        read_mem {Digest::LEN}
                        pop 1
                        // _ ... [lkmh]

                        dup 7
                        {&accessor}
                        // _ ... [lkmh] *field size

                        dup 1
                        place 7
                        // _ ... *field [lkmh] *field size

                        call {authenticate}
                        // _ ... *field
                    )
                };
                [one(left_lkmh), one(right_lkmh), one(new_lkmh)].concat()
            };

        let inner =
            |accessor: &[LabelledInstruction]| triton_asm!({&field_inner_kernel} {&accessor});

        // New inputs are exactly the operands' inputs, in any order. Removal
        // records are compared by their absolute index sets: that is what a
        // double spend collides on.
        let assert_inputs_are_the_operands_inputs = triton_asm!(
            // _ *witness *l_lk *r_lk *n_lk
            {&authenticate_in_all_three(&inner(&field_with_size_inputs), &authenticate_inputs)}
            // _ *witness *l_lk *r_lk *n_lk *l_in *r_in *n_in

            call {hash_1_removal_record_index_set}
            // _ *witness *l_lk *r_lk *n_lk *l_in *r_in *n_in_digests

            place 2
            call {hash_2_removal_record_index_sets}
            // _ *witness *l_lk *r_lk *n_lk *n_in_digests *lr_in_digests

            call {multiset_equality}
            assert error_id {INPUTS_ARE_NOT_THE_OPERANDS_INPUTS_ERROR}
            // _ *witness *l_lk *r_lk *n_lk
        );

        // Cut-through, on both sides at once: the chained outputs plus the
        // cut-through set are exactly the operands' outputs, and the chained
        // thruputs plus *that same* set are exactly the operands' thruputs. So
        // an addition record leaves the output side if and only if it leaves the
        // input side, which is precisely value conservation. Matching happens on
        // the addition record, i.e. on the UTXO's canonical commitment.
        let assert_cut_through =
            |accessor: &[LabelledInstruction], authenticate: &str, error_id: i128| {
                triton_asm!(
                    // _ *witness *l_lk *r_lk *n_lk
                    {&authenticate_in_all_three(accessor, authenticate)}
                    // _ *witness *l_lk *r_lk *n_lk *l_field *r_field *n_field

                    dup 6
                    {&field_cut_through}
                    // _ *witness *l_lk *r_lk *n_lk *l_field *r_field *n_field *cut_through

                    call {hash_2_lists_of_addition_records}
                    // _ *witness *l_lk *r_lk *n_lk *l_field *r_field *n_and_cut_digests

                    place 2
                    call {hash_2_lists_of_addition_records}
                    // _ *witness *l_lk *r_lk *n_lk *n_and_cut_digests *lr_digests

                    call {multiset_equality}
                    assert error_id {error_id}
                    // _ *witness *l_lk *r_lk *n_lk
                )
            };

        // Cut-through is maximal: no chained output is also a chained thruput.
        // The two equations above do not imply it -- they are satisfied by
        // *any* sub-multiset of the intersection, so on their own a prover may
        // name a short cut-through set and leave a matching pair standing --
        // and it is disjointness that pins the cut-through set to the whole
        // intersection: for a record held `a` times by the operands' outputs
        // and `b` times by their thruputs, the equations force the cut-through
        // multiplicity `c <= min(a, b)`, and disjointness of the `a - c` and
        // `b - c` survivors then forces `c = min(a, b)`.
        //
        // Both lists were authenticated against `lkmh` just above, by the
        // `assert_cut_through` pair; this only re-reads them.
        let assert_cut_through_is_maximal = triton_asm!(
            // _ *witness *l_lk *r_lk *n_lk
            dup 0
            {&inner(&field_outputs)}
            // _ *witness *l_lk *r_lk *n_lk *n_out

            push {chained_outputs_alloc.write_address()}
            write_mem 1
            pop 1
            // _ *witness *l_lk *r_lk *n_lk

            dup 0
            {&field_thruputs}
            // _ *witness *l_lk *r_lk *n_lk *n_thru

            call {no_thruput_is_a_chained_output}
            assert error_id {CUT_THROUGH_IS_NOT_MAXIMAL_ERROR}
            // _ *witness *l_lk *r_lk *n_lk
        );

        let assert_announcements_are_the_operands_announcements = triton_asm!(
            // _ *witness *l_lk *r_lk *n_lk
            {&authenticate_in_all_three(
                &inner(&field_with_size_announcements),
                &authenticate_announcements,
            )}
            // _ *witness *l_lk *r_lk *n_lk *l_pa *r_pa *n_pa

            call {hash_1_list_of_announcements}
            place 2
            call {hash_2_lists_of_announcements}
            call {multiset_equality}
            assert error_id {ANNOUNCEMENTS_ARE_NOT_THE_OPERANDS_ANNOUNCEMENTS_ERROR}
            // _ *witness *l_lk *r_lk *n_lk
        );

        // Read one kernel's fee, authenticate it against that kernel's MAST
        // hash, and leave its value on the stack.
        let authenticated_fee = |kernel_depth: usize, mast_hash_address| {
            triton_asm!(
                // _ *witness *l_lk *r_lk *n_lk [fees..]
                dup {kernel_depth}
                {&field_inner_kernel}
                {&field_fee}
                // _ ... *fee

                push {mast_hash_address}
                read_mem {Digest::LEN}
                pop 1
                // _ ... *fee [lkmh]

                dup 5
                push {fee_size}
                call {authenticate_fee}
                // _ ... *fee

                addi {fee_size - 1}
                read_mem {fee_size}
                pop 1
                // _ ... [fee; 4]
            )
        };

        let assert_fee_is_sum_of_operand_fees = triton_asm!(
            // _ *witness *l_lk *r_lk *n_lk
            {&authenticated_fee(2, left_lkmh)}
            // _ *witness *l_lk *r_lk *n_lk [left_fee; 4]

            {&authenticated_fee(5, right_lkmh)}
            // _ *witness *l_lk *r_lk *n_lk [left_fee; 4] [right_fee; 4]

            call {overflowing_add_u128}
            // _ *witness *l_lk *r_lk *n_lk [sum; 4] overflow

            /* assert no overflow */
            push 0 eq
            assert error_id {NEW_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR}
            // _ *witness *l_lk *r_lk *n_lk [sum; 4]

            /* assert valid native currency amount */
            dup 3 dup 3 dup 3 dup 3
            {&push_max_amount}
            call {lt_u128}
            push 0 eq
            assert error_id {NEW_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR}
            // _ *witness *l_lk *r_lk *n_lk [sum; 4]

            /* the chained kernel's fee must be that sum */
            dup 4
            {&field_inner_kernel}
            {&field_fee}
            // _ *witness *l_lk *r_lk *n_lk [sum; 4] *new_fee

            push {new_lkmh}
            read_mem {Digest::LEN}
            pop 1
            // _ ... [sum; 4] *new_fee [n_lkmh]

            dup 5
            push {fee_size}
            call {authenticate_fee}
            // _ ... [sum; 4] *new_fee

            addi {fee_size - 1}
            read_mem {fee_size}
            pop 1
            // _ *witness *l_lk *r_lk *n_lk [sum; 4] [new_fee; 4]

            {&compare_u128}
            assert error_id {NEW_FEE_IS_NOT_SUM_OF_OPERAND_FEES_ERROR}
            // _ *witness *l_lk *r_lk *n_lk
        );

        // Mirrors `merge_branch`'s timestamp handling: the chained timestamp is
        // the later of the two, computed branchlessly.
        let assert_timestamp_is_max_of_operand_timestamps = triton_asm!(
            // _ *witness *l_lk *r_lk *n_lk

            dup 2 {&field_inner_kernel} {&field_timestamp}
            read_mem 1 addi 1
            // _ *witness *l_lk *r_lk *n_lk left_timestamp *left_timestamp

            push {left_lkmh}
            read_mem {Digest::LEN}
            pop 1
            // _ ... left_timestamp *left_timestamp [l_lkmh]

            pick {Digest::LEN}
            push {timestamp_size}
            call {authenticate_timestamp}
            // _ *witness *l_lk *r_lk *n_lk left_timestamp

            dup 2 {&field_inner_kernel} {&field_timestamp}
            read_mem 1 addi 1
            // _ ... left_timestamp right_timestamp *right_timestamp

            push {right_lkmh}
            read_mem {Digest::LEN}
            pop 1
            // _ ... left_timestamp right_timestamp *right_timestamp [r_lkmh]

            pick {Digest::LEN}
            push {timestamp_size}
            call {authenticate_timestamp}
            // _ *witness *l_lk *r_lk *n_lk left_timestamp right_timestamp

            dup 1 split
            dup 2 split
            call {lt_u64}
            // _ ... left_timestamp right_timestamp (right < left)

            pick 2 dup 1 mul place 2
            // _ ... ((r<l) * left_timestamp) right_timestamp (r<l)

            push 0 eq mul
            // _ ... ((r<l) * left_timestamp) ((r>=l) * right_timestamp)

            add
            // _ *witness *l_lk *r_lk *n_lk max_timestamp

            dup 1 {&field_inner_kernel} {&field_timestamp}
            read_mem 1 addi 1
            // _ ... max_timestamp new_timestamp *new_timestamp

            place 2
            eq
            assert error_id {TIMESTAMP_IS_NOT_MAX_OF_OPERAND_TIMESTAMPS_ERROR}
            // _ *witness *l_lk *r_lk *n_lk *new_timestamp

            push {new_lkmh}
            read_mem {Digest::LEN}
            pop 1
            // _ ... *new_timestamp [n_lkmh]

            pick {Digest::LEN}
            push {timestamp_size}
            call {authenticate_timestamp}
            // _ *witness *l_lk *r_lk *n_lk
        );

        // All three kernels must be relative to one and the same mutator set;
        // otherwise the operands' membership proofs would be pooled across
        // incompatible mutator-set states.
        let read_and_authenticate_mutator_set_hash = |kernel_depth: usize, mast_hash_address| {
            triton_asm!(
                // _ ...
                dup {kernel_depth} {&field_inner_kernel} {&field_mutator_set_hash}
                addi {Digest::LEN - 1}
                read_mem {Digest::LEN}
                addi 1
                place {Digest::LEN}
                // _ ... *msh [msh]

                push {mast_hash_address}
                read_mem {Digest::LEN}
                pop 1
                // _ ... *msh [msh] [lkmh]

                pick {2 * Digest::LEN}
                push {Digest::LEN}
                call {authenticate_mutator_set_hash}
                // _ ... [msh]
            )
        };

        let assert_all_kernels_agree_on_mutator_set_hash = triton_asm!(
            // _ *witness *l_lk *r_lk *n_lk
            {&read_and_authenticate_mutator_set_hash(2, left_lkmh)}
            // _ *witness *l_lk *r_lk *n_lk [left_msh]

            {&read_and_authenticate_mutator_set_hash(6, right_lkmh)}
            // _ *witness *l_lk *r_lk *n_lk [left_msh] [right_msh]

            dup 9 dup 9 dup 9 dup 9 dup 9
            {&compare_digests}
            assert error_id {MUTATOR_SET_HASH_MISMATCH_ERROR}
            // _ *witness *l_lk *r_lk *n_lk [left_msh]

            // only `[left_msh]` survived the comparison above, so `*n_lk` is
            // back at the depth it had for the left operand's read, plus one
            // digest
            {&read_and_authenticate_mutator_set_hash(5, new_lkmh)}
            // _ *witness *l_lk *r_lk *n_lk [left_msh] [new_msh]

            dup 9 dup 9 dup 9 dup 9 dup 9
            {&compare_digests}
            assert error_id {MUTATOR_SET_HASH_MISMATCH_ERROR}
            // _ *witness *l_lk *r_lk *n_lk [left_msh]

            pop {Digest::LEN}
            // _ *witness *l_lk *r_lk *n_lk
        );

        // A chained transaction is no more a coinbase transaction, and no more
        // merged, than a forged one: the constant leaf is authenticated
        // directly, which asserts the field's value at the same time (only one
        // preimage hashes to it).
        let authenticate_constant_leaf = |leaf_index: LinkKernelField, leaf: Digest| {
            triton_asm!(
                // _
                push {new_lkmh}
                read_mem {Digest::LEN}
                pop 1
                // _ [n_lkmh]

                push {LinkKernel::MAST_HEIGHT}
                push {leaf_index.discriminant() as u32}
                {&push_digest(leaf)}
                // _ [n_lkmh] height index [leaf]

                call {merkle_verify}
                // _
            )
        };

        // Divine one operand's kernel MAST hash and stash it. Free to be
        // anything at this point: the field authentications in between bind it
        // to the witness data, but every input to those is prover-supplied, so
        // they rule out no value. The recursive verification below is what
        // forces it to be a root some link proof attests to.
        let divine_operand_mast_hash = |mast_hash_write_address| {
            triton_asm!(
                // _ [own_program_digest] disc *witness
                divine {Digest::LEN}
                hint operand_link_kernel_mast_hash = stack[0..5]
                // _ [own_program_digest] disc *witness [operand_lkmh]

                push {mast_hash_write_address}
                write_mem {Digest::LEN}
                pop 1
                // _ [own_program_digest] disc *witness
            )
        };

        // Recursively verify one operand's link proof, against a claim naming
        // this very program on that operand's kernel MAST hash.
        //
        // Deliberately the *last* thing the branch does, unlike
        // `merge_branch`, which recurses first. Everything else is cheap and
        // self-contained, so running it first lets a negative test drive any of
        // those assertions with a proofless witness -- the same reason `Forge`
        // ends with its script verifications. Order is immaterial to soundness:
        // every assertion has to hold either way.
        let verify_operand = |mast_hash_read_address, proof: &[LabelledInstruction]| {
            triton_asm!(
                // _ [own_program_digest] disc *witness
                push {mast_hash_read_address}
                read_mem {Digest::LEN}
                pop 1
                // _ [own_program_digest] disc *witness [operand_lkmh]

                dup 11 dup 11 dup 11 dup 11 dup 11
                // _ [own_program_digest] disc *witness [operand_lkmh] [own_program_digest]

                // The claim generator appends `D` itself, reading it from where
                // the dispatcher put the public input. Audit-critical: never
                // divined, never taken from the witness -- a gap there is
                // universal forgery.
                call {generate_link_proof_claim}
                // _ [own_program_digest] disc *witness *claim

                dup 1
                {&proof}
                // _ [own_program_digest] disc *witness *claim *proof

                call {stark_verify}
                // _ [own_program_digest] disc *witness
            )
        };

        triton_asm!(
            {self.entrypoint()}:
            // _ [own_program_digest] [new_lkmh] *link_proof_witness disc

            place 6
            // _ [own_program_digest] disc [new_lkmh] *link_proof_witness

            addi 2
            hint witness = stack[0]
            // _ [own_program_digest] disc [new_lkmh] *witness
            // `disc` stays buried below the frame until the epilogue; the own
            // program digest stays below that, where the dispatcher left it.

            dup 0 call {audit_preloaded_data} pop 1
            // _ [own_program_digest] disc [new_lkmh] *witness

            place 5
            push {new_lkmh_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ [own_program_digest] disc *witness

            {&divine_operand_mast_hash(left_lkmh_alloc.write_address())}
            {&divine_operand_mast_hash(right_lkmh_alloc.write_address())}
            // _ [own_program_digest] disc *witness

            dup 0 {&field_left_kernel}
            dup 1 {&field_right_kernel}
            dup 2 {&field_new_kernel}
            // _ [own_program_digest] disc *witness *l_lk *r_lk *n_lk

            {&assert_inputs_are_the_operands_inputs}
            {&assert_cut_through(
                &inner(&field_with_size_outputs),
                &authenticate_outputs,
                OUTPUTS_ARE_NOT_CUT_THROUGH_ERROR,
            )}
            {&assert_cut_through(
                &field_with_size_thruputs,
                &authenticate_thruputs,
                THRUPUTS_ARE_NOT_CUT_THROUGH_ERROR,
            )}
            {&assert_cut_through_is_maximal}
            {&assert_announcements_are_the_operands_announcements}
            {&assert_fee_is_sum_of_operand_fees}
            {&assert_timestamp_is_max_of_operand_timestamps}
            {&assert_all_kernels_agree_on_mutator_set_hash}
            // _ [own_program_digest] disc *witness *l_lk *r_lk *n_lk

            pop 3
            // _ [own_program_digest] disc *witness

            {&authenticate_constant_leaf(LinkKernelField::Coinbase, no_coinbase_leaf())}
            {&authenticate_constant_leaf(LinkKernelField::MergeBit, merge_bit_false_leaf())}
            // _ [own_program_digest] disc *witness

            /* Last: the recursion. Both operand kernels are bound to the witness
               data by now; these two claims bind them to their link proofs. */
            {&verify_operand(left_lkmh, &field_left_proof)}
            {&verify_operand(right_lkmh, &field_right_proof)}
            // _ [own_program_digest] disc *witness

            swap 1
            // _ [own_program_digest] *witness disc

            push {new_lkmh}
            read_mem {Digest::LEN}
            pop 1
            // _ [own_program_digest] *witness disc [new_lkmh]
            // (the chained kernel's MAST hash goes into the dispatcher's scratch
            // slot, which the dispatcher pops unread.)

            pick 6 pick 6
            // _ [own_program_digest] [new_lkmh] *witness disc

            addi {-(DISCRIMINANT_FOR_CHAIN as isize) - 1}
            // _ [own_program_digest] [new_lkmh] *witness -1

            return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use neptune_primitives::mast_hash::HasDiscriminant;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::chaintx::link_primitive_witness::LinkPrimitiveWitness;
    use crate::chaintx::mock_single_proof_digest;
    use crate::chaintx::test_helpers::deterministic_chainable_link_primitive_witnesses;
    use crate::chaintx::test_helpers::forge;
    use crate::chaintx::test_helpers::predecessor_resolving;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::TritonVmProofJobOptions;
    use crate::proof_abstractions::triton_vm_job_queue::vm_job_queue;
    use crate::transaction::primitive_witness::PrimitiveWitness;

    /// The `Chain` branch of the `LinkProof` rust shadow, called by
    /// [`LinkProof::source`](super::super::link_proof::LinkProof) once it has
    /// read the own program digest, `lkmh` and `D`, and matched the witness
    /// discriminant -- mirroring the tasm, where the dispatcher does exactly
    /// that before `call`ing this branch.
    ///
    /// `single_proof_digest` comes from the dispatcher, i.e. from the public
    /// input. Never from `witness.single_proof_digest`, which is present in the
    /// memory image and must stay unread!
    pub(in crate::chaintx) fn chain_branch_source(
        own_program_digest: Digest,
        lkmh: Digest,
        single_proof_digest: Digest,
        witness: ChainWitness,
    ) {
        /* the operands' kernel MAST hashes. The field authentications below
        tie each to its operand in the witness -- but root, leafs and paths are
        all prover-supplied, so they exclude no *value*. The recursive
        verifications at the very end are what force them to be roots that link
        proofs attest to. */
        let left_lkmh: Digest = tasm::tasmlib_io_read_secin___digest();
        let right_lkmh: Digest = tasm::tasmlib_io_read_secin___digest();

        let left = &witness.left_kernel;
        let right = &witness.right_kernel;
        let new = &witness.new_kernel;
        let height = LinkKernel::MAST_HEIGHT as u32;
        let authenticate = |root: Digest, field: LinkKernelField, leaf: Digest| {
            tasm::tasmlib_hashing_merkle_verify(root, field.discriminant() as u32, leaf, height);
        };

        /* inputs: the concatenation, in any order, compared by index set --
        that is what a double spend collides on */
        authenticate(
            left_lkmh,
            LinkKernelField::Inputs,
            Tip5::hash(&left.kernel.inputs),
        );
        authenticate(
            right_lkmh,
            LinkKernelField::Inputs,
            Tip5::hash(&right.kernel.inputs),
        );
        authenticate(
            lkmh,
            LinkKernelField::Inputs,
            Tip5::hash(&new.kernel.inputs),
        );
        let index_sets = |kernel: &LinkKernel| {
            kernel
                .kernel
                .inputs
                .iter()
                .map(|rr| Tip5::hash(&rr.absolute_indices.to_vec()))
                .collect_vec()
        };
        assert_eq!(
            [index_sets(left), index_sets(right)]
                .concat()
                .into_iter()
                .sorted()
                .collect_vec(),
            index_sets(new).into_iter().sorted().collect_vec(),
        );

        /* outputs and thruputs: the concatenations, both minus the same
        cut-through multiset */
        let cut_through = witness.cut_through.iter().map(Tip5::hash).collect_vec();
        let hashed = |records: &[AdditionRecord]| records.iter().map(Tip5::hash).collect_vec();

        authenticate(
            left_lkmh,
            LinkKernelField::Outputs,
            Tip5::hash(&left.kernel.outputs),
        );
        authenticate(
            right_lkmh,
            LinkKernelField::Outputs,
            Tip5::hash(&right.kernel.outputs),
        );
        authenticate(
            lkmh,
            LinkKernelField::Outputs,
            Tip5::hash(&new.kernel.outputs),
        );
        assert_eq!(
            [hashed(&left.kernel.outputs), hashed(&right.kernel.outputs)]
                .concat()
                .into_iter()
                .sorted()
                .collect_vec(),
            [hashed(&new.kernel.outputs), cut_through.clone()]
                .concat()
                .into_iter()
                .sorted()
                .collect_vec(),
        );

        authenticate(
            left_lkmh,
            LinkKernelField::Thruputs,
            Tip5::hash(&left.thruputs),
        );
        authenticate(
            right_lkmh,
            LinkKernelField::Thruputs,
            Tip5::hash(&right.thruputs),
        );
        authenticate(lkmh, LinkKernelField::Thruputs, Tip5::hash(&new.thruputs));
        assert_eq!(
            [hashed(&left.thruputs), hashed(&right.thruputs)]
                .concat()
                .into_iter()
                .sorted()
                .collect_vec(),
            [hashed(&new.thruputs), cut_through]
                .concat()
                .into_iter()
                .sorted()
                .collect_vec(),
        );

        /* cut-through is maximal: nothing cancellable is left standing. The two
        equations above hold for any sub-multiset of the intersection; this is
        what pins the cut-through set to all of it */
        for thruput in &new.thruputs {
            assert!(!new.kernel.outputs.contains(thruput));
        }

        /* announcements: the concatenation, in any order */
        authenticate(
            left_lkmh,
            LinkKernelField::Announcements,
            Tip5::hash(&left.kernel.announcements),
        );
        authenticate(
            right_lkmh,
            LinkKernelField::Announcements,
            Tip5::hash(&right.kernel.announcements),
        );
        authenticate(
            lkmh,
            LinkKernelField::Announcements,
            Tip5::hash(&new.kernel.announcements),
        );
        let announcements = |kernel: &LinkKernel| {
            kernel
                .kernel
                .announcements
                .iter()
                .map(Tip5::hash)
                .collect_vec()
        };
        assert_eq!(
            [announcements(left), announcements(right)]
                .concat()
                .into_iter()
                .sorted()
                .collect_vec(),
            announcements(new).into_iter().sorted().collect_vec(),
        );

        /* fee: the sum, which being in `[0, MAX_NAU]` puts both operands there
        too -- neither is bounded on its own */
        authenticate(
            left_lkmh,
            LinkKernelField::Fee,
            Tip5::hash(&left.kernel.fee),
        );
        authenticate(
            right_lkmh,
            LinkKernelField::Fee,
            Tip5::hash(&right.kernel.fee),
        );
        // Added on the raw `u128`s, exactly as the tasm adds them -- which is
        // where a negative amount is enormous rather than negative. So the
        // carry is the real thing here too, and the two asserts are the tasm's
        // two, not a signed surrogate for them.
        let raw = |amount: NativeCurrencyAmount| amount.to_nau() as u128;
        let (sum, carry) = raw(left.kernel.fee).overflowing_add(raw(right.kernel.fee));
        assert!(!carry);
        assert!(sum <= NativeCurrencyAmount::MAX_NAU as u128);
        authenticate(lkmh, LinkKernelField::Fee, Tip5::hash(&new.kernel.fee));
        assert_eq!(sum, raw(new.kernel.fee));

        /* timestamp: the later of the two */
        authenticate(
            left_lkmh,
            LinkKernelField::Timestamp,
            Tip5::hash(&left.kernel.timestamp),
        );
        authenticate(
            right_lkmh,
            LinkKernelField::Timestamp,
            Tip5::hash(&right.kernel.timestamp),
        );
        assert_eq!(
            max(left.kernel.timestamp, right.kernel.timestamp),
            new.kernel.timestamp
        );
        authenticate(
            lkmh,
            LinkKernelField::Timestamp,
            Tip5::hash(&new.kernel.timestamp),
        );

        /* one mutator set for all three */
        authenticate(
            left_lkmh,
            LinkKernelField::MutatorSetHash,
            Tip5::hash(&left.kernel.mutator_set_hash),
        );
        authenticate(
            right_lkmh,
            LinkKernelField::MutatorSetHash,
            Tip5::hash(&right.kernel.mutator_set_hash),
        );
        assert_eq!(left.kernel.mutator_set_hash, right.kernel.mutator_set_hash);
        authenticate(
            lkmh,
            LinkKernelField::MutatorSetHash,
            Tip5::hash(&new.kernel.mutator_set_hash),
        );
        assert_eq!(left.kernel.mutator_set_hash, new.kernel.mutator_set_hash);

        /* a chained transaction is no more a coinbase transaction, and no more
        merged, than a forged one */
        authenticate(lkmh, LinkKernelField::Coinbase, no_coinbase_leaf());
        authenticate(lkmh, LinkKernelField::MergeBit, merge_bit_false_leaf());

        /* last: recursively verify both operands' link proofs */
        let operand_claim = |operand_lkmh: Digest| {
            let input = link_proof_public_input(operand_lkmh, single_proof_digest);
            Claim::new(own_program_digest).with_input(input.individual_tokens)
        };
        tasm::verify_stark(
            Stark::default(),
            &operand_claim(left_lkmh),
            &witness.left_proof,
        );
        tasm::verify_stark(
            Stark::default(),
            &operand_claim(right_lkmh),
            &witness.right_proof,
        );
    }

    /// Assertion is that both the Rust shadow and the tasm run to completion
    /// and halt gracefully. Do this without proving anything.
    fn prop_positive(witness: ChainWitness) {
        LinkProof
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
        LinkProof
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
    }

    /// Cut-through pairs an output with a thruput and drops both, so the
    /// chained kernel loses one of each per pair.
    #[proptest(cases = 4)]
    fn cut_through_removes_matching_pairs_from_both_sides(
        #[strategy(0usize..=3)] num_thruputs: usize,
        #[strategy(arb())] shuffle_seed: [u8; 32],
    ) {
        let (predecessor, successor) =
            deterministic_chainable_link_primitive_witnesses(3, num_thruputs);
        let (chained, cut_through) =
            ChainWitness::chained_kernel(&predecessor.kernel, &successor.kernel, shuffle_seed);

        prop_assert_eq!(num_thruputs, cut_through.len());
        prop_assert_eq!(
            predecessor.kernel.kernel.outputs.len() + successor.kernel.kernel.outputs.len()
                - num_thruputs,
            chained.kernel.outputs.len()
        );
        prop_assert_eq!(
            predecessor.kernel.thruputs.len() + successor.kernel.thruputs.len() - num_thruputs,
            chained.thruputs.len()
        );
        prop_assert_eq!(
            predecessor.kernel.kernel.inputs.len() + successor.kernel.kernel.inputs.len(),
            chained.kernel.inputs.len()
        );
    }

    /// How many distinct addition records `chain_is_associative` draws from.
    const POOL: usize = 5;

    /// Everything a chained kernel is, up to the order of its multisets --
    /// which is all `Chain` fixes, the concatenations being shuffled.
    fn canonical(kernel: &LinkKernel) -> impl std::fmt::Debug + PartialEq {
        let sorted = |digests: Vec<Digest>| digests.into_iter().sorted().collect_vec();
        (
            sorted(kernel.kernel.inputs.iter().map(Tip5::hash).collect_vec()),
            sorted(kernel.kernel.outputs.iter().map(Tip5::hash).collect_vec()),
            sorted(kernel.thruputs.iter().map(Tip5::hash).collect_vec()),
            sorted(
                kernel
                    .kernel
                    .announcements
                    .iter()
                    .map(Tip5::hash)
                    .collect_vec(),
            ),
            kernel.kernel.fee,
            kernel.kernel.timestamp,
            kernel.kernel.mutator_set_hash,
        )
    }

    /// `Chain` is associative: `Chain(Chain(A, B), C) == Chain(A, Chain(B, C))`,
    /// up to the order of the multisets. Order of chaining does not matter.
    #[proptest(cases = 100)]
    fn chain_is_associative(
        #[strategy(proptest::collection::vec(0usize..=2, 3 * 2 * POOL))] multiplicities: Vec<usize>,
    ) {
        // one record per pool index, distinct and cheap -- `chained_kernel`
        // compares addition records, it does not interpret them
        let record = |i: usize| AdditionRecord {
            canonical_commitment: Digest::new([BFieldElement::new(i as u64); Digest::LEN]),
        };
        let multiset = |counts: &[usize]| {
            counts
                .iter()
                .enumerate()
                .flat_map(|(i, &n)| vec![record(i); n])
                .collect_vec()
        };

        let operand = |k: usize| {
            let side = |half: usize| {
                let start = 2 * POOL * k + POOL * half;
                multiset(&multiplicities[start..start + POOL])
            };
            LinkKernel {
                kernel: TransactionKernelProxy {
                    inputs: vec![],
                    outputs: side(0),
                    announcements: vec![],
                    fee: NativeCurrencyAmount::coins(k as u32),
                    coinbase: None,
                    timestamp: Timestamp::hours(k),
                    mutator_set_hash: Digest::default(),
                    merge_bit: false,
                }
                .into_kernel(),
                thruputs: side(1),
            }
        };
        let (a, b, c) = (operand(0), operand(1), operand(2));

        // Distinct seeds per step: the result is compared as multisets, so the
        // shuffling must not be what makes the two sides agree.
        let (ab, cut_ab) = ChainWitness::chained_kernel(&a, &b, [0u8; 32]);
        let (ab_c, cut_ab_c) = ChainWitness::chained_kernel(&ab, &c, [1u8; 32]);
        let (bc, cut_bc) = ChainWitness::chained_kernel(&b, &c, [2u8; 32]);
        let (a_bc, cut_a_bc) = ChainWitness::chained_kernel(&a, &bc, [3u8; 32]);

        prop_assert_eq!(canonical(&ab_c), canonical(&a_bc));

        // And the same records were cancelled along the way -- the groupings
        // agreeing on the result but not on what they cut through would mean
        // value moved between the two sides.
        let cut = |inner: Vec<AdditionRecord>, outer: Vec<AdditionRecord>| {
            [inner, outer]
                .concat()
                .iter()
                .map(Tip5::hash)
                .sorted()
                .collect_vec()
        };
        prop_assert_eq!(cut(cut_ab, cut_ab_c), cut(cut_bc, cut_a_bc));
    }

    /// A successor chained onto the predecessor whose outputs it spends: every
    /// thruput cuts through, and the chained transaction is one the `Fix` branch
    /// could eventually take to a block.
    #[tokio::test]
    async fn chain_accepts_a_predecessor_successor_pair() {
        for num_thruputs in 0..=2 {
            let (predecessor, successor) =
                deterministic_chainable_link_primitive_witnesses(2, num_thruputs);
            let d = mock_single_proof_digest(0);
            let witness = ChainWitness::chain(
                forge(&predecessor, d).await,
                forge(&successor, d).await,
                d,
                [0u8; 32],
            );
            assert_eq!(num_thruputs, witness.cut_through.len());
            assert!(witness.new_kernel.thruputs.is_empty());
            prop_positive(witness);
        }
    }

    /// Depth 2: a `Chain`-produced link proof is itself a valid operand, which
    /// is what makes a *chain* out of a binary operation.
    ///
    /// Every other test here chains `Forge`-produced operands.
    ///
    /// Nothing cuts through: the three operands are independent transactions
    /// over one mutator set, which is what makes them chainable in the first
    /// place. Cut-through across a chain is `chain_is_associative`'s job.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn chain_accepts_a_chain_produced_operand() {
        // ..._and_given_coinbase with `None`, not the plain tuple strategy:
        // that one hands one of the N a coinbase at random, and a link
        // transaction is never a coinbase transaction.
        let mut test_runner = TestRunner::deterministic();
        let [a, b, c] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets_and_given_coinbase(
                [(2, 2, 1); 3],
                None,
            )
            .new_tree(&mut test_runner)
            .unwrap()
            .current()
            .map(|pw| LinkPrimitiveWitness::from_primitive_witness(pw, 0));

        let d = mock_single_proof_digest(0);
        let inner = ChainWitness::chain(forge(&a, d).await, forge(&b, d).await, d, [0u8; 32]);
        let inner_proof = LinkProof
            .prove(
                inner.claim(),
                inner.nondeterminism(),
                vm_job_queue(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();
        let inner_tx = LinkTx {
            kernel: inner.new_kernel,
            proof: LinkTxProof::Proof(inner_proof),
        };

        prop_positive(ChainWitness::chain(
            inner_tx,
            forge(&c, d).await,
            d,
            [1u8; 32],
        ));
    }

    /// Thruputs resolved in two stages, one `Chain` each.
    ///
    /// The successor is funded entirely by unconfirmed money, and by *two*
    /// different predecessors -- one thruput apiece. Chaining in the first
    /// cancels one thruput and leaves the other standing; only chaining in the
    /// second empties the list, and with it makes the transaction something
    /// `Fix` could take to a block.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn thruputs_resolve_in_two_stages() {
        let mut test_runner = TestRunner::deterministic();
        let successor_pw = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();

        // Both of the successor's inputs become thruputs, one per predecessor.
        let first = predecessor_resolving(&successor_pw, 0..1);
        let second = predecessor_resolving(&successor_pw, 1..2);
        let successor = LinkPrimitiveWitness::from_primitive_witness(successor_pw, 2);
        assert_eq!(2, successor.kernel.thruputs.len());

        let d = mock_single_proof_digest(0);
        let stage_one = ChainWitness::chain(
            forge(&first, d).await,
            forge(&successor, d).await,
            d,
            [0u8; 32],
        );
        assert_eq!(1, stage_one.cut_through.len());
        assert_eq!(
            1,
            stage_one.new_kernel.thruputs.len(),
            "the second predecessor's thruput is still outstanding"
        );
        prop_positive(stage_one.clone());

        let stage_one_proof = LinkProof
            .prove(
                stage_one.claim(),
                stage_one.nondeterminism(),
                vm_job_queue(),
                TritonVmProofJobOptions::default(),
            )
            .await
            .unwrap();
        let stage_one_tx = LinkTx {
            kernel: stage_one.new_kernel,
            proof: LinkTxProof::Proof(stage_one_proof),
        };

        let stage_two = ChainWitness::chain(stage_one_tx, forge(&second, d).await, d, [1u8; 32]);
        assert_eq!(1, stage_two.cut_through.len());
        assert!(
            stage_two.new_kernel.thruputs.is_empty(),
            "the second stage resolves the last thruput"
        );
        prop_positive(stage_two);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod negative_tests {
    use neptune_mutator_set::addition_record::AdditionRecord;
    use num_traits::CheckedSub;
    use tasm_lib::hashing::merkle_verify::MerkleVerify;

    use proptest::prop_assert_eq;
    use proptest::prop_assume;
    use proptest::strategy::Strategy;
    use test_strategy::proptest;

    use super::*;
    use crate::chaintx::link_primitive_witness::LinkPrimitiveWitness;
    use crate::chaintx::mock_single_proof_digest;
    use crate::chaintx::test_helpers::chainable_link_primitive_witnesses;
    use crate::chaintx::test_helpers::deterministic_chainable_link_primitive_witnesses;
    use crate::chaintx::test_helpers::forge;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::TritonError;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;

    impl ChainWitness {
        /// Cheap test-only constructor: a [`ChainWitness`] whose operand link
        /// proofs are mocks.
        ///
        /// Sound for every negative below because the recursion is the *last*
        /// thing the `Chain` branch does, so any other assertion fires before a
        /// proof is ever looked at. A positive test cannot use this.
        fn without_proofs(left: &LinkKernel, right: &LinkKernel, shuffle_seed: [u8; 32]) -> Self {
            let (new_kernel, cut_through) = Self::chained_kernel(left, right, shuffle_seed);
            Self {
                left_kernel: left.clone(),
                right_kernel: right.clone(),
                new_kernel,
                cut_through,
                left_proof: Proof::invalid_mock(),
                right_proof: Proof::invalid_mock(),
                single_proof_digest: mock_single_proof_digest(0),
            }
        }
    }

    /// A chainable pair of random contents whose successor holds one thruput
    /// that a predecessor output resolves -- so there is a cut-through to tamper
    /// with, an input on either side, and a non-empty everything.
    ///
    /// The *shape* is held fixed (2 inputs, 1 of them a thruput) so that every
    /// index the negatives poke exists; only the contents vary. Mirrors
    /// [`pokeable_lpw`](super::super::forge::tests) on the `Forge` side.
    fn pokeable_witness() -> proptest::strategy::BoxedStrategy<ChainWitness> {
        pokeable_pair()
            .prop_map(|(predecessor, successor)| {
                ChainWitness::without_proofs(&predecessor.kernel, &successor.kernel, [0u8; 32])
            })
            .boxed()
    }

    /// The chainable pair behind [`pokeable_witness`], for the negatives that
    /// have to reach past the witness and poke an operand first.
    fn pokeable_pair(
    ) -> proptest::strategy::BoxedStrategy<(LinkPrimitiveWitness, LinkPrimitiveWitness)> {
        PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .prop_map(|pw| chainable_link_primitive_witnesses(pw, 1))
            .boxed()
    }

    /// Poke the chained kernel and re-derive everything from it: the claim's
    /// public input and all of its authentication paths come from
    /// `new_kernel`, so a tampered kernel stays internally consistent and only
    /// the check under test can fail.
    fn expect_failure(
        witness: ChainWitness,
        error_ids: &[i128],
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        LinkProof.test_assertion_failure(
            witness.standard_input(),
            witness.nondeterminism(),
            error_ids,
        )
    }

    /// Dropping one of the operands' removal records from the chained kernel is
    /// value creation: an input vanishes without its funds being accounted for.
    #[proptest(cases = 4)]
    fn chained_inputs_must_be_the_operands_inputs(
        #[strategy(pokeable_witness())] mut witness: ChainWitness,
    ) {
        let mut inputs = witness.new_kernel.kernel.inputs.clone();
        inputs.pop().unwrap();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(witness.new_kernel.kernel);

        expect_failure(witness, &[INPUTS_ARE_NOT_THE_OPERANDS_INPUTS_ERROR]).unwrap();
    }

    /// Announcements likewise carry over wholesale.
    #[proptest(cases = 4)]
    fn chained_announcements_must_be_the_operands_announcements(
        #[strategy(pokeable_witness())] mut witness: ChainWitness,
    ) {
        let mut announcements = witness.new_kernel.kernel.announcements.clone();
        announcements.pop().unwrap();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .announcements(announcements)
            .modify(witness.new_kernel.kernel);

        expect_failure(
            witness,
            &[ANNOUNCEMENTS_ARE_NOT_THE_OPERANDS_ANNOUNCEMENTS_ERROR],
        )
        .unwrap();
    }

    /// With nothing to cut through, the outputs of the chained kernel are the
    /// union of the operands' outputs, and the cut-through equation degenerates
    /// to that plain multiset equality. Every other negative here pokes a
    /// witness whose cut-through is *non-empty*, so this is the case where the
    /// equation compares against a zero-length list -- and an empty operand is
    /// exactly where a multiset comparison can pass vacuously without anyone
    /// noticing.
    #[proptest(cases = 4)]
    fn chained_outputs_must_be_union_of_outputs_of_operands(
        #[strategy(pokeable_pair())] pair: (LinkPrimitiveWitness, LinkPrimitiveWitness),
    ) {
        let (predecessor, mut successor) = pair;

        // drop the thruput the predecessor's output would have resolved; the
        // operands now share no record, so nothing cancels
        successor.kernel.thruputs.clear();
        let mut witness =
            ChainWitness::without_proofs(&predecessor.kernel, &successor.kernel, [0u8; 32]);
        assert!(witness.cut_through.is_empty());

        let mut outputs = witness.new_kernel.kernel.outputs.clone();
        outputs.pop().unwrap();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .outputs(outputs)
            .modify(witness.new_kernel.kernel);

        expect_failure(witness, &[OUTPUTS_ARE_NOT_CUT_THROUGH_ERROR]).unwrap();
    }

    /// Cut-through must be two-sided. Dropping a record from the output side
    /// alone -- keeping the thruput that pays for it -- destroys value; the
    /// mirror image creates it. Both are one cancellation that only happened
    /// once, and both are caught by the *outputs* equation, which is checked
    /// first.
    #[proptest(cases = 4)]
    fn one_sided_cut_through_is_rejected(#[strategy(pokeable_witness())] original: ChainWitness) {
        // the thruput leaves, its matching output stays
        let mut witness = original.clone();
        let outputs = [
            witness.new_kernel.kernel.outputs.clone(),
            witness.cut_through.clone(),
        ]
        .concat();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .outputs(outputs)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[OUTPUTS_ARE_NOT_CUT_THROUGH_ERROR]).unwrap();

        // the output leaves, its matching thruput stays
        let mut witness = original.clone();
        witness.new_kernel.thruputs = [
            witness.new_kernel.thruputs.clone(),
            witness.cut_through.clone(),
        ]
        .concat();
        expect_failure(witness, &[THRUPUTS_ARE_NOT_CUT_THROUGH_ERROR]).unwrap();
    }

    /// Cut-through cancels an output against a thruput only when their
    /// canonical commitments are equal. A record matching neither side cancels
    /// nothing, so naming it in the cut-through set fails the same equation --
    /// which is what stops a thruput being resolved by a predecessor output that
    /// does not exist.
    #[proptest(cases = 4)]
    fn cut_through_on_unequal_commitments_is_rejected(
        #[strategy(pokeable_witness())] mut witness: ChainWitness,
    ) {
        witness.cut_through[0] = AdditionRecord {
            canonical_commitment: Digest::default(),
        };

        expect_failure(witness, &[OUTPUTS_ARE_NOT_CUT_THROUGH_ERROR]).unwrap();
    }

    /// Cut-through must be maximal. Here the prover declines one cancellation
    /// it could have made: the record leaves the cut-through set and goes back
    /// onto *both* sides, so both cut-through equations still hold -- the
    /// concatenations are unchanged and so is the pairing -- and nothing but the
    /// maximality assert stands between this witness and a valid chain.
    ///
    /// That is the whole hole: the equations bound the cut-through set to a
    /// sub-multiset of the intersection, and only this assert pins it to all of
    /// it.
    #[proptest(cases = 4)]
    fn non_maximal_cut_through_is_rejected(
        #[strategy(pokeable_witness())] mut witness: ChainWitness,
    ) {
        let uncut = witness.cut_through.pop().unwrap();

        let outputs = [witness.new_kernel.kernel.outputs.clone(), vec![uncut]].concat();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .outputs(outputs)
            .modify(witness.new_kernel.kernel);
        witness.new_kernel.thruputs.push(uncut);

        expect_failure(witness, &[CUT_THROUGH_IS_NOT_MAXIMAL_ERROR]).unwrap();
    }

    /// A thruput cannot be cut-through twice.
    ///
    /// This is a double spend that cannot be enforced on the host machine in
    /// `Block::is_valid` rule 2.c because a thruput is not a removal record and
    /// never reaches a block, so verifying uniqeness of all index-sets cannot
    /// be what stops it.
    ///
    /// A conservation law is the solution. One operand claims the same
    /// unconfirmed output as a thruput twice, the other supplies the single
    /// output that resolves it, and the two cut-through equations subtract the
    /// *same* multiset from both sides -- so at most one copy can cancel and
    /// the surplus survives as a thruput the chain still owes, which `Fix`
    /// refuses to carry into a block (`thruputs == []`).
    ///
    /// The attack is the prover cancelling both copies against the one output.
    /// It fails the *outputs* equation: cut-through would have to take that
    /// record off the output side twice, and it is only there once.
    #[proptest(cases = 4)]
    fn a_thruput_cannot_be_cut_through_twice(
        #[strategy(pokeable_pair())] pair: (LinkPrimitiveWitness, LinkPrimitiveWitness),
    ) {
        let (predecessor, mut successor) = pair;

        // the successor now claims its thruput twice; the predecessor's one
        // output can resolve only one of them. Both operands stay internally
        // valid -- outputs and thruputs disjoint on either side -- so this is a
        // shape `Forge` can actually emit, by listing one commitment twice.
        let thruput = successor.kernel.thruputs[0];
        successor.kernel.thruputs.push(thruput);
        let mut witness =
            ChainWitness::without_proofs(&predecessor.kernel, &successor.kernel, [0u8; 32]);

        // conservation, honestly chained: one copy cancels, one is still owed
        prop_assert_eq!(vec![thruput], witness.cut_through.clone());
        prop_assert_eq!(vec![thruput], witness.new_kernel.thruputs.clone());

        // the double spend: cancel the surplus copy too
        witness.cut_through.push(thruput);
        witness.new_kernel.thruputs.clear();

        expect_failure(witness, &[OUTPUTS_ARE_NOT_CUT_THROUGH_ERROR]).unwrap();
    }

    /// Chain the two operand fees and the chained fee, all in nau, and expect
    /// `Chain` to reject the combination. `sum` is stated rather than computed:
    /// the point of every caller below is which side of `[0, MAX_NAU]` it falls
    /// on, so it should be readable off the call.
    fn expect_fee_failure(mut witness: ChainWitness, left: i128, right: i128, sum: i128) {
        let set_fee = |kernel: &mut LinkKernel, nau: i128| {
            kernel.kernel = TransactionKernelModifier::default()
                .fee(NativeCurrencyAmount::from_nau(nau))
                .modify(kernel.kernel.clone());
        };
        set_fee(&mut witness.left_kernel, left);
        set_fee(&mut witness.right_kernel, right);
        set_fee(&mut witness.new_kernel, sum);

        expect_failure(witness, &[NEW_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR]).unwrap();
    }

    /// A fee sum outside `[0, MAX_NAU]` is rejected, over the top and under the
    /// bottom, and on either operand.
    ///
    /// The over-the-top cases use operands that are each *individually* a
    /// perfectly valid amount, so what is rejected is the sum and nothing else.
    /// A negative sum cannot be reached that way -- two amounts in `[0, MAX_NAU]`
    /// cannot add to less than zero -- so those cases put the negative on one
    /// operand and leave the other at zero, making the sum equal to it.
    #[proptest(cases = 4)]
    fn fee_sum_outside_the_valid_range_is_rejected(
        #[strategy(pokeable_witness())] witness: ChainWitness,
    ) {
        let max = NativeCurrencyAmount::MAX_NAU;

        // one nau over the maximum
        expect_fee_failure(witness.clone(), max, 1, max + 1);
        expect_fee_failure(witness.clone(), 1, max, max + 1);

        // one nau below zero
        expect_fee_failure(witness.clone(), -1, 0, -1);
        expect_fee_failure(witness.clone(), 0, -1, -1);
    }

    /// A negative operand fee is rejected even when the sum it produces is a
    /// valid amount -- the case the range check above cannot reach, and the only
    /// thing standing in its way is the assert that the `u128` addition did not
    /// carry.
    ///
    /// This is where `Chain` parts ways with `merge_branch`, which *pops* that
    /// carry (`merge_branch.rs:520`) precisely so a negative fee on its LHS
    /// wraps and adds correctly. So it is also the test that pins the
    /// consequence: fee-gobbling has to happen on standard transactions,
    /// because a negative-fee `LinkTx` can never be chained.
    #[proptest(cases = 4)]
    fn negative_operand_fee_is_rejected_even_when_the_sum_is_valid(
        #[strategy(pokeable_witness())] witness: ChainWitness,
    ) {
        expect_fee_failure(witness.clone(), -1, 2, 1);
        expect_fee_failure(witness.clone(), 2, -1, 1);
    }

    /// The chained fee is the operands' fees added up -- no more (a fee the
    /// operands never paid is minted out of nothing) and no less (short-changing
    /// the miner while the operands' balances still say otherwise).
    #[proptest(cases = 4)]
    fn chained_fee_must_be_the_sum_of_the_operand_fees(
        #[strategy(pokeable_witness())] original: ChainWitness,
    ) {
        let one_nau = NativeCurrencyAmount::one_nau();
        let base_fee = original.new_kernel.kernel.fee;

        // A drawn fixture may chain to a zero fee, which has no room to go
        // down. Rejected rather than clamped: the point is that the equation is
        // tight in *both* directions, and a case that only tests one of them
        // would pass while saying less than the test name claims.
        prop_assume!(base_fee >= one_nau);

        for fee in [
            base_fee + one_nau,
            base_fee
                .checked_sub(&one_nau)
                .expect("fee stays non-negative"),
        ] {
            let mut witness = original.clone();
            witness.new_kernel.kernel = TransactionKernelModifier::default()
                .fee(fee)
                .modify(witness.new_kernel.kernel);

            expect_failure(witness, &[NEW_FEE_IS_NOT_SUM_OF_OPERAND_FEES_ERROR]).unwrap();
        }
    }

    /// A chained transaction is no older than the later of its operands --
    /// otherwise chaining would be a way to walk a transaction backwards past a
    /// time lock.
    #[proptest(cases = 4)]
    fn chained_timestamp_must_be_the_later_of_the_operand_timestamps(
        #[strategy(pokeable_witness())] mut witness: ChainWitness,
    ) {
        let timestamp = witness.new_kernel.kernel.timestamp - Timestamp::seconds(1);
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .timestamp(timestamp)
            .modify(witness.new_kernel.kernel);

        expect_failure(witness, &[TIMESTAMP_IS_NOT_MAX_OF_OPERAND_TIMESTAMPS_ERROR]).unwrap();
    }

    /// All three kernels are relative to one and the same mutator set.
    #[proptest(cases = 4)]
    fn mismatched_mutator_set_hash_is_rejected(
        #[strategy(pokeable_witness())] mut witness: ChainWitness,
    ) {
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .mutator_set_hash(Digest::default())
            .modify(witness.new_kernel.kernel);

        expect_failure(witness, &[MUTATOR_SET_HASH_MISMATCH_ERROR]).unwrap();
    }

    /// A chained transaction is never a coinbase transaction and never carries
    /// the merge bit. Both leafs are constants the branch authenticates
    /// directly, so a kernel holding anything else has the wrong leaf, not
    /// merely the wrong value.
    #[proptest(cases = 4)]
    fn coinbase_or_merge_bit_on_the_chained_kernel_is_rejected(
        #[strategy(pokeable_witness())] original: ChainWitness,
    ) {
        let mut witness = original.clone();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .coinbase(Some(NativeCurrencyAmount::coins(1)))
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();

        let mut witness = original.clone();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .merge_bit(true)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();
    }

    /// Every field the branch reads is bound to the kernel it was read from: a
    /// bad authentication path fails before any of the equations above get a
    /// chance to hold.
    #[proptest(cases = 4)]
    fn bad_authentication_path_is_rejected(#[strategy(pokeable_witness())] witness: ChainWitness) {
        let mut nondeterminism = witness.nondeterminism();
        nondeterminism.digests[0].0[0].increment();

        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                nondeterminism,
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            )
            .unwrap();
    }

    /// The chained kernel is bound to the claim: `Chain` authenticates the new
    /// kernel's fields against `lkmh` straight off the public input, so a
    /// witness proven against some *other* transaction's kernel fails at the
    /// first field.
    #[proptest(cases = 4)]
    fn chained_kernel_must_be_the_one_in_the_claim(
        #[strategy(pokeable_witness())] witness: ChainWitness,
    ) {
        let other_lkmh = witness.left_kernel.mast_hash();

        LinkProof
            .test_assertion_failure(
                link_proof_public_input(other_lkmh, witness.single_proof_digest),
                witness.nondeterminism(),
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            )
            .unwrap();
    }

    /// The kernel MAST hash is *divined*, and the field authentication only tie
    /// that hash to witness data the prover supplies too. Without a valid
    /// proof, that data is still unauthenticated. Every other negative here runs
    /// on mock proofs and would pass with the recursion deleted; this is the
    /// one that would not.
    ///
    /// Swapping the two proofs leaves the kernels, and hence every
    /// authentication path, untouched: the only thing broken is which proof
    /// attests to which operand.
    #[tokio::test]
    async fn operand_proof_must_attest_to_its_own_operand() {
        let (predecessor, successor) = deterministic_chainable_link_primitive_witnesses(2, 1);
        let d = mock_single_proof_digest(0);
        let mut witness = ChainWitness::chain(
            forge(&predecessor, d).await,
            forge(&successor, d).await,
            d,
            [0u8; 32],
        );
        assert_ne!(
            witness.left_kernel.mast_hash(),
            witness.right_kernel.mast_hash(),
            "the two operands must be distinguishable for the swap to be a tamper"
        );

        // The nondeterminism is the *un*swapped witness's -- its digest stream
        // is extracted per (proof, claim) pair, which only makes sense for the
        // pairing the proofs were made for. Swapping in memory afterwards is
        // what the branch sees, and it is exactly the prover freedom under
        // test: any proof, in any slot.
        let mut nondeterminism = witness.nondeterminism();
        std::mem::swap(&mut witness.left_proof, &mut witness.right_proof);
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &LinkProofWitnessMemory::Chain(Box::new(witness.clone())),
        );

        let input = witness.standard_input();
        LinkProof
            .run_rust(&input, nondeterminism.clone())
            .unwrap_err();

        // Where it fails is the point: an earlier assertion would make this
        // test pass without the recursion ever running, which is the very
        // vacuity it exists to rule out. (The rust shadow's panic message does
        // not survive `catch_unwind`, so only the tasm side can be pinned.)
        let Err(TritonError::TritonVMPanic(vm_state, _)) =
            LinkProof.run_tasm(&input, nondeterminism)
        else {
            panic!("`Chain` must reject a proof that attests to the other operand");
        };
        assert!(
            vm_state.contains("stark_verify"),
            "must fail in the recursive verification, not before it:\n{vm_state}"
        );
    }

    /// `D` is *in* the operand claims, and it is the one off the public input.
    ///
    /// The operands here are proven under `D'`, and everything -- witness,
    /// nondeterminism, authentication paths -- is built consistently around
    /// `D'`; only the claim the chain is run against names `D`. Both ways of
    /// getting `D` wrong therefore fail this test: a branch that dropped `D`
    /// from the operand claims, and a branch that took it from the witness
    /// instead of the public input, would each verify the operands happily.
    ///
    /// Only the left operand needs its own test. `verify_operand` is one closure
    /// applied to both, reading `D` from the same static address either time, so
    /// the per-operand copy-paste slip has nowhere to live.
    #[tokio::test]
    async fn operand_forged_under_another_single_proof_digest_is_rejected() {
        let (predecessor, successor) = deterministic_chainable_link_primitive_witnesses(2, 1);
        let other_d = mock_single_proof_digest(1);
        let witness = ChainWitness::chain(
            forge(&predecessor, other_d).await,
            forge(&successor, other_d).await,
            other_d,
            [0u8; 32],
        );

        // The claim, and only the claim, names the real `D`. `lkmh` is
        // untouched, so every field authentication still passes and the branch
        // gets all the way to the recursion.
        let input =
            link_proof_public_input(witness.kernel_mast_hash(), mock_single_proof_digest(0));
        let nondeterminism = witness.nondeterminism();
        LinkProof
            .run_rust(&input, nondeterminism.clone())
            .unwrap_err();

        let Err(TritonError::TritonVMPanic(vm_state, _)) =
            LinkProof.run_tasm(&input, nondeterminism)
        else {
            panic!("`Chain` must reject an operand proven under another `D`");
        };
        assert!(
            vm_state.contains("stark_verify"),
            "must fail in the recursive verification, not before it:\n{vm_state}"
        );
    }

    /// One operand good, one junk -- in each direction. Both slots are verified.
    ///
    /// `Chain` does not *compare* two digests; there is only one `D`. It is read
    /// from the public input into a single static slot, and
    /// `generate_link_proof_claim` appends that one value to both operand
    /// claims, so mixed provenance is unrepresentable rather than rejected: two
    /// operands cannot disagree about a digest neither of them supplies. That is
    /// the structural half of the argument, and it needs no test.
    ///
    /// What does need one is that both claims are actually *checked*. Every
    /// other operand negative corrupts both operands at once --
    /// [`operand_forged_under_another_single_proof_digest_is_rejected`] forges
    /// each under `D'`, [`operand_proof_must_attest_to_its_own_operand`] swaps
    /// them -- so verifying the left operand alone would trip all of them, and
    /// deleting the right `verify_operand` call would go unnoticed by the entire
    /// suite. Here exactly one operand is junk, so the surviving verification is
    /// the only thing that can fire, and running it both ways round pins the two
    /// slots independently.
    ///
    /// Costs cache hits rather than forges: both digests over both operands are
    /// proofs the tests around it already make.
    ///
    /// The non-determinism is a *consistent* witness's, and the junk operand is
    /// substituted afterwards -- the same construction
    /// [`operand_proof_must_attest_to_its_own_operand`] uses, and for the same
    /// reason: the digest stream is extracted per (proof, claim) pair, so it can
    /// only be built for operands that answer their claims. A prover holding
    /// only an `other_d` proof is in exactly this position. It also sharpens the
    /// test -- if the substituted operand's verification were skipped, its proof
    /// would never be read and the leftover stream would go unused, so the run
    /// would succeed.
    ///
    /// Only the tasm is run, unlike its neighbours: the rust shadow's
    /// `verify_stark` unwraps FRI errors, so it aborts rather than returning.
    /// That is the shadow's error handling, not the branch's behaviour.
    #[tokio::test]
    async fn each_operand_is_verified_against_the_claims_d() {
        let (predecessor, successor) = deterministic_chainable_link_primitive_witnesses(2, 1);
        let d = mock_single_proof_digest(0);
        let other_d = mock_single_proof_digest(1);

        for junk_on_the_right in [false, true] {
            let mut witness = ChainWitness::chain(
                forge(&predecessor, d).await,
                forge(&successor, d).await,
                d,
                [0u8; 32],
            );
            let mut nondeterminism = witness.nondeterminism();

            let junk = if junk_on_the_right {
                forge(&successor, other_d).await
            } else {
                forge(&predecessor, other_d).await
            };
            let LinkTxProof::Proof(junk_proof) = junk.proof else {
                unreachable!("`forge` produces a proof-backed link transaction")
            };
            if junk_on_the_right {
                witness.right_proof = junk_proof;
            } else {
                witness.left_proof = junk_proof;
            }
            encode_to_memory(
                &mut nondeterminism.ram,
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                &LinkProofWitnessMemory::Chain(Box::new(witness.clone())),
            );

            let input = witness.standard_input();
            let Err(TritonError::TritonVMPanic(vm_state, _)) =
                LinkProof.run_tasm(&input, nondeterminism)
            else {
                panic!("`Chain` must verify both operands against the claim's `D`");
            };
            assert!(
                vm_state.contains("stark_verify"),
                "must fail in the recursive verification, not before it:\n{vm_state}"
            );
        }
    }

    /// The converse: `D` sits in the witness's memory image, and the branch must
    /// never look at it.
    ///
    /// Poked to a value the operand proofs were *not* made under, while the
    /// public input keeps the real one. A branch that divined `D` from the
    /// witness would build two claims no proof answers and fail; this one
    /// passes, which is the guard, not the accident.
    ///
    /// It also pins the dispatcher-to-branch handoff, which nothing else does.
    /// The rust shadow takes `D` as an argument, the way it takes
    /// `own_program_digest` and `lkmh`; the tasm reads it out of the static slot
    /// the dispatcher wrote. Running *both* over real operand proofs, with a
    /// third `D` in the witness so neither side can be reading that one, is what
    /// says the two routes deliver the same digest. Verified by mutation:
    /// shifting the branch's read address by one word leaves `run_rust` happy
    /// and fails `run_tasm` inside `stark_verify`. Keep both runs, and keep the
    /// witness's `D` distinct from the claim's, or that coverage goes away
    /// silently.
    #[tokio::test]
    async fn witness_supplied_single_proof_digest_is_ignored() {
        let (predecessor, successor) = deterministic_chainable_link_primitive_witnesses(2, 1);
        let d = mock_single_proof_digest(0);
        let mut witness = ChainWitness::chain(
            forge(&predecessor, d).await,
            forge(&successor, d).await,
            d,
            [0u8; 32],
        );

        // Both derived from the honest witness, before the poke: the claim the
        // operands answer, and the digest stream extracted against it.
        let input = witness.standard_input();
        let mut nondeterminism = witness.nondeterminism();

        witness.single_proof_digest = mock_single_proof_digest(1);
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &LinkProofWitnessMemory::Chain(Box::new(witness)),
        );

        LinkProof.run_rust(&input, nondeterminism.clone()).unwrap();
        LinkProof.run_tasm(&input, nondeterminism).unwrap();
    }
}
