use std::collections::HashMap;

use itertools::Itertools;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::commit;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::timestamp::Timestamp;
use tasm_lib::arithmetic::u64::incr::Incr;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::list::higher_order::inner_function::InnerFunction;
use tasm_lib::list::higher_order::inner_function::RawCode;
use tasm_lib::list::higher_order::map::ChainMap;
use tasm_lib::list::multiset_equality_digests::MultisetEqualityDigests;
use tasm_lib::list::push::Push;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::verify_from_secret_in_leaf_index_on_stack::MmrVerifyFromSecretInLeafIndexOnStack;
use tasm_lib::mmr::verify_mmr_successor::VerifyMmrSuccessor;
use tasm_lib::neptune::mutator_set;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Digest;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_successor_proof::MmrSuccessorProof;
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
use super::link_proof_witness::DISCRIMINANT_FOR_UPDATE;
use super::link_tx::LinkTx;
use super::link_tx::LinkTxProof;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::validity::tasm::compute_absolute_indices::ComputeAbsoluteIndices;
use crate::transaction::validity::tasm::hash_removal_record_index_sets::HashRemovalRecordIndexSets;
use crate::transaction::validity::tasm::leaf_authentication::authenticate_msa_against_txk::AuthenticateMsaAgainstTxk;

const NEW_TIMESTAMP_IS_OLDER_THAN_OLD_ERROR: i128 = 1_000_561;
const PROMOTED_THRUPUTS_DO_NOT_MATCH_ERROR: i128 = 1_000_562;
const PROMOTED_INDEX_SETS_DO_NOT_MATCH_ERROR: i128 = 1_000_563;
const PROMOTIONS_ARE_NOT_ASCENDING_ERROR: i128 = 1_000_564;

/// One promoted thruput.
///
/// The old kernel carries a thruput (and addition record) and this thruput
/// becomes a proper input (now removal record) in the new kernel.
///
/// Carries exactly what it takes to derive *both* sides of that move --
/// the addition record or the absolute index set.
///
/// The `(item, sender_randomness, receiver_preimage, aocl_leaf_index)` shape is
/// `Forge`'s confirmed-input loop verbatim -- promotion is that loop run
/// against the *new* AOCL, on records that were thruputs a moment ago.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
pub struct Promotion {
    pub(super) item: Digest,
    pub(super) sender_randomness: Digest,
    pub(super) receiver_preimage: Digest,

    /// In the new AOCL.
    pub(super) aocl_leaf_index: u64,

    /// Relative to the new AOCL.
    pub(super) aocl_auth_path: MmrMembershipProof,
}

impl Promotion {
    /// The addition record that leaves the old kernel's thruput list.
    pub(super) fn addition_record(&self) -> AdditionRecord {
        commit(
            self.item,
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
    }

    /// The absolute index set that joins the new kernel's input list.
    pub(super) fn absolute_indices(&self) -> AbsoluteIndexSet {
        AbsoluteIndexSet::compute(
            self.item,
            self.sender_randomness,
            self.receiver_preimage,
            self.aocl_leaf_index,
        )
    }
}

/// The witness consumed by [`Update`].
///
/// Holds the out-of-date [`LinkKernel`] and its link proof, the re-targeted
/// kernel, both mutator set accumulators in the pre-reduced form
/// [`AuthenticateMsaAgainstTxk`] eats, and the proof that the new AOCL extends
/// the old one.
///
/// Transaction-chaining analog of
/// [`UpdateWitness`](crate::transaction::validity::tasm::single_proof::update_branch::UpdateWitness),
/// and -- like [`ChainWitness`](super::chain::ChainWitness) -- its own memory
/// image: everything it carries is read from RAM.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
pub struct UpdateWitness {
    pub(super) old_kernel: LinkKernel,
    pub(super) new_kernel: LinkKernel,

    pub(super) old_aocl: MmrAccumulator,
    pub(super) old_swbfi_bagged: Digest,
    pub(super) old_swbfa_hash: Digest,

    pub(super) new_aocl: MmrAccumulator,
    pub(super) new_swbfi_bagged: Digest,
    pub(super) new_swbfa_hash: Digest,

    pub(super) aocl_successor_proof: MmrSuccessorProof,

    /// The set of thruputs that are being promoted to inputs.
    ///
    /// Strictly ascending by `aocl_leaf_index`. Allowed to be empty.
    pub(super) promotions: Vec<Promotion>,

    pub(super) old_proof: Proof,

    /// The `SingleProof` program digest `D` this update is claimed under, and
    /// which the old link proof must have been made under too.
    ///
    /// Rust-side only, exactly as in [`ChainWitness`](super::chain::ChainWitness):
    /// it is here to build the public input and the operand claim, while the
    /// tasm branch reads `D` off the public input. `Update` re-targets the
    /// *mutator set*; `D` it only passes through.
    pub(super) single_proof_digest: Digest,
}

impl UpdateWitness {
    /// Re-target an out-of-date [`LinkTx`] at a newer mutator set.
    ///
    /// The new kernel must be identical to the old except for:
    ///  - mutator set hash
    ///  - removal records
    ///  - promotions
    ///  - a later timestamp.
    ///
    /// All bullet points are optional, but some change is mandatory.
    ///
    /// The `old` kernel must be backed by a `LinkProof` relative to SingleProof
    /// digest D. That digest goes into the claim that is being verified. It is
    /// also what the resulting `LinkProof` is relative to.
    pub fn update(
        old: LinkTx,
        old_msa: &MutatorSetAccumulator,
        new_kernel: LinkKernel,
        new_msa: &MutatorSetAccumulator,
        aocl_successor_proof: MmrSuccessorProof,
        promotions: Vec<Promotion>,
        single_proof_digest: Digest,
    ) -> Self {
        let LinkTxProof::Proof(old_proof) = old.proof else {
            panic!("cannot update a link transaction that is not backed by a link proof");
        };
        assert_eq!(
            old.kernel.kernel.mutator_set_hash,
            old_msa.hash(),
            "the old kernel must name the old mutator set"
        );
        assert_eq!(
            new_kernel.kernel.mutator_set_hash,
            new_msa.hash(),
            "the new kernel must name the new mutator set"
        );

        // The two promotion equations, up to order, plus the per-entry AOCL
        // membership: exactly what `Update` asserts, checked here so a bad
        // witness fails in milliseconds instead of after a proof.
        let sorted = |digests: Vec<Digest>| digests.into_iter().sorted().collect_vec();
        let commitments = |ars: &[AdditionRecord]| -> Vec<Digest> {
            ars.iter().map(|ar| ar.canonical_commitment).collect()
        };
        let index_sets = |rrs: &[RemovalRecord]| -> Vec<Digest> {
            rrs.iter()
                .map(|rr| Tip5::hash(&rr.absolute_indices))
                .collect()
        };
        let promoted_addition_records = promotions
            .iter()
            .map(|p| p.addition_record().canonical_commitment)
            .collect_vec();
        let promoted_index_sets = promotions
            .iter()
            .map(|p| Tip5::hash(&p.absolute_indices()))
            .collect_vec();
        assert_eq!(
            sorted(commitments(&old.kernel.thruputs)),
            sorted([commitments(&new_kernel.thruputs), promoted_addition_records].concat()),
            "the promoted addition records must be exactly the thruputs the new kernel drops"
        );
        assert_eq!(
            sorted(index_sets(&new_kernel.kernel.inputs)),
            sorted([index_sets(&old.kernel.kernel.inputs), promoted_index_sets].concat()),
            "the promoted index sets must be exactly the ones the new inputs add"
        );
        assert!(
            promotions
                .iter()
                .map(|p| p.aocl_leaf_index)
                .tuple_windows()
                .all(|(l, r)| l < r),
            "promotions must be sorted by strictly ascending AOCL leaf index"
        );
        for promotion in &promotions {
            assert!(
                promotion.aocl_auth_path.verify(
                    promotion.aocl_leaf_index,
                    promotion.addition_record().canonical_commitment,
                    &new_msa.aocl.peaks(),
                    new_msa.aocl.num_leafs(),
                ),
                "a promoted thruput must be confirmed in the new AOCL"
            );
        }

        Self {
            old_kernel: old.kernel,
            new_kernel,
            old_aocl: old_msa.aocl.clone(),
            old_swbfi_bagged: old_msa.swbf_inactive.bag_peaks(),
            old_swbfa_hash: Tip5::hash(&old_msa.swbf_active),
            new_aocl: new_msa.aocl.clone(),
            new_swbfi_bagged: new_msa.swbf_inactive.bag_peaks(),
            new_swbfa_hash: Tip5::hash(&new_msa.swbf_active),
            aocl_successor_proof,
            promotions,
            old_proof,
            single_proof_digest,
        }
    }

    /// MAST hash of the re-targeted [`LinkKernel`]: the public input of the
    /// `LinkProof` claim this witness is proven against.
    pub(super) fn kernel_mast_hash(&self) -> Digest {
        self.new_kernel.mast_hash()
    }

    /// The claim the old link proof is verified against: this very program, on
    /// the old kernel's MAST hash, under the same `D`.
    fn old_claim(&self) -> Claim {
        let input = link_proof_public_input(self.old_kernel.mast_hash(), self.single_proof_digest);
        Claim::new(LinkProof.hash()).with_input(input.individual_tokens)
    }
}

impl SecretWitness for UpdateWitness {
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
        // `Update` is a branch of `LinkProof`, so the memory image is that of
        // the enum variant's associated data: field size, then the payload.
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &LinkProofWitnessMemory::Update(Box::new(self.clone())),
        );

        // The old kernel's MAST hash is divined -- bound to the old link proof
        // by the recursive verification, and to the fields read out of the
        // witness by the authentication paths below.
        let individual_tokens = self.old_kernel.mast_hash().reversed().values().to_vec();
        let mut nondeterminism = NonDeterminism::new(individual_tokens).with_ram(memory);

        // The digest stream is consumed in program order. First the two mutator
        // set authentications, old then new.
        nondeterminism.digests.extend(
            [
                self.old_kernel.mast_path(LinkKernelField::MutatorSetHash),
                self.new_kernel.mast_path(LinkKernelField::MutatorSetHash),
            ]
            .concat(),
        );

        // Then the AOCL successor proof, which appends to *both* streams: its
        // first authentication path goes in as individual tokens, and lands
        // after the divined kernel MAST hash, which is the order the branch
        // reads them in.
        VerifyMmrSuccessor::update_nondeterminism(&mut nondeterminism, &self.aocl_successor_proof);

        // Then the field authentications, old kernel then new kernel per field,
        // and finally the new kernel's two constant leafs. Inputs and thruputs
        // come first and together: the promotion equations need both.
        let per_kernel = |field: LinkKernelField| {
            [
                self.old_kernel.mast_path(field),
                self.new_kernel.mast_path(field),
            ]
            .concat()
        };
        //
        // The promotion loop's AOCL membership proofs, in promotion order, land
        // between the thruputs and the outputs: that is where the loop runs,
        // once the two lists its equations compare are bound to their kernels
        // and before the fields the branch merely carries over. The leaf index
        // and the commitment come off the stack -- the former read out of the
        // entry, the latter computed from it -- so the path is all the loop
        // takes from this stream.
        let promotion_paths = self
            .promotions
            .iter()
            .flat_map(|promotion| promotion.aocl_auth_path.authentication_path.clone())
            .collect_vec();
        nondeterminism.digests.extend(
            [
                per_kernel(LinkKernelField::Inputs),
                per_kernel(LinkKernelField::Thruputs),
                promotion_paths,
                per_kernel(LinkKernelField::Outputs),
                per_kernel(LinkKernelField::Announcements),
                per_kernel(LinkKernelField::Fee),
                per_kernel(LinkKernelField::Timestamp),
                self.new_kernel.mast_path(LinkKernelField::Coinbase),
                self.new_kernel.mast_path(LinkKernelField::MergeBit),
            ]
            .concat(),
        );

        // Then the recursive link-proof verification, which the branch does
        // last. A mock proof has no proof stream to extract nondeterminism
        // from, and never reaches a real `StarkVerify` either: in the negative
        // tests some earlier assertion fires first, the recursion being this
        // branch's last act.
        if !self.old_proof.is_mock() {
            StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
                &mut nondeterminism,
                &self.old_proof,
                &self.old_claim(),
            );
        }

        nondeterminism
    }
}

/// `Update: LinkTx -> LinkTx`: re-target a link transaction at a newer mutator
/// set without re-forging it.
///
/// `Update` recursively verifies the old link proof -- against a claim that
/// names `LinkProof` itself, taken from the dispatcher's copy of the own program
/// digest -- and then establishes that the new kernel is the old one moved
/// forward, and nothing else:
///
/// - both kernels' mutator set accumulators are authenticated against their own
///   MAST hashes, and the new AOCL is a successor of the old one;
/// - the inputs' absolute index sets are unchanged -- the removal records
///   themselves may differ, since re-targeting rewrites their membership data,
///   but what a double spend collides on may not move;
/// - outputs, thruputs, announcements and the fee are byte-for-byte the same in
///   both kernels;
/// - the timestamp does not go backwards;
/// - the new kernel carries no coinbase and no merge bit.
///
/// The old kernel's coinbase and merge-bit leafs are deliberately *not*
/// re-checked: every branch producing a `LinkProof` asserts both on the kernel
/// it produces, so an operand that verifies has them by induction.
///
/// Thruputs are either a) carried across unchanged, or b) promoted into inputs.
/// (Right now (b) is not supported yet.)
///
/// Unlike its legacy sibling, `Update` does *not* require a non-empty input set.
/// A `LinkTx` may legitimately have zero confirmed inputs -- an all-thruputs
/// link, funded entirely by its predecessors -- and such a link still has to
/// follow the mutator set, because `Chain` requires all three of its kernels to
/// agree on the mutator set hash. Refusing to update it would strand it the
/// moment any chain partner moved.
#[derive(Debug, Copy, Clone)]
pub struct Update {
    /// Where the dispatcher stashed the `SingleProof` program digest `D` it read
    /// off the public input. `Update` copies it verbatim into the old kernel's
    /// claim; see [`LinkProof`].
    pub(super) single_proof_digest_address: BFieldElement,
}

impl BasicSnippet for Update {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "link_kernel_mast_hash".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "discriminant".to_string()),
        ]
    }

    /// The digest slot is the dispatcher's scratch space, not a return value;
    /// this branch leaves the new kernel's MAST hash there. See `LinkProof`.
    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "dispatcher_scratch".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "minus_1".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_chaintx_link_proof_update_branch".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let audit_preloaded_data =
            library.import(Box::new(VerifyNdSiIntegrity::<UpdateWitness>::default()));
        let generate_link_proof_claim = library.import(Box::new(GenerateLinkProofClaim {
            single_proof_digest_address: self.single_proof_digest_address,
        }));
        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let multiset_equality = library.import(Box::new(MultisetEqualityDigests));
        let hash_removal_record_index_sets =
            library.import(Box::new(HashRemovalRecordIndexSets::<1>));
        let authenticate_msa = library.import(Box::new(AuthenticateMsaAgainstTxk {
            mast_height: LinkKernel::MAST_HEIGHT as u32,
        }));
        let verify_mmr_successor = library.import(Box::new(VerifyMmrSuccessor));
        let lt_u64 = library.import(Box::new(tasm_lib::arithmetic::u64::lt::Lt));
        let increment_u64 = library.import(Box::new(Incr));
        let ms_commit = library.import(Box::new(mutator_set::commit::Commit));
        let mmr_verify = library.import(Box::new(MmrVerifyFromSecretInLeafIndexOnStack));
        let compute_absolute_indices = library.import(Box::new(ComputeAbsoluteIndices));
        let hash_absolute_indices = library.import(Box::new(HashStaticSize {
            size: AbsoluteIndexSet::static_length().expect("absolute indices have a static size"),
        }));
        let list_push_digest = library.import(Box::new(Push::new(DataType::Digest)));

        // Copying a list of digests is a `Map` whose function is the identity:
        // it is how the right-hand side of the thruput equation gets a list it
        // may grow, without touching the kernel's own.
        let copy_digests = library.import(Box::new(ChainMap::<1>::new(InnerFunction::RawCode(
            RawCode::new(
                triton_asm!(neptune_consensus_chaintx_update_copy_digest: return),
                DataType::Digest,
                DataType::Digest,
            ),
        ))));

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

        let digest_len = u32::try_from(Digest::LEN).unwrap();
        let old_lkmh_alloc = library.kmalloc(digest_len);
        let new_lkmh_alloc = library.kmalloc(digest_len);
        let old_lkmh = old_lkmh_alloc.read_address();
        let new_lkmh = new_lkmh_alloc.read_address();

        // The promotion loop carries its whole state on the stack -- no static
        // memory. The invariant consists of eight words:
        //
        //     _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si
        //
        // Everything the body reads is either one of those or a field of the
        // entry the cursor is on, and the body's deepest reach is `dup 14`, so
        // the whole loop stays inside the sixteen addressable stack words.
        let promotion_loop = "neptune_consensus_chaintx_update_promotion_loop".to_string();
        let u64_stack_size = u32::try_from(DataType::U64.stack_size()).unwrap();

        let field_old_kernel = field!(UpdateWitness::old_kernel);
        let field_new_kernel = field!(UpdateWitness::new_kernel);
        let field_old_aocl = field!(UpdateWitness::old_aocl);
        let field_old_swbfi_bagged = field!(UpdateWitness::old_swbfi_bagged);
        let field_old_swbfa_hash = field!(UpdateWitness::old_swbfa_hash);
        let field_new_aocl = field!(UpdateWitness::new_aocl);
        let field_new_swbfi_bagged = field!(UpdateWitness::new_swbfi_bagged);
        let field_new_swbfa_hash = field!(UpdateWitness::new_swbfa_hash);
        let field_old_proof = field!(UpdateWitness::old_proof);
        let field_promotions = field!(UpdateWitness::promotions);

        let field_item = field!(Promotion::item);
        let field_sender_randomness = field!(Promotion::sender_randomness);
        let field_receiver_preimage = field!(Promotion::receiver_preimage);
        let field_aocl_leaf_index = field!(Promotion::aocl_leaf_index);

        let field_peaks = field!(MmrAccumulator::peaks);
        let field_leaf_count = field!(MmrAccumulator::leaf_count);

        // A `LinkKernel` composes a legacy `TransactionKernel`, so every legacy
        // field is reached through this one extra hop.
        let field_inner_kernel = field!(LinkKernel::kernel);
        let field_with_size_thruputs = field_with_size!(LinkKernel::thruputs);
        let field_with_size_inputs = field_with_size!(TransactionKernel::inputs);
        let field_with_size_outputs = field_with_size!(TransactionKernel::outputs);
        let field_with_size_announcements = field_with_size!(TransactionKernel::announcements);
        let field_with_size_fee = field_with_size!(TransactionKernel::fee);
        let field_timestamp = field!(TransactionKernel::timestamp);

        let timestamp_size = Timestamp::static_length().unwrap();

        let inner =
            |accessor: &[LabelledInstruction]| triton_asm!({&field_inner_kernel} {&accessor});

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

        // Read one kernel MAST hash out of its static slot.
        let load_lkmh = |address| triton_asm!(push {address} read_mem {Digest::LEN} pop 1);

        // Authenticate *the old kernel's* field against both MAST hashes: one
        // set of bytes, two roots, which is exactly "this field did not change".
        //
        // BEFORE: _ *witness *old_lk *new_lk
        // AFTER:  _ *witness *old_lk *new_lk
        let assert_field_is_unchanged =
            |accessor: &[LabelledInstruction], authenticate: &str| -> Vec<LabelledInstruction> {
                let against = |mast_hash_address| {
                    triton_asm!(
                        // _ *witness *old_lk *new_lk *field size
                        {&load_lkmh(mast_hash_address)}
                        // _ ... *field size [lkmh]

                        dup 6
                        dup 6
                        // _ ... *field size [lkmh] *field size

                        call {authenticate}
                        // _ *witness *old_lk *new_lk *field size
                    )
                };
                triton_asm!(
                    // _ *witness *old_lk *new_lk
                    dup 1
                    {&accessor}
                    // _ *witness *old_lk *new_lk *field size

                    {&against(old_lkmh)}
                    {&against(new_lkmh)}
                    // _ *witness *old_lk *new_lk *field size

                    pop 2
                    // _ *witness *old_lk *new_lk
                )
            };

        // Authenticate one kernel's variable-length field against that kernel's
        // MAST hash and leave the field pointer behind. `kernel_depth` is where
        // the kernel pointer sits when the call is made; it changes because the
        // pointers pile up.
        //
        // BEFORE: _ ...
        // AFTER:  _ ... *field
        let authenticate_and_keep = |kernel_depth: usize,
                                     accessor: &[LabelledInstruction],
                                     authenticate: &str,
                                     mast_hash_address|
         -> Vec<LabelledInstruction> {
            triton_asm!(
                // _ ...
                dup {kernel_depth}
                {&accessor}
                // _ ... *field size

                {&load_lkmh(mast_hash_address)}
                dup 6 dup 6
                call {authenticate}
                // _ ... *field size

                pop 1
                // _ ... *field
            )
        };

        // Read a `Digest` field of the promotion the loop is on. `depth` is
        // where `*promotion` sits at the time of the read.
        let read_digest_field = |depth: usize, accessor: &[LabelledInstruction]| {
            triton_asm!(
                dup {depth}
                {&accessor}
                addi {Digest::LEN - 1}
                read_mem {Digest::LEN}
                pop 1
            )
        };
        let read_leaf_index = |depth: usize| {
            triton_asm!(
                dup {depth}
                {&field_aocl_leaf_index}
                addi 1
                read_mem {u64_stack_size}
                pop 1
            )
        };

        // Promotion: a thruput confirmed since the old mutator set moves into
        // the confirmed inputs. Two coupled equations over the witness-supplied
        // promotion set `P`, both compared as multisets:
        //
        //     old.thruputs          == new.thruputs   ++ addition_records(P)
        //     indexsets(new.inputs) == indexsets(old.inputs) ++ indexsets(P)
        //
        // so an addition record leaves the thruput list if and only if a
        // removal record carrying its index set joins the input list -- the
        // same leaves-one-side-iff-it-leaves-the-other shape as `Chain`'s
        // cut-through. An empty `P` collapses the pair into "thruputs
        // unchanged, index sets unchanged", which is what this branch asserted
        // before promotion, so the old behaviour is the empty case rather than
        // a special one.
        //
        // Each right-hand side is a list the loop appends to: a copy of the new
        // thruputs, and the old inputs' hashed index sets. Appending is safe
        // because every list gets a page of dynamic memory to itself.
        let assert_promotion_equations = triton_asm!(
            // _ *witness *old_lk *new_lk
            {&authenticate_and_keep(1, &inner(&field_with_size_inputs), &authenticate_inputs, old_lkmh)}
            {&authenticate_and_keep(1, &inner(&field_with_size_inputs), &authenticate_inputs, new_lkmh)}
            {&authenticate_and_keep(3, &field_with_size_thruputs, &authenticate_thruputs, old_lkmh)}
            {&authenticate_and_keep(3, &field_with_size_thruputs, &authenticate_thruputs, new_lkmh)}
            // _ *witness *old_lk *new_lk *old_in *new_in *old_thru *new_thru

            /* the loop's state: the accumulator it verifies membership
               against, the two lists it appends to, and the bound the leaf
               indices must climb, which starts at zero so the first promotion
               may name leaf 0 */
            dup 6
            {&field_new_aocl}
            // _ *witness *old_lk *new_lk *old_in *new_in *old_thru *new_thru *new_aocl

            dup 1
            call {copy_digests}
            // _ *witness *old_lk *new_lk *old_in *new_in *old_thru *new_thru *new_aocl *addition_records

            dup 5
            call {hash_removal_record_index_sets}
            // _ *witness *old_lk *new_lk *old_in *new_in *old_thru *new_thru *new_aocl *addition_records *index_sets

            push 0
            push 0
            // _ *witness *old_lk *new_lk *old_in *new_in *old_thru *new_thru *new_aocl *addition_records *index_sets [running_lower_bound]

            dup 11
            {&field_promotions}
            read_mem 1
            addi 2
            // _ *witness *old_lk *new_lk *old_in *new_in *old_thru *new_thru *new_aocl *addition_records *index_sets [running_lower_bound] num *promotions[0]_si

            push 0
            swap 1
            // _ *witness .. *new_thru *new_aocl *addition_records *index_sets [running_lower_bound] num 0 *promotions[0]_si

            call {promotion_loop}
            // _ *witness .. *new_thru *new_aocl *addition_records *index_sets [running_lower_bound] num num *promotions[num]_si

            pop 5
            // _ *witness *old_lk *new_lk *old_in *new_in *old_thru *new_thru *new_aocl *addition_records *index_sets

            /* The first promotion equation: the old kernel's thruputs are
               exactly the new kernel's thruputs together with the promoted
               ones. `*addition_records` is that right-hand side, the loop
               having appended one canonical commitment per promotion to a copy
               of the new thruputs. Nothing needs hashing before the
               comparison, because an `AdditionRecord` is a single canonical
               commitment and a list of them is therefore already a list of
               digests. */
            pick 4
            pick 2
            // _ *witness *old_lk *new_lk *old_in *new_in *new_thru *new_aocl *index_sets *old_thru *new_and_promoted

            call {multiset_equality}
            assert error_id {PROMOTED_THRUPUTS_DO_NOT_MATCH_ERROR}
            // _ *witness *old_lk *new_lk *old_in *new_in *new_thru *new_aocl *index_sets

            /* The second promotion equation: the new kernel's inputs are
               exactly the old kernel's inputs together with the promoted ones.
               `*index_sets` is that right-hand side, the loop having appended
               one hashed index set per promotion to the hashed index sets of
               the old inputs. Removal records are compared by absolute index
               set rather than byte for byte, because the index set is what a
               double spend collides on, and re-targeting is free to rewrite
               everything else about them. */
            pick 3
            call {hash_removal_record_index_sets}
            pick 1
            // _ *witness *old_lk *new_lk *old_in *new_thru *new_aocl *new_in_digests *old_and_promoted

            call {multiset_equality}
            assert error_id {PROMOTED_INDEX_SETS_DO_NOT_MATCH_ERROR}
            // _ *witness *old_lk *new_lk *old_in *new_thru *new_aocl

            pop 3
            // _ *witness *old_lk *new_lk
        );

        // One promoted thruput per iteration: the entry's four fields determine
        // both sides of the move, and the loop puts each side in the list its
        // equation compares.
        //
        // The entries are size-prefixed, `Promotion` being dynamically sized,
        // so the cursor walks them; the four fields the body reads all precede
        // the authentication path, hence sit at static offsets.
        let promotion_loop_code = triton_asm!(
            // INVARIANT: _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si
            {promotion_loop}:
                dup 2 dup 2 eq
                skiz return
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si

                dup 0 addi 1
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion

                /* the addition record leaving the thruputs:
                   commit(item, sender_randomness, H(receiver_preimage)).
                   Inflation-critical: it is what stops a promoted input from
                   spending a UTXO other than the one `Forge` proved. */
                push 0 push 0 push 0 push 0 push 0
                {&read_digest_field(5, &field_receiver_preimage)}
                hash
                // _ ... *promotion [receiver_digest]

                {&read_digest_field(5, &field_sender_randomness)}
                {&read_digest_field(10, &field_item)}
                // _ ... *promotion [receiver_digest] [sender_randomness] [item]

                call {ms_commit}
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion [cc]

                /* it joins the copy of the new thruputs */
                dup 12
                dup 5 dup 5 dup 5 dup 5 dup 5
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion [cc] *addition_records [cc]

                call {list_push_digest}
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion [cc]

                /* "Confirmed since" is membership in the *new* AOCL, the one
                   the new kernel names. Nothing needs to say the record was
                   absent from the old AOCL, and nothing could: MMR
                   non-membership is not cheap. Nor does it matter. The old
                   AOCL is a leaf-index-preserving prefix of the new one, so a
                   commitment already confirmed at the old mutator set is
                   confirmed at the same leaf index in the new one, and its
                   promotion pins the same index set a later confirmation would
                   have. */
                dup 13
                {&field_peaks}
                place {Digest::LEN}
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion *peaks [cc]

                dup 14
                {&field_leaf_count}
                addi 1
                read_mem {u64_stack_size}
                pop 1
                // _ *new_aocl .. *promotions[i]_si *promotion *peaks [cc] [num_leafs]

                {&read_leaf_index(8)}
                // _ *new_aocl .. *promotion *peaks [cc] [num_leafs] [aocl_leaf_index]

                call {mmr_verify}
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion

                /* The promotions must be listed in strictly ascending order
                   of AOCL leaf index. This iteration asserts that its own index
                   is not below the running lower bound, and then raises that
                   bound to its own index plus one, so the next iteration has to
                   name a strictly larger leaf. The `+ 1` cannot wrap, because
                   the membership check above bounds the index below the AOCL's
                   leaf count.

                   The ordering is a means, not an end. What this assertion
                   forbids, at the cost of one u64 comparison per iteration, is
                   two promotions naming the same AOCL leaf.

                   Nothing forbids the production of a `LinkKernel` with two
                   identical thruputs. When promoted, they must name
                   *different* AOCL leaf indices, because otherwise they
                   generate identical absolute index sets. That feature makes
                   the `LinkTx` into a transaction that double-spends itself.
                   Self-double-spending transactions cannot be confirmed into
                   a block, so that non-path is a road to failure anyway -- it
                   just fails faster (and with more defense in depth) here.

                   Distinct thruputs that name the same AOCL leaf index cannot
                   both pass the MMR membership test. */
                dup 5 dup 5
                {&read_leaf_index(2)}
                // _ *new_aocl .. *promotions[i]_si *promotion [running_lower_bound] [aocl_leaf_index]

                call {lt_u64}
                push 0 eq
                assert error_id {PROMOTIONS_ARE_NOT_ASCENDING_ERROR}
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion

                {&read_leaf_index(0)}
                call {increment_u64}
                // _ *new_aocl *addition_records *index_sets [running_lower_bound] num i *promotions[i]_si *promotion [aocl_leaf_index + 1]

                swap 6 pop 1
                swap 6 pop 1
                // _ *new_aocl *addition_records *index_sets [running_lower_bound'] num i *promotions[i]_si *promotion

                /* the absolute index set joining the inputs */
                {&read_leaf_index(0)}
                {&read_digest_field(2, &field_receiver_preimage)}
                {&read_digest_field(7, &field_sender_randomness)}
                {&read_digest_field(12, &field_item)}
                // _ ... *promotion [aocl_leaf_index] [rp] [sr] [item]

                call {compute_absolute_indices}
                call {hash_absolute_indices}
                pop 1
                // _ *new_aocl *addition_records *index_sets [running_lower_bound'] num i *promotions[i]_si *promotion [index_set_digest]

                dup 11
                place {Digest::LEN}
                call {list_push_digest}
                // _ *new_aocl *addition_records *index_sets [running_lower_bound'] num i *promotions[i]_si *promotion

                /* advance */
                pop 1
                swap 1 addi 1 swap 1
                // _ *new_aocl *addition_records *index_sets [running_lower_bound'] num (i+1) *promotions[i]_si

                read_mem 1
                addi 2
                add
                // _ *new_aocl *addition_records *index_sets [running_lower_bound'] num (i+1) *promotions[i+1]_si

                recurse
        );

        // Authenticate one kernel's mutator set accumulator against that
        // kernel's MAST hash. The accumulator lives on the witness in the
        // pre-reduced form the snippet eats: the raw AOCL (which it bags
        // itself), the bagged inactive-window peaks, and the active window's
        // hash.
        let authenticate_msa_of = |aocl: &[LabelledInstruction],
                                   swbfi_bagged: &[LabelledInstruction],
                                   swbfa_hash: &[LabelledInstruction],
                                   mast_hash_address|
         -> Vec<LabelledInstruction> {
            triton_asm!(
                // _ *witness *old_lk *new_lk
                dup 2 {&aocl}
                dup 3 {&swbfi_bagged}
                dup 4 {&swbfa_hash}
                // _ *witness *old_lk *new_lk *aocl *swbfi_bagged *swbfa_hash

                {&load_lkmh(mast_hash_address)}
                // _ ... *aocl *swbfi_bagged *swbfa_hash [lkmh]

                call {authenticate_msa}
                // _ *witness *old_lk *new_lk
            )
        };

        // Both kernels name the accumulator they were built against, and the
        // new AOCL only ever grew. The append-only check is what makes an
        // update a move *forward*: without it a transaction could be re-targeted
        // at a mutator set in which its inputs were never spent.
        let assert_mutator_set_moved_forward = triton_asm!(
            // _ *witness *old_lk *new_lk
            {&authenticate_msa_of(
                &field_old_aocl,
                &field_old_swbfi_bagged,
                &field_old_swbfa_hash,
                old_lkmh,
            )}
            {&authenticate_msa_of(
                &field_new_aocl,
                &field_new_swbfi_bagged,
                &field_new_swbfa_hash,
                new_lkmh,
            )}
            // _ *witness *old_lk *new_lk

            dup 2 {&field_old_aocl}
            dup 3 {&field_new_aocl}
            // _ *witness *old_lk *new_lk *old_aocl *new_aocl

            call {verify_mmr_successor}
            // _ *witness *old_lk *new_lk
        );

        // Read one kernel's timestamp, authenticated against that kernel's MAST
        // hash. `kernel_depth` is 1 both times: the stack grows by one word per
        // call, and the kernel pointer being read sinks by one at the same rate.
        let read_and_authenticate_timestamp = |mast_hash_address| {
            triton_asm!(
                // _ ... *lk
                dup 1
                {&inner(&field_timestamp)}
                // _ ... *timestamp

                {&load_lkmh(mast_hash_address)}
                // _ ... *timestamp [lkmh]

                dup 5
                push {timestamp_size}
                call {authenticate_timestamp}
                // _ ... *timestamp

                read_mem 1
                pop 1
                // _ ... timestamp
            )
        };

        // A re-targeted transaction may sit still or move forward in time, but
        // never backwards -- otherwise updating would be a way to walk a
        // transaction back past a time lock.
        let assert_timestamp_does_not_go_backwards = triton_asm!(
            // _ *witness *old_lk *new_lk
            {&read_and_authenticate_timestamp(old_lkmh)}
            // _ *witness *old_lk *new_lk old_timestamp

            {&read_and_authenticate_timestamp(new_lkmh)}
            // _ *witness *old_lk *new_lk old_timestamp new_timestamp

            dup 1 split
            dup 2 split
            call {lt_u64}
            // _ ... old_timestamp new_timestamp (new < old)

            push 0 eq
            assert error_id {NEW_TIMESTAMP_IS_OLDER_THAN_OLD_ERROR}
            // _ *witness *old_lk *new_lk old_timestamp new_timestamp

            pop 2
            // _ *witness *old_lk *new_lk
        );

        // An updated transaction is no more a coinbase transaction, and no more
        // merged, than a forged one: the constant leaf is authenticated
        // directly, which asserts the field's value at the same time (only one
        // preimage hashes to it).
        let authenticate_constant_leaf = |leaf_index: LinkKernelField, leaf: Digest| {
            triton_asm!(
                // _
                {&load_lkmh(new_lkmh)}
                // _ [new_lkmh]

                push {LinkKernel::MAST_HEIGHT}
                push {leaf_index.discriminant() as u32}
                {&push_digest(leaf)}
                // _ [new_lkmh] height index [leaf]

                call {merkle_verify}
                // _
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

            // The old kernel's MAST hash. Free to be anything at this point:
            // the field authentications in between bind it to the witness data,
            // but every input to those is prover-supplied, so they rule out no
            // value. The recursive verification at the very end is what forces
            // it to be a root some link proof attests to.
            divine {Digest::LEN}
            hint old_link_kernel_mast_hash = stack[0..5]
            push {old_lkmh_alloc.write_address()}
            write_mem {Digest::LEN}
            pop 1
            // _ [own_program_digest] disc *witness

            dup 0 {&field_old_kernel}
            dup 1 {&field_new_kernel}
            // _ [own_program_digest] disc *witness *old_lk *new_lk

            {&assert_mutator_set_moved_forward}
            {&assert_promotion_equations}
            {&assert_field_is_unchanged(
                &inner(&field_with_size_outputs),
                &authenticate_outputs,
            )}
            {&assert_field_is_unchanged(
                &inner(&field_with_size_announcements),
                &authenticate_announcements,
            )}
            {&assert_field_is_unchanged(&inner(&field_with_size_fee), &authenticate_fee)}
            {&assert_timestamp_does_not_go_backwards}
            // _ [own_program_digest] disc *witness *old_lk *new_lk

            pop 2
            // _ [own_program_digest] disc *witness

            {&authenticate_constant_leaf(LinkKernelField::Coinbase, no_coinbase_leaf())}
            {&authenticate_constant_leaf(LinkKernelField::MergeBit, merge_bit_false_leaf())}
            // _ [own_program_digest] disc *witness

            /* Last: the recursion. The old kernel is bound to the witness data
               by now; this claim binds it to its link proof. */
            {&load_lkmh(old_lkmh)}
            // _ [own_program_digest] disc *witness [old_lkmh]

            dup 11 dup 11 dup 11 dup 11 dup 11
            // _ [own_program_digest] disc *witness [old_lkmh] [own_program_digest]

            // The claim generator appends `D` itself, reading it from where the
            // dispatcher put the public input. Audit-critical: never divined,
            // never taken from the witness -- a gap there is universal forgery.
            call {generate_link_proof_claim}
            // _ [own_program_digest] disc *witness *claim

            dup 1
            {&field_old_proof}
            // _ [own_program_digest] disc *witness *claim *proof

            call {stark_verify}
            // _ [own_program_digest] disc *witness

            swap 1
            // _ [own_program_digest] *witness disc

            {&load_lkmh(new_lkmh)}
            // _ [own_program_digest] *witness disc [new_lkmh]
            // (the new kernel's MAST hash goes into the dispatcher's scratch
            // slot, which the dispatcher pops unread.)

            pick 6 pick 6
            // _ [own_program_digest] [new_lkmh] *witness disc

            addi {-(DISCRIMINANT_FOR_UPDATE as isize) - 1}
            // _ [own_program_digest] [new_lkmh] *witness -1

            return

            {&promotion_loop_code}
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
    use proptest::strategy::Strategy;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;

    use super::*;
    use crate::chaintx::link_primitive_witness::LinkPrimitiveWitness;
    use crate::chaintx::mock_single_proof_digest;
    pub(super) use crate::chaintx::test_helpers::forge;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;

    /// The `Update` branch of the `LinkProof` rust shadow, called by
    /// [`LinkProof::source`](super::super::link_proof::LinkProof) once it has
    /// read the own program digest, `lkmh` and `D`, and matched the witness
    /// discriminant -- mirroring the tasm, where the dispatcher does exactly
    /// that before `call`ing this branch.
    ///
    /// `single_proof_digest` comes from the dispatcher, i.e. from the public
    /// input. Never from `witness.single_proof_digest`, which is present in the
    /// memory image and must stay unread!
    pub(in crate::chaintx) fn update_branch_source(
        own_program_digest: Digest,
        lkmh: Digest,
        single_proof_digest: Digest,
        witness: UpdateWitness,
    ) {
        /* the old kernel's MAST hash. The field authentications below tie it
        to the old kernel in the witness -- but root, leafs and paths are all
        prover-supplied, so they exclude no *value*. The recursive verification
        at the very end is what forces it to be a root some link proof attests
        to. */
        let old_lkmh: Digest = tasm::tasmlib_io_read_secin___digest();

        let old = &witness.old_kernel;
        let new = &witness.new_kernel;
        let height = LinkKernel::MAST_HEIGHT as u32;
        let authenticate = |root: Digest, field: LinkKernelField, leaf: Digest| {
            tasm::tasmlib_hashing_merkle_verify(root, field.discriminant() as u32, leaf, height);
        };

        /* both kernels name the accumulator they were built against ... */
        let mutator_set_hash = |aocl: &MmrAccumulator, swbfi_bagged: Digest, swbfa_hash: Digest| {
            let left = Tip5::hash_pair(aocl.bag_peaks(), swbfi_bagged);
            let right = Tip5::hash_pair(swbfa_hash, Digest::default());
            Tip5::hash_pair(left, right)
        };
        let old_aocl: MmrAccumulator = witness.old_aocl;
        let new_aocl: MmrAccumulator = witness.new_aocl;
        authenticate(
            old_lkmh,
            LinkKernelField::MutatorSetHash,
            Tip5::hash(&mutator_set_hash(
                &old_aocl,
                witness.old_swbfi_bagged,
                witness.old_swbfa_hash,
            )),
        );
        authenticate(
            lkmh,
            LinkKernelField::MutatorSetHash,
            Tip5::hash(&mutator_set_hash(
                &new_aocl,
                witness.new_swbfi_bagged,
                witness.new_swbfa_hash,
            )),
        );

        /* ... and the new AOCL only ever grew */
        tasm::verify_mmr_successor_proof(&old_aocl, &new_aocl, &witness.aocl_successor_proof);

        /* Inputs and thruputs may both move, but only by promotion. A thruput
        that was confirmed since the old mutator set leaves the thruput list
        if and only if a removal record carrying its index set joins the
        input list. */
        authenticate(
            old_lkmh,
            LinkKernelField::Inputs,
            Tip5::hash(&old.kernel.inputs),
        );
        authenticate(
            lkmh,
            LinkKernelField::Inputs,
            Tip5::hash(&new.kernel.inputs),
        );
        authenticate(
            old_lkmh,
            LinkKernelField::Thruputs,
            Tip5::hash(&old.thruputs),
        );
        authenticate(lkmh, LinkKernelField::Thruputs, Tip5::hash(&new.thruputs));

        let mut new_and_promoted_thruputs: Vec<Digest> = new
            .thruputs
            .iter()
            .map(|ar| ar.canonical_commitment)
            .collect_vec();
        let mut old_and_promoted_index_sets: Vec<Digest> = old
            .kernel
            .inputs
            .iter()
            .map(|rr| Tip5::hash(&rr.absolute_indices))
            .collect_vec();
        let mut previous_leaf_index: u64 = 0;
        let mut i: usize = 0;
        while i < witness.promotions.len() {
            let promotion: &Promotion = &witness.promotions[i];

            /* what leaves the thruputs. Inflation-critical: without it a
            promoted input could spend a UTXO other than the one `Forge`
            proved. */
            let addition_record = commit(
                promotion.item,
                promotion.sender_randomness,
                promotion.receiver_preimage.hash(),
            );

            /* "confirmed since" is membership in the *new* AOCL */
            assert!(tasm::mmr_verify_from_secret_in_leaf_index_on_stack(
                &new_aocl.peaks(),
                new_aocl.num_leafs(),
                promotion.aocl_leaf_index,
                addition_record.canonical_commitment,
            ));

            /* leaf indices climb strictly, which is pairwise distinctness */
            assert!(previous_leaf_index <= promotion.aocl_leaf_index);
            previous_leaf_index = promotion.aocl_leaf_index + 1;

            new_and_promoted_thruputs.push(addition_record.canonical_commitment);
            old_and_promoted_index_sets.push(Tip5::hash(&AbsoluteIndexSet::compute(
                promotion.item,
                promotion.sender_randomness,
                promotion.receiver_preimage,
                promotion.aocl_leaf_index,
            )));

            i += 1;
        }

        let sorted = |digests: Vec<Digest>| digests.into_iter().sorted().collect_vec();
        assert_eq!(
            sorted(
                old.thruputs
                    .iter()
                    .map(|ar| ar.canonical_commitment)
                    .collect_vec()
            ),
            sorted(new_and_promoted_thruputs)
        );
        assert_eq!(
            sorted(
                new.kernel
                    .inputs
                    .iter()
                    .map(|rr| Tip5::hash(&rr.absolute_indices))
                    .collect_vec()
            ),
            sorted(old_and_promoted_index_sets)
        );

        /* everything else is carried over verbatim: one set of bytes, two
        roots */
        let unchanged = |field: LinkKernelField, leaf: Digest| {
            authenticate(old_lkmh, field, leaf);
            authenticate(lkmh, field, leaf);
        };
        unchanged(LinkKernelField::Outputs, Tip5::hash(&old.kernel.outputs));
        unchanged(
            LinkKernelField::Announcements,
            Tip5::hash(&old.kernel.announcements),
        );
        unchanged(LinkKernelField::Fee, Tip5::hash(&old.kernel.fee));

        /* the timestamp may stand still or move forward, never backwards */
        authenticate(
            old_lkmh,
            LinkKernelField::Timestamp,
            Tip5::hash(&old.kernel.timestamp),
        );
        authenticate(
            lkmh,
            LinkKernelField::Timestamp,
            Tip5::hash(&new.kernel.timestamp),
        );
        assert!(new.kernel.timestamp >= old.kernel.timestamp);

        /* an updated transaction is no more a coinbase transaction, and no more
        merged, than a forged one */
        authenticate(lkmh, LinkKernelField::Coinbase, no_coinbase_leaf());
        authenticate(lkmh, LinkKernelField::MergeBit, merge_bit_false_leaf());

        /* last: recursively verify the old link proof */
        let input = link_proof_public_input(old_lkmh, single_proof_digest);
        let claim = Claim::new(own_program_digest).with_input(input.individual_tokens);
        tasm::verify_stark(Stark::default(), &claim, &witness.old_proof);
    }

    /// A link primitive witness together with a mutator set that has grown by
    /// `num_additions` records, and the kernel re-targeted at it.
    ///
    /// Additions only, with the old removal records carried over verbatim, so
    /// the new kernel differs from the old one in nothing but its mutator-set
    /// hash and its timestamp. That is a legal witness whatever the additions
    /// did to the sliding-window Bloom filter -- which they may well have slid,
    /// the window advancing with the AOCL and not with removals: the branch
    /// requires the absolute index sets to match, not the removal records to
    /// have been re-derived. (A real updater would re-derive them. Neither
    /// `Update` nor `update_branch` compels it; a removal record is only made
    /// to answer for itself against a mutator set when the block applies it.)
    ///
    /// The smallest fixture that is still a real update -- the mutator-set hash
    /// moves and the successor proof is a genuine one -- and it leaves the
    /// index-set equation to be broken deliberately, by the negatives below,
    /// rather than incidentally.
    pub(super) fn updatable(
        pw: PrimitiveWitness,
        num_thruputs: usize,
        num_additions: usize,
    ) -> (
        LinkPrimitiveWitness,
        MutatorSetAccumulator,
        LinkKernel,
        MutatorSetAccumulator,
        MmrSuccessorProof,
    ) {
        let lpw = LinkPrimitiveWitness::from_primitive_witness(pw, num_thruputs);

        let old_msa = lpw.mutator_set_accumulator.clone();
        let mut new_msa = old_msa.clone();
        let newly_confirmed = (0..num_additions)
            .map(|i| Digest::new([BFieldElement::new(i as u64 + 1); Digest::LEN]))
            .collect_vec();
        for canonical_commitment in newly_confirmed.iter().copied() {
            new_msa.add(&AdditionRecord::new(canonical_commitment));
        }
        assert_ne!(
            old_msa.aocl.num_leafs(),
            new_msa.aocl.num_leafs(),
            "the mutator set must actually move for the update to be a real one"
        );

        let new_kernel = LinkKernel {
            kernel: TransactionKernelModifier::default()
                .mutator_set_hash(new_msa.hash())
                .timestamp(lpw.kernel.kernel.timestamp + Timestamp::days(1))
                .clone_modify(&lpw.kernel.kernel),
            thruputs: lpw.kernel.thruputs.clone(),
        };

        let successor_proof =
            MmrSuccessorProof::new_from_batch_append(&old_msa.aocl, &newly_confirmed);

        (lpw, old_msa, new_kernel, new_msa, successor_proof)
    }

    /// The pieces of an update that promotes every thruput: an old kernel with
    /// `num_thruputs` of them, a mutator set grown by `num_additions` leafs, and
    /// a new kernel with no thruputs left and a removal record for each.
    ///
    /// The thruputs a [`LinkPrimitiveWitness`] is built with are *reclassified
    /// as confirmed inputs*, so the primitive witness still holds everything a
    /// promotion needs: the UTXO, its membership proof's commitment randomness
    /// and AOCL leaf index, and the very removal record the reclassification
    /// dropped from the kernel. Promotion here is thus the reclassification run
    /// backwards, which is what makes the index sets agree by construction
    /// rather than by fixture arithmetic.
    ///
    /// The promoted records are already in the *old* AOCL, where a real
    /// promotion's would only have landed in the new one. `Update` cannot tell
    /// the difference and deliberately does not try -- membership in the new
    /// AOCL is the whole check -- so the shortcut costs the fixture nothing.
    /// The membership proofs are carried across the appends, since the new
    /// kernel names the grown accumulator and the branch verifies against it.
    pub(super) fn promotable(
        pw: PrimitiveWitness,
        num_thruputs: usize,
        num_additions: usize,
    ) -> (
        LinkPrimitiveWitness,
        MutatorSetAccumulator,
        LinkKernel,
        MutatorSetAccumulator,
        MmrSuccessorProof,
        Vec<Promotion>,
    ) {
        let num_confirmed = pw.input_membership_proofs.len() - num_thruputs;
        let items = pw.input_utxos.utxos[num_confirmed..]
            .iter()
            .map(Tip5::hash)
            .collect_vec();
        let mut membership_proofs = pw.input_membership_proofs[num_confirmed..].to_vec();
        let promoted_removal_records = pw.kernel.inputs[num_confirmed..].to_vec();

        let lpw = LinkPrimitiveWitness::from_primitive_witness(pw, num_thruputs);
        let old_msa = lpw.mutator_set_accumulator.clone();

        let mut new_msa = old_msa.clone();
        let newly_confirmed = (0..num_additions)
            .map(|i| Digest::new([BFieldElement::new(i as u64 + 1); Digest::LEN]))
            .collect_vec();
        for canonical_commitment in newly_confirmed.iter().copied() {
            let addition_record = AdditionRecord::new(canonical_commitment);
            MsMembershipProof::batch_update_from_addition(
                &mut membership_proofs.iter_mut().collect_vec(),
                &items,
                &new_msa,
                &addition_record,
            )
            .unwrap();
            new_msa.add(&addition_record);
        }

        let promotions = membership_proofs
            .iter()
            .zip_eq(&items)
            .map(|(mp, &item)| Promotion {
                item,
                sender_randomness: mp.sender_randomness,
                receiver_preimage: mp.receiver_preimage,
                aocl_leaf_index: mp.aocl_leaf_index,
                aocl_auth_path: mp.auth_path_aocl.clone(),
            })
            .sorted_by_key(|promotion| promotion.aocl_leaf_index)
            .collect_vec();

        let new_kernel = LinkKernel {
            kernel: TransactionKernelModifier::default()
                .mutator_set_hash(new_msa.hash())
                .timestamp(lpw.kernel.kernel.timestamp + Timestamp::days(1))
                .inputs([lpw.kernel.kernel.inputs.clone(), promoted_removal_records].concat())
                .clone_modify(&lpw.kernel.kernel),
            thruputs: vec![],
        };

        let successor_proof =
            MmrSuccessorProof::new_from_batch_append(&old_msa.aocl, &newly_confirmed);

        (
            lpw,
            old_msa,
            new_kernel,
            new_msa,
            successor_proof,
            promotions,
        )
    }

    /// [`updatable`] over the fixed fixture the proof-bearing tests share.
    ///
    /// Deterministic on purpose: same witness and same `D` means the same claim,
    /// hence a proof-cache hit rather than a fresh `Forge`. The mock-proof
    /// negatives draw their fixture at random instead -- they pay no proving
    /// cost, so there is nothing to amortize and everything to gain.
    pub(super) fn deterministic_updatable(
        num_thruputs: usize,
    ) -> (
        LinkPrimitiveWitness,
        MutatorSetAccumulator,
        LinkKernel,
        MutatorSetAccumulator,
        MmrSuccessorProof,
    ) {
        let mut test_runner = TestRunner::deterministic();
        let pw = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        updatable(pw, num_thruputs, 3)
    }

    /// `Update` writes nothing to stdout, so the assertion is that both the Rust
    /// shadow and the tasm run to completion: every `assert` in either one held.
    fn prop_positive(witness: UpdateWitness) {
        LinkProof
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
        LinkProof
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
    }

    /// Re-target a `Forge`d link transaction at a mutator set that has moved on.
    ///
    /// Both mixed shapes the fixture's two confirmed inputs allow: no thruputs
    /// -- an empty list is where a "did not change" check can pass vacuously --
    /// and one of each. The all-thruputs shape gets its own test below.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn update_accepts_a_forged_link_transaction() {
        for num_thruputs in 0..=1 {
            prop_positive(deterministic_update_witness(num_thruputs).await);
        }
    }

    /// Verify that a thruput is promoted if the matching addition record was
    /// confirmed.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn update_promotes_a_confirmed_thruput() {
        for num_thruputs in 1..=2 {
            let witness = deterministic_promotion_witness(num_thruputs).await;
            assert_eq!(
                num_thruputs,
                witness.promotions.len(),
                "the fixture must promote every thruput for this test to be the one it claims"
            );
            assert!(witness.new_kernel.thruputs.is_empty());

            prop_positive(witness);
        }
    }

    /// A link transaction with *no confirmed inputs at all* can be updated.
    ///
    /// This is the shape §Governing invariants commits to. An all-thruputs link
    /// -- one funded entirely by its predecessors -- has no removal records of
    /// its own to re-target, so `update_branch`'s non-empty-input-set
    /// requirement would reject it outright. It still has to follow the mutator
    /// set, because `Chain` requires all three of its kernels to agree on the
    /// mutator set hash, so rejecting it would strand it the moment a chain
    /// partner moved. Its own test, not a loop iteration, because it is the only
    /// thing standing behind that divergence: delete it and the invariant is an
    /// assertion nobody checks.
    ///
    /// Note what it does *not* say. Here the index-set equation compares two
    /// empty multisets and passes without meaning anything -- which is the
    /// intended reading for this shape, and exactly why the negatives below run
    /// on shapes that do have inputs.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn update_accepts_an_all_thruputs_link_transaction() {
        let witness = deterministic_update_witness(2).await;
        assert!(
            witness.old_kernel.kernel.inputs.is_empty(),
            "the fixture must have no confirmed inputs for this test to be the one it claims"
        );

        prop_positive(witness);
    }

    /// `Forge` a deterministic `LinkTx` and build an `UpdateWitness` that
    /// re-targets it.
    ///
    /// Shared by the positive tests, so: cached once + reused often.
    ///
    /// A witness that promotes every one of its `num_thruputs` thruputs.
    ///
    /// Shares [`deterministic_updatable`]'s primitive witness, hence its
    /// `Forge` claim, hence its cached proof: promotion changes the *new*
    /// kernel, and the old link proof is what the proving time goes into.
    async fn deterministic_promotion_witness(num_thruputs: usize) -> UpdateWitness {
        let mut test_runner = TestRunner::deterministic();
        let pw = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let (lpw, old_msa, new_kernel, new_msa, successor_proof, promotions) =
            promotable(pw, num_thruputs, 3);
        let d = mock_single_proof_digest(0);

        UpdateWitness::update(
            forge(&lpw, d).await,
            &old_msa,
            new_kernel,
            &new_msa,
            successor_proof,
            promotions,
            d,
        )
    }

    async fn deterministic_update_witness(num_thruputs: usize) -> UpdateWitness {
        let (lpw, old_msa, new_kernel, new_msa, successor_proof) =
            deterministic_updatable(num_thruputs);
        let d = mock_single_proof_digest(0);

        UpdateWitness::update(
            forge(&lpw, d).await,
            &old_msa,
            new_kernel,
            &new_msa,
            successor_proof,
            vec![],
            d,
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod negative_tests {
    use neptune_mutator_set::addition_record::AdditionRecord;
    use neptune_primitives::timestamp::Timestamp;
    use tasm_lib::hashing::merkle_verify::MerkleVerify;

    use test_strategy::proptest;

    use super::tests::deterministic_updatable;
    use super::tests::forge;
    use super::tests::updatable;
    use super::*;
    use crate::chaintx::mock_single_proof_digest;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::tasm::program::TritonError;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    /// A witness of random contents whose old link proof is a mock.
    ///
    /// Sound for every negative below because the recursion is the *last* thing
    /// the `Update` branch does, so any other assertion fires before a proof is
    /// ever looked at. A positive test cannot use this -- which is also why this
    /// one can afford to be a strategy: no proving cost to amortize, so there is
    /// no reason to hold the fixture still.
    ///
    /// The shape varies over the two the fixture's two inputs allow while
    /// keeping at least one confirmed input, since the index-set negatives need
    /// a record to tamper with. (The zero-confirmed shape is a *positive* case;
    /// it is covered by `update_accepts_a_forged_link_transaction`, which has to
    /// pay for a proof to reach it.)
    fn pokeable_witness() -> proptest::strategy::BoxedStrategy<UpdateWitness> {
        use proptest::strategy::Strategy;

        (
            PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1),
            0usize..=1,
        )
            .prop_map(|(pw, num_thruputs)| {
                let (lpw, old_msa, new_kernel, new_msa, successor_proof) =
                    updatable(pw, num_thruputs, 3);
                UpdateWitness::update(
                    LinkTx {
                        kernel: lpw.kernel.clone(),
                        proof: LinkTxProof::Proof(Proof::invalid_mock()),
                    },
                    &old_msa,
                    new_kernel,
                    &new_msa,
                    successor_proof,
                    vec![],
                    mock_single_proof_digest(0),
                )
            })
            .boxed()
    }

    fn expect_failure(
        witness: UpdateWitness,
        error_ids: &[i128],
    ) -> Result<(), proptest::test_runner::TestCaseError> {
        LinkProof.test_assertion_failure(
            witness.standard_input(),
            witness.nondeterminism(),
            error_ids,
        )
    }

    /// Updating may not walk a transaction backwards in time -- that would make
    /// re-targeting a way past a time lock.
    #[proptest(cases = 4)]
    fn new_timestamp_older_than_old_is_rejected(
        #[strategy(pokeable_witness())] mut witness: UpdateWitness,
    ) {
        let timestamp = witness.old_kernel.kernel.timestamp - Timestamp::seconds(1);
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .timestamp(timestamp)
            .modify(witness.new_kernel.kernel);

        expect_failure(witness, &[NEW_TIMESTAMP_IS_OLDER_THAN_OLD_ERROR]).unwrap();
    }

    /// Tamper with the inputs and verify that it fails.
    ///
    /// With no promotions, an update that touches the removal records is an
    /// update that spends something else. In this test, the inputs are tampered
    /// all three ways the multiset comparison can see: one index changed, one
    /// record dropped, and one record too many.
    #[proptest(cases = 4)]
    fn tampered_absolute_index_set_is_rejected(
        #[strategy(pokeable_witness())] original: UpdateWitness,
    ) {
        let mut witness = original.clone();
        let mut inputs = witness.new_kernel.kernel.inputs.clone();
        inputs[0].absolute_indices.increment_bloom_filter_index(0);
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[PROMOTED_INDEX_SETS_DO_NOT_MATCH_ERROR]).unwrap();

        let mut witness = original.clone();
        let mut inputs = witness.new_kernel.kernel.inputs.clone();
        inputs.pop().unwrap();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[PROMOTED_INDEX_SETS_DO_NOT_MATCH_ERROR]).unwrap();

        let mut witness = original.clone();
        let mut inputs = witness.new_kernel.kernel.inputs.clone();
        inputs.push(inputs[0].clone());
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[PROMOTED_INDEX_SETS_DO_NOT_MATCH_ERROR]).unwrap();
    }

    /// The accumulators on the witness are the ones the kernels name. A poked
    /// AOCL -- old or new -- no longer hashes to the mutator-set-hash leaf it is
    /// authenticated against.
    #[proptest(cases = 4)]
    fn mutator_set_accumulator_must_be_the_one_the_kernel_names(
        #[strategy(pokeable_witness())] witness: UpdateWitness,
    ) {
        for poke_old in [true, false] {
            let mut witness = witness.clone();
            let aocl = if poke_old {
                &mut witness.old_aocl
            } else {
                &mut witness.new_aocl
            };
            aocl.append(Digest::default());

            expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();
        }
    }

    /// Every field that must not change is authenticated with the *old*
    /// kernel's bytes against *both* roots, so any change at all fails the new
    /// kernel's leaf. One poke per field: outputs, announcements, fee.
    ///
    /// Inputs-and-thruputs are the exception, promotion having replaced their
    /// byte equality with a multiset equation: each kernel's list is
    /// authenticated against its own root, so a poked list is a
    /// well-authenticated list that the equation then refuses.
    #[proptest(cases = 4)]
    fn changing_a_carried_over_field_is_rejected(
        #[strategy(pokeable_witness())] original: UpdateWitness,
    ) {
        let record = AdditionRecord::new(Digest::default());

        let mut witness = original.clone();
        let outputs = [witness.new_kernel.kernel.outputs.clone(), vec![record]].concat();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .outputs(outputs)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();

        let mut witness = original.clone();
        witness.new_kernel.thruputs.push(record);
        expect_failure(witness, &[PROMOTED_THRUPUTS_DO_NOT_MATCH_ERROR]).unwrap();

        let mut witness = original.clone();
        let mut announcements = witness.new_kernel.kernel.announcements.clone();
        announcements.pop().unwrap();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .announcements(announcements)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();

        let mut witness = original.clone();
        let fee = witness.new_kernel.kernel.fee + NativeCurrencyAmount::one_nau();
        witness.new_kernel.kernel = TransactionKernelModifier::default()
            .fee(fee)
            .modify(witness.new_kernel.kernel);
        expect_failure(witness, &[MerkleVerify::ROOT_MISMATCH_ERROR_ID]).unwrap();
    }

    /// An updated transaction is never a coinbase transaction and never carries
    /// the merge bit. Both leafs are constants the branch authenticates
    /// directly, so a kernel holding anything else has the wrong leaf, not
    /// merely the wrong value.
    #[proptest(cases = 4)]
    fn coinbase_or_merge_bit_on_the_new_kernel_is_rejected(
        #[strategy(pokeable_witness())] original: UpdateWitness,
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

    /// `D` is *in* the old kernel's claim, and it is the one off the public
    /// input.
    ///
    /// The operand here is proven under `D'`, and everything -- witness,
    /// nondeterminism, authentication paths -- is built consistently around
    /// `D'`; only the claim the update is run against names `D`. Both ways of
    /// getting `D` wrong therefore fail this test: a branch that dropped `D`
    /// from the operand claim, and a branch that took it from the witness
    /// instead of the public input, would each verify the operand happily.
    ///
    /// This is also what says `Update` cannot *re-target* `D`. There is only one
    /// `D` in the program -- the one the dispatcher read -- and it goes into the
    /// operand claim verbatim, so "the new `D`" is not a value the branch could
    /// name even if it wanted to. Re-targeting it would have to look like this
    /// test: an operand proven under one digest, claimed under another.
    ///
    /// This test involves producing proofs and might take a while to complete
    /// if there is no proof cache.
    #[tokio::test]
    async fn old_proof_forged_under_another_single_proof_digest_is_rejected() {
        let (lpw, old_msa, new_kernel, new_msa, successor_proof) = deterministic_updatable(1);
        let other_d = mock_single_proof_digest(1);
        let witness = UpdateWitness::update(
            forge(&lpw, other_d).await,
            &old_msa,
            new_kernel,
            &new_msa,
            successor_proof,
            vec![],
            other_d,
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
            panic!("`Update` must reject an operand proven under another `D`");
        };
        assert!(
            vm_state.contains("stark_verify"),
            "must fail in the recursive verification, not before it:\n{vm_state}"
        );
    }

    /// The converse: `D` sits in the witness's memory image, and the branch must
    /// never look at it.
    ///
    /// Poked to a value the old link proof was *not* made under, while the
    /// public input keeps the real one. A branch that divined `D` from the
    /// witness would build a claim no proof answers and fail; this one passes,
    /// which is the guard, not the accident.
    ///
    /// Narrower than [`Chain`](super::super::chain::Chain)'s namesake, and
    /// deliberately so: the route from the dispatcher's slot into the operand
    /// claim is `GenerateLinkProofClaim`, shared with `Chain` and pinned there
    /// (including by mutation, per that test's note). What is pinned *here* is
    /// only the thing that is `Update`'s own -- that this branch does not
    /// additionally read `witness.single_proof_digest` somewhere along the way.
    /// Keep the witness's `D` distinct from the claim's, or that goes away
    /// silently.
    ///
    /// Reuses the `Forge` proof the positive test above makes -- same fixture,
    /// same `D`, hence the same claim -- so it costs a cache hit, not a proof.
    #[tokio::test]
    async fn witness_supplied_single_proof_digest_is_ignored() {
        let (lpw, old_msa, new_kernel, new_msa, successor_proof) = deterministic_updatable(1);
        let d = mock_single_proof_digest(0);
        let mut witness = UpdateWitness::update(
            forge(&lpw, d).await,
            &old_msa,
            new_kernel,
            &new_msa,
            successor_proof,
            vec![],
            d,
        );

        // Both derived from the honest witness, before the poke: the claim the
        // old proof answers, and the digest stream extracted against it.
        let input = witness.standard_input();
        let mut nondeterminism = witness.nondeterminism();

        witness.single_proof_digest = mock_single_proof_digest(1);
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &LinkProofWitnessMemory::Update(Box::new(witness)),
        );

        LinkProof.run_rust(&input, nondeterminism.clone()).unwrap();
        LinkProof.run_tasm(&input, nondeterminism).unwrap();
    }

    /// The new kernel is bound to the claim: `Update` authenticates its fields
    /// against `lkmh` straight off the public input, so a witness proven against
    /// some *other* transaction's kernel fails at the first field.
    #[proptest(cases = 4)]
    fn new_kernel_must_be_the_one_in_the_claim(
        #[strategy(pokeable_witness())] witness: UpdateWitness,
    ) {
        let other_lkmh = witness.old_kernel.mast_hash();

        LinkProof
            .test_assertion_failure(
                link_proof_public_input(other_lkmh, witness.single_proof_digest),
                witness.nondeterminism(),
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            )
            .unwrap();
    }
}
