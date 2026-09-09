use std::collections::HashMap;
use std::sync::Arc;

use itertools::Itertools;
use neptune_mutator_set::addition_record::AdditionRecord;
use neptune_mutator_set::ms_membership_proof::MsMembershipProof;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use neptune_mutator_set::removal_record::RemovalRecord;
use neptune_primitives::mast_hash::HasDiscriminant;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::list::contains::Contains;
use tasm_lib::list::new::New;
use tasm_lib::list::push::Push;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::verify_from_secret_in_leaf_index_on_stack::MmrVerifyFromSecretInLeafIndexOnStack;
use tasm_lib::neptune::mutator_set;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::prelude::MerkleTree;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::authenticate_link_kernel_field::AuthenticateLinkKernelField;
use super::link_kernel::LinkKernel;
use super::link_kernel::LinkKernelField;
use super::link_primitive_witness::LinkPrimitiveWitness;
use super::link_proof::link_proof_claim;
use super::link_proof::link_proof_public_input;
use super::link_proof::link_proof_public_output;
use super::link_proof::merge_bit_false_leaf;
use super::link_proof::no_coinbase_leaf;
use super::link_proof::LinkProof;
use super::link_proof_witness::LinkProofWitnessMemory;
use super::link_proof_witness::DISCRIMINANT_FOR_FORGE;
use super::link_tx::LinkTx;
use super::link_tx::LinkTxProof;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::error::CreateProofError;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::proof_abstractions::triton_vm_job_queue::TritonVmJobQueue;
use crate::proof_abstractions::SecretWitness;
use crate::transaction::primitive_witness::SaltedUtxos;
use crate::transaction::transaction_kernel::TransactionKernel;
use crate::transaction::utxo::Coin;
use crate::transaction::utxo::Utxo;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::validity::tasm::claims::new_claim::NewClaim;
use crate::transaction::validity::tasm::compute_absolute_indices::ComputeAbsoluteIndices;
use crate::transaction::validity::tasm::leaf_authentication::authenticate_msa_against_txk::AuthenticateMsaAgainstTxk;
use crate::type_scripts::native_currency::NativeCurrency;
use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

const CARDINALITY_MISMATCH_ERROR: i128 = 1_000_520;
const COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR: i128 = 1_000_521;
const UTXO_COMMITMENT_MISMATCH_ERROR: i128 = 1_000_522;
const UTXOS_SIZE_MANIPULATION_ERROR: i128 = 1_000_523;
const JUMP_OUT_OF_BOUNDS_ERROR: i128 = 1_000_524;
const INNER_ROOT_MISMATCH_ERROR: i128 = 1_000_525;
const TOO_MANY_COINS_ERROR: i128 = 1_000_526;
const WRONG_NUMBER_OF_TYPE_SCRIPT_PROOFS_ERROR: i128 = 1_000_527;
const WRONG_NUMBER_OF_LOCK_SCRIPT_PROOFS_ERROR: i128 = 1_000_528;
const FORGE_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR: i128 = 1_000_529;

/// Number of coins per UTXO must be strictly less than this. Copied, with the
/// guard, from [`CollectTypeScripts`](crate::transaction::validity::collect_type_scripts).
const MAX_NUM_COINS_PER_UTXO: usize = 100_000;

/// The witness consumed by [`Forge`]: the `Forge`-facing projection of a
/// [`LinkPrimitiveWitness`].
///
/// Carries the input/output-integrity data plus the recursive script proofs:
/// one halting proof per input lock script and one per *unique* type script.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
pub struct ForgeWitness {
    input_utxos: SaltedUtxos,
    confirmed_inputs: Vec<RemovalRecord>,
    thruputs: Vec<AdditionRecord>,

    /// The outputs as the type scripts see them. Bound to `outputs` below by
    /// the same commitment check the thruputs get -- `KernelToOutputs`,
    /// absorbed into `Forge` the way `RemovalRecordsIntegrity` is. Without that
    /// binding a prover could show the type scripts cheap outputs while the
    /// kernel commits to expensive addition records, which is an inflation
    /// path.
    output_utxos: SaltedUtxos,
    outputs: Vec<AdditionRecord>,
    output_sender_randomnesses: Vec<Digest>,
    output_receiver_digests: Vec<Digest>,

    aocl: MmrAccumulator,
    swbfi: MmrAccumulator,

    /// Membership proofs for the confirmed inputs, *i.e.* the first
    /// `confirmed_inputs.len()` entries of `input_utxos`.
    membership_proofs: Vec<MsMembershipProof>,
    aocl_auth_paths: Vec<MmrMembershipProof>,
    swbfa_hash: Digest,

    /// The kernel's fee. In the witness so that `Forge` can authenticate it
    /// against the kernel MAST hash and assert it is a non-negative amount.
    fee: NativeCurrencyAmount,

    /// Commitment randomness for the thruputs, parallel to `thruputs`.
    thruput_sender_randomnesses: Vec<Digest>,
    thruput_receiver_digests: Vec<Digest>,

    /// The `SingleProof` program digest `D` this witness is claimed under.
    ///
    /// `Forge` ignores its value -- it recurses into nothing, so it has no
    /// operand claim to pass `D` onto -- but `D` is in the claim regardless, and
    /// so has to be here to build the public input. Deliberately absent from
    /// [`ForgeWitnessMemory`]: what the branch never sees, it cannot read.
    single_proof_digest: Digest,

    /// Halting proofs for the input lock scripts, parallel to `input_utxos`:
    /// `lock_scripts_halt[i]` proves the lock script whose hash is
    /// `input_utxos[i].lock_script_hash()` halts on the *inner* kernel MAST
    /// hash. Empty until [`produce`](Self::produce) fills it -- the `From`
    /// projection carries only the input/output-integrity data. `Forge`
    /// recursively verifies each.
    lock_scripts_halt: Vec<Proof>,

    /// Halting proofs for the *unique* type scripts, parallel to
    /// `Utxo::type_script_hashes(input_utxos || output_utxos)` (the same
    /// deduplicated, native-currency-first list `CollectTypeScripts` builds):
    /// `type_scripts_halt[i]` proves the type script whose hash is that list's
    /// `i`-th entry halts on `[inner_root, H(input_utxos), H(output_utxos)]`.
    /// `Forge` recollects the list and recursively verifies each.
    type_scripts_halt: Vec<Proof>,

    /// The [`LinkKernel`]'s MAST leafs, in [`LinkKernelField`] order.
    ///
    /// The root `Forge` is claimed against and all five authentication paths
    /// are *derived* from these (see [`mast_tree`](Self::mast_tree)), so no two
    /// of them can disagree -- which storing the paths separately allowed.
    ///
    /// Deliberately not derived any further to avoid redundant data and
    /// potential discrepancies.
    mast_leafs: Vec<Digest>,
}

impl ForgeWitness {
    /// The [`LinkKernel`]'s MAST hash: the public input of the `LinkProof`
    /// claim this witness is proven against.
    pub(super) fn kernel_mast_hash(&self) -> Digest {
        self.mast_tree().root()
    }

    /// The [`LinkKernel`]'s MAST tree, rebuilt from [`Self::mast_leafs`].
    /// Mirrors [`MastHash::merkle_tree`]'s padding.
    fn mast_tree(&self) -> MerkleTree {
        let mut leafs = self.mast_leafs.clone();
        while leafs.len() & (leafs.len() - 1) != 0 {
            leafs.push(Digest::default());
        }
        MerkleTree::sequential_new(&leafs).unwrap()
    }

    /// The *inner* [`TransactionKernel`] MAST hash (height 3), the root of the
    /// first `2^3` of [`Self::mast_leafs`]. A [`LinkKernel`] reuses the transaction
    /// kernel's leafs for its first eight fields (`Inputs..=MergeBit`, before
    /// `Thruputs`), so this is exactly the hash the type scripts and lock
    /// scripts were proven against -- `Forge` must feed *this*, not its own
    /// height-4 `LinkKernel` root, to the recursive script-proof claims. The
    /// first eight leafs are already a power of two, so no padding is needed.
    fn inner_kernel_mast_hash(&self) -> Digest {
        let num_inner_leafs = 1 << <TransactionKernel as MastHash>::MAST_HEIGHT;
        MerkleTree::sequential_new(&self.mast_leafs[..num_inner_leafs])
            .unwrap()
            .root()
    }

    /// The inner (height-3) root and its right sibling -- the two children of
    /// the height-4 [`LinkKernel`] MAST root. `Tip5::hash_pair(inner_root,
    /// right_sibling)` reconstructs that root, so `Forge` authenticates the
    /// divined inner root with a single hash instead of rebuilding a subtree.
    /// The left half is leafs `Inputs..=MergeBit` (exactly the
    /// `TransactionKernel` leafs); the right half is `Thruputs` then padding.
    fn inner_root_and_right_sibling(&self) -> (Digest, Digest) {
        let num_inner = 1 << <TransactionKernel as MastHash>::MAST_HEIGHT;
        let mut right_leafs = self.mast_leafs[num_inner..].to_vec();
        right_leafs.resize(num_inner, Digest::default());
        let right_sibling = MerkleTree::sequential_new(&right_leafs).unwrap().root();
        (self.inner_kernel_mast_hash(), right_sibling)
    }
}

/// The parts of a [`ForgeWitness`] that are initialized in memory at the start
/// of each execution. The rest arrives on the non-determinism streams.
///
/// Wrapped in
/// [`LinkProofWitnessMemory::Forge`]
/// before it is written to memory -- `Forge` is a branch of `LinkProof`, not a
/// program of its own.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
pub(super) struct ForgeWitnessMemory {
    input_utxos: SaltedUtxos,
    confirmed_inputs: Vec<RemovalRecord>,
    thruputs: Vec<AdditionRecord>,
    output_utxos: SaltedUtxos,
    outputs: Vec<AdditionRecord>,
    aocl: MmrAccumulator,
    /// The bagged inactive-window peaks and the active-window hash, as digests.
    /// `AuthenticateMsaAgainstTxk` consumes these directly (it bags only the
    /// AOCL itself), so -- like `update_branch`'s `UpdateWitness` -- the memory
    /// image carries them pre-reduced rather than the raw swbfi MMR.
    swbfi_bagged: Digest,
    swbfa_hash: Digest,
    fee: NativeCurrencyAmount,
    lock_scripts_halt: Vec<Proof>,
    type_scripts_halt: Vec<Proof>,
}

impl From<&ForgeWitness> for ForgeWitnessMemory {
    fn from(witness: &ForgeWitness) -> Self {
        use tasm_lib::twenty_first::prelude::Mmr;
        Self {
            input_utxos: witness.input_utxos.clone(),
            confirmed_inputs: witness.confirmed_inputs.clone(),
            thruputs: witness.thruputs.clone(),
            output_utxos: witness.output_utxos.clone(),
            outputs: witness.outputs.clone(),
            aocl: witness.aocl.clone(),
            swbfi_bagged: witness.swbfi.bag_peaks(),
            swbfa_hash: witness.swbfa_hash,
            fee: witness.fee,
            lock_scripts_halt: witness.lock_scripts_halt.clone(),
            type_scripts_halt: witness.type_scripts_halt.clone(),
        }
    }
}

/// Forge a [`LinkPrimitiveWitness`] into a proof-backed [`LinkTx`].
///
/// The chain-pipeline analog of raising a primitive witness to a
/// `SingleProof`: the entry point of the pipeline. `single_proof_digest` is
/// the `D` the link proof is claimed under.
pub async fn forge(
    link_primitive_witness: &LinkPrimitiveWitness,
    single_proof_digest: Digest,
    consensus_rule_set: ConsensusRuleSet,
    job_queue: Arc<TritonVmJobQueue>,
    proof_job_options: TritonVmProofJobOptions,
) -> Result<LinkTx, CreateProofError> {
    let kernel = link_primitive_witness.kernel.clone();

    let proof = if proof_job_options.job_settings.network.use_mock_proof() {
        Proof::valid_mock()
    } else {
        let witness = ForgeWitness::produce(
            link_primitive_witness,
            single_proof_digest,
            job_queue.clone(),
            proof_job_options.clone(),
        )
        .await?;
        let claim = link_proof_claim(kernel.mast_hash(), single_proof_digest, consensus_rule_set);
        LinkProof
            .prove(
                claim,
                witness.nondeterminism(),
                job_queue,
                proof_job_options,
            )
            .await?
    };

    Ok(LinkTx {
        kernel,
        proof: LinkTxProof::Proof(proof),
    })
}

impl ForgeWitness {
    /// Upgrade a [`LinkPrimitiveWitness`] into a [`ForgeWitness`].
    ///
    ///  The sole way to build a [`ForgeWitness`]: copy the shared data from
    /// [`LinkPrimitiveWitness`] and prove that every input lock script and
    /// every unique type script halts gracefully. The analog of
    /// [`ProofCollection::produce`](crate::transaction::validity::proof_collection::ProofCollection::produce).
    ///
    /// There is deliberately no cheap proofless constructor -- a
    /// [`ForgeWitness`] without its proofs is not a [`ForgeWitness`]. A
    /// produced witness can be checked cheaply with [`Self::validate`], which
    /// is sound with respect to `Forge`: if [`Self::validate`] passes, `Forge`
    /// must succeed.
    pub async fn produce(
        lpw: &LinkPrimitiveWitness,
        single_proof_digest: Digest,
        job_queue: Arc<TritonVmJobQueue>,
        options: TritonVmProofJobOptions,
    ) -> Result<Self, CreateProofError> {
        let inner_root = lpw.kernel.kernel.mast_hash();
        let lock_script_input = PublicInput::new(inner_root.reversed().values().to_vec());
        let mut lock_scripts_halt = Vec::with_capacity(lpw.lock_scripts_and_witnesses.len());
        for lsaw in &lpw.lock_scripts_and_witnesses {
            lock_scripts_halt.push(
                lsaw.prove(
                    lock_script_input.clone(),
                    ConsensusRuleSet::HardforkDelta,
                    job_queue.clone(),
                    options.clone(),
                )
                .await?,
            );
        }

        // One proof per *unique* type script, in the deduplicated,
        // native-currency-first order `Forge` recollects in tasm (see
        // [`Utxo::type_script_hashes`]). Each type script is proven against the
        // same inner kernel root plus the two salted-UTXO hashes.
        let salted_inputs_hash = Tip5::hash(&lpw.input_utxos);
        let salted_outputs_hash = Tip5::hash(&lpw.output_utxos);
        let type_script_dictionary: HashMap<Digest, &crate::type_scripts::TypeScriptAndWitness> =
            lpw.type_scripts_and_witnesses
                .iter()
                .map(|tsaw| (tsaw.program.hash(), tsaw))
                .collect();
        let unique_type_script_hashes =
            Utxo::type_script_hashes(lpw.input_utxos.utxos.iter().chain(&lpw.output_utxos.utxos));
        let mut type_scripts_halt = Vec::with_capacity(unique_type_script_hashes.len());
        for hash in &unique_type_script_hashes {
            let tsaw = type_script_dictionary
                .get(hash)
                .expect("every required type script must have a witness");
            type_scripts_halt.push(
                tsaw.prove(
                    inner_root,
                    salted_inputs_hash,
                    salted_outputs_hash,
                    ConsensusRuleSet::HardforkDelta,
                    job_queue.clone(),
                    options.clone(),
                )
                .await?,
            );
        }

        Ok(Self::build_from_parts(
            lpw,
            single_proof_digest,
            lock_scripts_halt,
            type_scripts_halt,
        ))
    }

    /// Assemble the witness from an [`LinkPrimitiveWitness`] and its (already
    /// proven) lock and type scripts.
    //
    // [`produce`](Self::produce) supplies real proofs; the test-only
    // [`without_proofs`](Self::without_proofs) supplies none. A `ForgeWitness`
    // without proofs does not pass `validate` but does pass
    // `validate_integrity`, which is does every check except the proofs.
    fn build_from_parts(
        lpw: &LinkPrimitiveWitness,
        single_proof_digest: Digest,
        lock_scripts_halt: Vec<Proof>,
        type_scripts_halt: Vec<Proof>,
    ) -> Self {
        let kernel = &lpw.kernel;
        Self {
            input_utxos: lpw.input_utxos.clone(),
            confirmed_inputs: kernel.kernel.inputs.clone(),
            thruputs: kernel.thruputs.clone(),

            output_utxos: lpw.output_utxos.clone(),
            outputs: kernel.kernel.outputs.clone(),
            output_sender_randomnesses: lpw.output_sender_randomnesses.clone(),
            output_receiver_digests: lpw.output_receiver_digests.clone(),

            aocl: lpw.mutator_set_accumulator.aocl.clone(),
            swbfi: lpw.mutator_set_accumulator.swbf_inactive.clone(),

            membership_proofs: lpw.input_membership_proofs.clone(),
            aocl_auth_paths: lpw
                .input_membership_proofs
                .iter()
                .map(|mp| mp.auth_path_aocl.clone())
                .collect(),
            swbfa_hash: Tip5::hash(&lpw.mutator_set_accumulator.swbf_active),

            fee: kernel.kernel.fee,

            thruput_sender_randomnesses: lpw.thruput_sender_randomnesses.clone(),
            thruput_receiver_digests: lpw.thruput_receiver_digests.clone(),

            single_proof_digest,
            lock_scripts_halt,
            type_scripts_halt,

            mast_leafs: kernel
                .mast_sequences()
                .iter()
                .map(|sequence| Tip5::hash_varlen(sequence))
                .collect(),
        }
    }

    /// The first step of [`validate`], covering everything but the proofs.
    ///
    /// Covers:
    ///  - cardinality
    ///  - MAST-leaf consistency
    ///  - removal-records-integrity
    ///  - thruput/output commitments.
    ///
    /// Pure and proof-free, so it is cheap and can be exercised exhaustively
    /// against proofless (`without_proofs`) witnesses -- unlike the full
    /// [`validate`], which needs produced proofs. `validate` layers the proof
    /// verification on top.
    ///
    /// [`validate`]: Self::validate
    pub fn validate_integrity(&self) -> bool {
        use neptune_mutator_set::commit;
        use tasm_lib::twenty_first::prelude::Mmr;

        let num_confirmed = self.confirmed_inputs.len();
        let num_thruputs = self.thruputs.len();
        let num_outputs = self.outputs.len();

        // Parallel-vector cardinality. `Forge` asserts these; guarding here also
        // keeps the indexing below panic-free on a malformed (untrusted) witness.
        if self.input_utxos.utxos.len() != num_confirmed + num_thruputs
            || self.output_utxos.utxos.len() != num_outputs
            || self.membership_proofs.len() != num_confirmed
            || self.thruput_sender_randomnesses.len() != num_thruputs
            || self.thruput_receiver_digests.len() != num_thruputs
            || self.output_sender_randomnesses.len() != num_outputs
            || self.output_receiver_digests.len() != num_outputs
            || self.mast_leafs.len() <= LinkKernelField::Thruputs.discriminant()
        {
            return false;
        }

        // The MAST leafs must faithfully commit to the kernel fields `Forge`
        // authenticates. The rest (fee, timestamp, ...) are free here exactly as
        // they are free in `Forge`; the lock-script proofs pin them transitively
        // via the inner root.
        let left = Tip5::hash_pair(self.aocl.bag_peaks(), self.swbfi.bag_peaks());
        let right = Tip5::hash_pair(self.swbfa_hash, Digest::default());
        let msah = Tip5::hash_pair(left, right);
        let leaf = |f: LinkKernelField| self.mast_leafs[f.discriminant()];
        if leaf(LinkKernelField::MutatorSetHash) != Tip5::hash(&msah)
            || leaf(LinkKernelField::Inputs) != Tip5::hash(&self.confirmed_inputs)
            || leaf(LinkKernelField::Thruputs) != Tip5::hash(&self.thruputs)
            || leaf(LinkKernelField::Outputs) != Tip5::hash(&self.outputs)
            || leaf(LinkKernelField::Coinbase) != no_coinbase_leaf()
            || leaf(LinkKernelField::MergeBit) != merge_bit_false_leaf()
            || leaf(LinkKernelField::Fee) != Tip5::hash(&self.fee)
            || self.fee.is_negative()
        {
            return false;
        }

        // Confirmed inputs: RemovalRecordsIntegrity, inlined -- the addition
        // record is in the AOCL and the computed index set matches the record.
        for (i, msmp) in self.membership_proofs.iter().enumerate() {
            let utxo_hash = Tip5::hash(&self.input_utxos.utxos[i]);
            let addition_record = commit(
                utxo_hash,
                msmp.sender_randomness,
                msmp.receiver_preimage.hash(),
            );
            let in_aocl = msmp.auth_path_aocl.verify(
                msmp.aocl_leaf_index,
                addition_record.canonical_commitment,
                &self.aocl.peaks(),
                self.aocl.num_leafs(),
            );
            let index_set = AbsoluteIndexSet::compute(
                utxo_hash,
                msmp.sender_randomness,
                msmp.receiver_preimage,
                msmp.aocl_leaf_index,
            );
            if !in_aocl || index_set != self.confirmed_inputs[i].absolute_indices {
                return false;
            }
        }

        // Thruputs and outputs: each addition record commits to its UTXO.
        for j in 0..num_thruputs {
            let utxo_hash = Tip5::hash(&self.input_utxos.utxos[num_confirmed + j]);
            let ar = commit(
                utxo_hash,
                self.thruput_sender_randomnesses[j],
                self.thruput_receiver_digests[j],
            );
            if ar != self.thruputs[j] {
                return false;
            }
        }
        for k in 0..num_outputs {
            let utxo_hash = Tip5::hash(&self.output_utxos.utxos[k]);
            let ar = commit(
                utxo_hash,
                self.output_sender_randomnesses[k],
                self.output_receiver_digests[k],
            );
            if ar != self.outputs[k] {
                return false;
            }
        }

        true
    }

    /// Reference predicate for [`Forge`] -- the proof-carrying analog of
    /// [`LinkPrimitiveWitness::validate`] and sibling of
    /// [`ProofCollection::verify`](crate::transaction::validity::proof_collection::ProofCollection).
    /// Unlike `ProofCollection`, `Forge` *inlines* removal-records- and
    /// kernel-to-outputs-integrity (they are not sub-proofs), so this checks
    /// those natively via [`validate_integrity`](Self::validate_integrity) and
    /// then only *verifies* -- never runs -- the lock scripts and the type
    /// scripts. If this function returns `true`, the tasm `Forge` succeeds, so
    /// a caller can gate the expensive `Forge` proof on it.
    pub async fn validate(&self, network: neptune_primitives::network::Network) -> bool {
        use crate::proof_abstractions::verifier::verify;

        // One halting proof per input UTXO. The guard prevents the `zip` below
        // from silently skipping surplus lock scripts (cf. `ProofCollection`).
        if !self.validate_integrity()
            || self.lock_scripts_halt.len() != self.input_utxos.utxos.len()
        {
            return false;
        }

        // Every input lock script must carry a halting proof against the inner
        // (height-3) kernel root it was proven against.
        let inner_root = self.inner_kernel_mast_hash();
        for (utxo, proof) in self.input_utxos.utxos.iter().zip(&self.lock_scripts_halt) {
            let claim =
                Claim::new(utxo.lock_script_hash()).with_input(inner_root.reversed().values());
            if !verify(claim, proof.clone(), network).await {
                return false;
            }
        }

        // Every unique type script must carry a halting proof against the inner
        // root plus the two salted-UTXO hashes -- the input the type scripts see.
        let type_script_input: Vec<BFieldElement> = [
            inner_root,
            Tip5::hash(&self.input_utxos),
            Tip5::hash(&self.output_utxos),
        ]
        .into_iter()
        .flat_map(|d| d.reversed().values())
        .collect();
        let unique_type_script_hashes = Utxo::type_script_hashes(
            self.input_utxos
                .utxos
                .iter()
                .chain(&self.output_utxos.utxos),
        );
        if self.type_scripts_halt.len() != unique_type_script_hashes.len() {
            return false;
        }
        for (hash, proof) in unique_type_script_hashes
            .iter()
            .zip(&self.type_scripts_halt)
        {
            let claim = Claim::new(*hash).with_input(type_script_input.clone());
            if !verify(claim, proof.clone(), network).await {
                return false;
            }
        }

        true
    }
}

impl SecretWitness for ForgeWitness {
    fn standard_input(&self) -> PublicInput {
        link_proof_public_input(self.mast_tree().root(), self.single_proof_digest)
    }

    fn output(&self) -> Vec<BFieldElement> {
        link_proof_public_output(self.single_proof_digest)
    }

    fn program(&self) -> Program {
        LinkProof.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // `Forge` is a branch of `LinkProof`, so the memory image is the
        // *enum's*: discriminant, field size, then the payload.
        let memory_part = LinkProofWitnessMemory::Forge(Box::new(self.into()));
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &memory_part,
        );

        // Each digest and the u64 leaf index are laid down reversed: that is
        // the orientation the tasm expects to find them in on the stack after
        // divining. (The swbfa hash used to be divined here; it now lives in the
        // memory image, so the stream starts with the confirmed-input data.)
        let mut nd_stream: Vec<BFieldElement> = vec![];
        for msmp in &self.membership_proofs {
            let mut leaf_index = msmp.aocl_leaf_index.encode();
            leaf_index.reverse();
            nd_stream.extend(&leaf_index);
            nd_stream.extend(&msmp.receiver_preimage.reversed().values());
            nd_stream.extend(&msmp.sender_randomness.reversed().values());
        }
        for (receiver_digest, sender_randomness) in self
            .thruput_receiver_digests
            .iter()
            .zip_eq(&self.thruput_sender_randomnesses)
        {
            nd_stream.extend(&receiver_digest.reversed().values());
            nd_stream.extend(&sender_randomness.reversed().values());
        }
        for (receiver_digest, sender_randomness) in self
            .output_receiver_digests
            .iter()
            .zip_eq(&self.output_sender_randomnesses)
        {
            nd_stream.extend(&receiver_digest.reversed().values());
            nd_stream.extend(&sender_randomness.reversed().values());
        }

        // Order must match the order of the `merkle_verify` calls in the
        // program, followed by the AOCL auth paths in loop order.
        let mast_tree = self.mast_tree();
        let mast_path = |field: LinkKernelField| {
            mast_tree
                .authentication_structure(&[field.discriminant()])
                .unwrap()
        };
        let digests = [
            mast_path(LinkKernelField::MutatorSetHash),
            mast_path(LinkKernelField::Inputs),
            mast_path(LinkKernelField::Thruputs),
            mast_path(LinkKernelField::Outputs),
            mast_path(LinkKernelField::Coinbase),
            mast_path(LinkKernelField::MergeBit),
            mast_path(LinkKernelField::Fee),
            self.aocl_auth_paths
                .iter()
                .flat_map(|mp| mp.authentication_path.clone())
                .collect_vec(),
        ]
        .concat();

        // Inner-root authentication data, read after the input/output-integrity
        // divines: the inner (height-3) `TransactionKernel` root. The program
        // computes its right sibling from the (already authenticated) thruputs
        // and `hash`es the two to reconstruct `lkmh`, authenticating the inner
        // root the lock/type scripts were proven against.
        let (inner_root, _) = self.inner_root_and_right_sibling();
        nd_stream.extend(inner_root.reversed().values());

        let mut nondeterminism = NonDeterminism::new(nd_stream)
            .with_ram(memory)
            .with_digests(digests);

        // Append each proof's `StarkVerify` aux nondeterminism in the order the
        // program consumes it: type scripts, then lock scripts. (The proofs are
        // already in RAM via `ForgeWitnessMemory`.)
        // Why `zip`, and not `zip_eq`? The negative tests mismatch these
        // lengths on purpose, and `zip_eq` would panic here instead of letting
        // the tasm reject them (the behavior being tested). It's harmless
        // because mismatching cardinalities are filtered out before the verify
        // loops start.
        let stark_verify = StarkVerify::new_with_dynamic_layout(Stark::default());
        let inner_input = inner_root.reversed().values().to_vec();

        // Type scripts, in the deduplicated native-currency-first order (see
        // `Utxo::type_script_hashes`), each against the inner root plus the two
        // salted-UTXO hashes.
        let type_script_input: Vec<BFieldElement> = inner_input
            .iter()
            .copied()
            .chain(Tip5::hash(&self.input_utxos).reversed().values())
            .chain(Tip5::hash(&self.output_utxos).reversed().values())
            .collect();
        let unique_type_script_hashes = Utxo::type_script_hashes(
            self.input_utxos
                .utxos
                .iter()
                .chain(&self.output_utxos.utxos),
        );
        for (hash, proof) in unique_type_script_hashes
            .iter()
            .zip(&self.type_scripts_halt)
        {
            let claim = Claim::new(*hash).with_input(type_script_input.clone());
            stark_verify.update_nondeterminism(&mut nondeterminism, proof, &claim);
        }

        // Lock scripts, in input-UTXO order, each against the inner root.
        for (utxo, proof) in self.input_utxos.utxos.iter().zip(&self.lock_scripts_halt) {
            let claim = Claim::new(utxo.lock_script_hash()).with_input(inner_input.clone());
            stark_verify.update_nondeterminism(&mut nondeterminism, proof, &claim);
        }

        nondeterminism
    }
}

/// `Forge: LinkPrimitiveWitness -> LinkTx`: the entry point into the
/// transaction-chaining pipeline.
///
/// `Forge` establishes that a [`LinkKernel`]'s inputs are legitimate:
///
/// - the *confirmed* inputs are members of the mutator set and their removal
///   records carry the right absolute index sets ([`RemovalRecordsIntegrity`]
///   inlined non-recursively -- the cost saving that motivates chaining);
/// - the *thruputs* commit to the tail of the input UTXO list;
/// - the two together exactly cover the type-script-facing input UTXO list, so
///   type scripts see `confirmed_inputs || thruputs` and thus treat confirmed
///   inputs and thruputs the same;
/// - the kernel carries no coinbase and no merge bit.
///
/// `Forge` *also* establishes that every lock script and every unique type
/// script halts gracefully, recursively verifying both. So every input is
/// provably unlocked and every coin's type script provably halts.
///
/// [`RemovalRecordsIntegrity`]: crate::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity
#[derive(Debug, Copy, Clone)]
pub struct Forge;

impl BasicSnippet for Forge {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "link_kernel_mast_hash".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "discriminant".to_string()),
        ]
    }

    /// The digest slot is the dispatcher's scratch space, not a return value:
    /// this branch leaves the *inner* (`TransactionKernel`) root there,
    /// having reused the slot once `lkmh` went dead. See `LinkProof`.
    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::Digest, "dispatcher_scratch".to_string()),
            (DataType::VoidPointer, "link_proof_witness".to_string()),
            (DataType::Bfe, "minus_1".to_string()),
        ]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_chaintx_link_proof_forge_branch".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        type MmrAccumulatorTip5 = MmrAccumulator;
        const MAX_JUMP_LENGTH: usize = 2_000_000;

        let merkle_verify = library.import(Box::new(MerkleVerify));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let ms_commit = library.import(Box::new(mutator_set::commit::Commit));
        let mmr_verify = library.import(Box::new(MmrVerifyFromSecretInLeafIndexOnStack));
        let compute_absolute_indices = library.import(Box::new(ComputeAbsoluteIndices));
        let hash_absolute_indices = library.import(Box::new(HashStaticSize {
            size: AbsoluteIndexSet::static_length().expect("absolute indices have a static size"),
        }));
        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            ForgeWitnessMemory,
        >::default()));

        // The confirmed-input loop's static-memory addresses must lie the same
        // way relative to each other as `RemovalRecordsIntegrity`'s (see
        // `forge_confirmed_loop_matches_rri`), which holds only if these four
        // `kmalloc`s stay contiguous and in this order. `StarkVerify`'s import
        // `kmalloc`s heavily, so it -- and every other verifier-side import --
        // must come *after* these four. Where the block as a whole starts does
        // not matter; the guard rebases that away.
        let u64_stack_size: u32 = DataType::U64.stack_size().try_into().unwrap();
        let aocl_leaf_index_alloc = library.kmalloc(u64_stack_size);
        let digest_stack_size: u32 = DataType::Digest.stack_size().try_into().unwrap();
        let receiver_preimage_alloc = library.kmalloc(digest_stack_size);
        let sender_randomness_alloc = library.kmalloc(digest_stack_size);
        let utxo_hash_alloc = library.kmalloc(digest_stack_size);

        let stark_verify = library.import(Box::new(StarkVerify::new_with_dynamic_layout(
            Stark::default(),
        )));

        let new_claim = library.import(Box::new(NewClaim::new(ConsensusRuleSet::HardforkDelta)));

        // Verifier-side imports too: these `kmalloc` internally, so like
        // `StarkVerify` they must land *after* the four RRI-matching allocs.
        let contains = library.import(Box::new(Contains::new(DataType::Digest)));
        let new_list = library.import(Box::new(New));
        let list_push_digest = library.import(Box::new(Push::new(DataType::Digest)));
        // Shared mutator-set-accumulator authentication, at LinkKernel's height.
        // Imported here (with the other verifier-side snippets) so its internal
        // `BagPeaks`/`MerkleVerify` imports cannot disturb the four allocs above.
        let authenticate_msa = library.import(Box::new(AuthenticateMsaAgainstTxk {
            mast_height: LinkKernel::MAST_HEIGHT as u32,
        }));
        // Same reasoning: neither of this snippet's imports allocates today, but
        // importing it here rather than above keeps that from mattering.
        let authenticate_inputs = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Inputs,
        )));
        let authenticate_thruputs_field = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Thruputs,
        )));
        let authenticate_outputs_field = library.import(Box::new(AuthenticateLinkKernelField(
            LinkKernelField::Outputs,
        )));

        let field_aocl = field!(ForgeWitnessMemory::aocl);
        let field_swbfi_bagged = field!(ForgeWitnessMemory::swbfi_bagged);
        let field_swbfa_hash = field!(ForgeWitnessMemory::swbfa_hash);
        let field_peaks = field!(MmrAccumulatorTip5::peaks);
        let field_mmr_num_leafs = field!(MmrAccumulatorTip5::leaf_count);
        let field_input_utxos = field!(ForgeWitnessMemory::input_utxos);
        let field_with_size_input_utxos = field_with_size!(ForgeWitnessMemory::input_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_utxos_with_size = field_with_size!(SaltedUtxos::utxos);
        let field_confirmed_inputs = field!(ForgeWitnessMemory::confirmed_inputs);
        let field_with_size_confirmed_inputs =
            field_with_size!(ForgeWitnessMemory::confirmed_inputs);
        let field_thruputs = field!(ForgeWitnessMemory::thruputs);
        let field_with_size_thruputs = field_with_size!(ForgeWitnessMemory::thruputs);
        let field_output_utxos = field!(ForgeWitnessMemory::output_utxos);
        let field_with_size_output_utxos = field_with_size!(ForgeWitnessMemory::output_utxos);
        let field_outputs = field!(ForgeWitnessMemory::outputs);
        let field_with_size_outputs = field_with_size!(ForgeWitnessMemory::outputs);
        let field_indices = field!(RemovalRecord::absolute_indices);
        let field_lock_scripts_halt = field!(ForgeWitnessMemory::lock_scripts_halt);
        let field_type_scripts_halt = field!(ForgeWitnessMemory::type_scripts_halt);
        let field_lock_script_hash = field!(Utxo::lock_script_hash);
        let field_coins = field!(Utxo::coins);
        let field_type_script_hash = field!(Coin::type_script_hash);

        let compare_digests = DataType::Digest.compare();
        let for_all_confirmed = "neptune_consensus_chaintx_forge_for_all_confirmed".to_string();
        // Thruputs and outputs are both `AdditionRecord`s that must equal the
        // canonical commitment of a UTXO, so one subroutine serves both.
        let for_all_addition_records =
            "neptune_consensus_chaintx_forge_for_all_addition_records".to_string();
        let verify_lock_scripts = "neptune_consensus_chaintx_forge_verify_lock_scripts".to_string();
        let verify_type_scripts = "neptune_consensus_chaintx_forge_verify_type_scripts".to_string();
        // Deduplicated type-script-hash collection, absorbed from
        // `CollectTypeScripts` (copied instruction-for-instruction; guarded by
        // `forge_collect_type_scripts_matches_cts`).
        let collect_from_utxos =
            "neptune_consensus_chaintx_forge_collect_type_script_hashes_from_utxos".to_string();
        let collect_from_coins =
            "neptune_consensus_chaintx_forge_collect_type_script_hashes_from_coins".to_string();
        let push_ts_hash_from_coin =
            "neptune_consensus_chaintx_forge_push_type_script_hash_from_coin".to_string();

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
        let push_no_coinbase_leaf = push_digest(no_coinbase_leaf());
        let push_merge_bit_false_leaf = push_digest(merge_bit_false_leaf());
        // The native-currency type-script hash seeds the deduplicated list: it
        // is always present (fees are paid in native currency), so `Forge`
        // pushes it first, matching `CollectTypeScripts`.
        let push_native_currency_hash = push_digest(NativeCurrency.hash());

        let d1 = Digest::default();
        let d2 = Tip5::hash_pair(d1, d1);
        let d4 = Tip5::hash_pair(d2, d2);
        let right_lkmh_node_from_thruputs = triton_asm!(
            // _ *thruputs

            {&push_digest(d4)}
            {&push_digest(d2)}
            {&push_digest(d1)}
            // _ *thruputs [d4] [d2] [d1]

            pick 15
            read_mem 1
            // _ [d4] [d2] [d1] len (*thruputs - 1)

            addi 1
            swap 1
            // _ [d4] [d2] [d1] *thruputs len

            push {Digest::LEN}
            mul
            addi 1
            // _ [d4] [d2] [d1] *thruputs size

            call {hash_varlen}
            // _ [d4] [d2] [d1] [thruput_leaf: Digest]

            hash
            // _ [d4] [d2] [n1: Digest]

            hash
            // _ [d4] [n2: Digest]

            hash
            // _ [root_right_child: Digest]
        );

        // Authenticate the mutator-set accumulator against the link-kernel MAST
        // hash via the shared `AuthenticateMsaAgainstTxk` snippet (instantiated
        // at LinkKernel's height; the `MutatorSetHash` leaf index 6 is the same
        // as `TransactionKernel`'s). The snippet bags the AOCL peaks itself and
        // reads the pre-bagged swbfi digest and the swbfa digest from the
        // witness -- the same layout `update_branch`'s `UpdateWitness` uses.
        let authenticate_mutator_set_acc = triton_asm!(
            // _ [lkmh] *witness
            dup 0 {&field_aocl}
            // _ [lkmh] *witness *aocl

            dup 1 {&field_swbfi_bagged}
            // _ [lkmh] *witness *aocl *swbfi_bagged

            dup 2 {&field_swbfa_hash}
            // _ [lkmh] *witness *aocl *swbfi_bagged *swbfa

            dup 8 dup 8 dup 8 dup 8 dup 8
            // _ [lkmh] *witness *aocl *swbfi_bagged *swbfa [lkmh]

            call {authenticate_msa}
            // _ [lkmh] *witness
        );

        // Authenticate one variable-length link-kernel MAST leaf, via the
        // shared `AuthenticateLinkKernelField` snippet, so no two branches can
        // drift on how a `LinkKernel` leaf is proven. `field_accessor` turns
        // `*witness` into `*field size`.
        let authenticate_field = |snippet: &str, field_accessor: &[LabelledInstruction]| {
            triton_asm!(
                // _ [lkmh] *witness
                dup 5 dup 5 dup 5 dup 5 dup 5
                // _ [lkmh] *witness [lkmh]

                dup 5
                {&field_accessor}
                // _ [lkmh] *witness [lkmh] *field size

                call {snippet}
                // _ [lkmh] *witness
            )
        };

        // A leaf whose value consensus fixes is *not* one of those: pushing the
        // constant digest straight into `merkle_verify` asserts the field's
        // value at the same time (only one preimage hashes to it), which is
        // strictly stronger than authenticating whatever the witness holds.
        let authenticate_constant_leaf =
            |leaf_index: LinkKernelField, leaf: &[LabelledInstruction]| {
                triton_asm!(
                    // _ [lkmh] *witness
                    dup 5 dup 5 dup 5 dup 5 dup 5
                    push {LinkKernel::MAST_HEIGHT}
                    push {leaf_index.discriminant() as u32}
                    // _ [lkmh] *witness [lkmh] h i

                    {&leaf}
                    // _ [lkmh] *witness [lkmh] h i [leaf]

                    call {merkle_verify}
                    // _ [lkmh] *witness
                )
            };

        let authenticate_confirmed_inputs =
            authenticate_field(&authenticate_inputs, &field_with_size_confirmed_inputs);
        let authenticate_thruputs =
            authenticate_field(&authenticate_thruputs_field, &field_with_size_thruputs);
        let authenticate_outputs =
            authenticate_field(&authenticate_outputs_field, &field_with_size_outputs);
        let authenticate_no_coinbase =
            authenticate_constant_leaf(LinkKernelField::Coinbase, &push_no_coinbase_leaf);
        let authenticate_merge_bit_false =
            authenticate_constant_leaf(LinkKernelField::MergeBit, &push_merge_bit_false_leaf);

        let authenticate_fee_field =
            library.import(Box::new(AuthenticateLinkKernelField(LinkKernelField::Fee)));
        let lt_u128 = library.import(Box::new(tasm_lib::arithmetic::u128::lt::Lt));
        let field_fee = field!(ForgeWitnessMemory::fee);
        let fee_size = NativeCurrencyAmount::static_length().unwrap();
        let push_max_amount = NativeCurrencyAmount::max().push_to_stack();

        // The kernel's fee is a non-negative amount in range: `Forge` is an
        // entry point into the chain pipeline, and no link transaction may
        // carry a negative fee.
        let assert_fee_is_valid_amount = triton_asm!(
            // _ [lkmh] *witness
            dup 0
            {&field_fee}
            // _ [lkmh] *witness *fee

            dup 6 dup 6 dup 6 dup 6 dup 6
            // _ [lkmh] *witness *fee [lkmh]

            dup 5
            push {fee_size}
            call {authenticate_fee_field}
            // _ [lkmh] *witness *fee

            addi {fee_size - 1}
            read_mem {fee_size}
            pop 1
            // _ [lkmh] *witness [fee; 4]

            /* Ensure fee not-negative, and in-range */
            {&push_max_amount}
            call {lt_u128}
            push 0 eq
            // _ [lkmh] *witness (!(fee > max))

            assert error_id {FORGE_FEE_IS_NEGATIVE_OR_INVALID_AMOUNT_ERROR}
            // _ [lkmh] *witness
        );

        let crash_if_not_u32 = triton_asm!(
            // _ value

            dup 0
            pop_count
            pop 1
            // _ (value: u32)
        );

        // The type scripts see `input_utxos` as one flat list and contain all
        // inputs, both confirmed inputs and thruputs. Binding its length to
        // `|confirmed| + |thruputs|` is what stops a phantom input UTXO --
        // backed by neither a removal record nor a thruput -- from inflating.
        let assert_cardinality = triton_asm!(
            // _ [lkmh] *witness
            dup 0 {&field_input_utxos} {&field_utxos} read_mem 1 pop 1
            // _ [lkmh] *witness num_utxos

            {&crash_if_not_u32}
            // _ [lkmh] *witness num_utxos

            dup 1 {&field_confirmed_inputs} read_mem 1 pop 1
            // _ [lkmh] *witness num_utxos num_confirmed

            {&crash_if_not_u32}
            // _ [lkmh] *witness num_utxos num_confirmed

            dup 2 {&field_thruputs} read_mem 1 pop 1
            // _ [lkmh] *witness num_utxos num_confirmed num_thruputs

            {&crash_if_not_u32}
            // _ [lkmh] *witness num_utxos num_confirmed num_thruputs

            add
            // _ [lkmh] *witness num_utxos (num_confirmed + num_thruputs)

            eq assert error_id {CARDINALITY_MISMATCH_ERROR}
            // _ [lkmh] *witness

            /* ... and likewise every output UTXO is backed by an addition
               record, so the balance the type scripts compute over
               `output_utxos` is the balance the mutator set will receive. */
            dup 0 {&field_output_utxos} {&field_utxos} read_mem 1 pop 1
            // _ [lkmh] *witness num_output_utxos

            {&crash_if_not_u32}
            // _ [lkmh] *witness num_output_utxos

            dup 1 {&field_outputs} read_mem 1 pop 1
            // _ [lkmh] *witness num_output_utxos num_outputs

            eq assert error_id {CARDINALITY_MISMATCH_ERROR}
            // _ [lkmh] *witness
        );

        // Walking a UTXO list must land exactly at its end; otherwise a size
        // indicator was manipulated to hide entries from the loop.
        let assert_end_of_utxo_list = |field_salted_utxos: &[LabelledInstruction]| {
            triton_asm!(
                // _ [lkmh] *witness *utxos[N]_si
                dup 1 {&field_salted_utxos} {&field_utxos_with_size}
                // _ [lkmh] *witness *utxos[N]_si *utxos utxos_size

                {&crash_if_not_u32}
                // _ [lkmh] *witness *utxos[N]_si *utxos utxos_size

                add
                // _ [lkmh] *witness *utxos[N]_si (*utxos + utxos_size)

                /* Require that witness is fully contained on the 1st memory
                   page */
                {&crash_if_not_u32}
                // _ [lkmh] *witness *utxos[N]_si (*utxos + utxos_size)

                eq assert error_id {UTXOS_SIZE_MANIPULATION_ERROR}
                // _ [lkmh] *witness
            )
        };

        let payload = triton_asm!(
            {self.entrypoint()}:
            // _ [lkmh] *link_proof_witness disc

            place 6
            // _ disc [lkmh] *link_proof_witness

            addi 2
            hint witness = stack[0]
            // _ disc [lkmh] *witness
            // `disc` stays buried below the frame until the epilogue

            dup 0 call {audit_preloaded_data} pop 1
            // _ [lkmh] *witness

            {&authenticate_mutator_set_acc}
            {&authenticate_confirmed_inputs}
            {&authenticate_thruputs}
            {&authenticate_outputs}
            {&authenticate_no_coinbase}
            {&authenticate_merge_bit_false}
            {&assert_fee_is_valid_amount}
            {&assert_cardinality}
            // _ [lkmh] *witness

            /* Confirmed inputs: mutator-set membership + index-set integrity. */
            dup 0 {&field_confirmed_inputs} addi 1
            // _ [lkmh] *witness *rrs[0]_si

            dup 1 {&field_confirmed_inputs} read_mem 1 pop 1
            // _ [lkmh] *witness *rrs[0]_si num_confirmed

            push 0
            // _ [lkmh] *witness *rrs[0]_si num_confirmed 0

            dup 3 {&field_input_utxos} {&field_utxos} addi 1
            // _ [lkmh] *witness *rrs[0]_si num_confirmed 0 *utxos[0]_si

            dup 4 {&field_aocl}
            // _ [lkmh] *witness *rrs[0]_si num_confirmed 0 *utxos[0]_si *aocl

            call {for_all_confirmed}
            // _ [lkmh] *witness *rrs[n]_si n n *utxos[n]_si *aocl

            pop 1 swap 3 pop 3
            // _ [lkmh] *witness *utxos[num_confirmed]_si

            /* Ensure pointer is still in ND-region */
            {&crash_if_not_u32}

            /* Thruputs: each commits to the matching tail input UTXO. */
            dup 1 {&field_thruputs} read_mem 1 pop 1
            // _ [lkmh] *witness *utxos[nc]_si num_thruputs

            swap 1 push 0 swap 1
            // _ [lkmh] *witness num_thruputs 0 *utxos[nc]_si

            dup 3 {&field_thruputs} addi 1
            // _ [lkmh] *witness num_thruputs 0 *utxos[nc]_si *thruputs[0]

            call {for_all_addition_records}
            // _ [lkmh] *witness num_thruputs num_thruputs *utxos[N]_si *thruputs[N]

            pop 1 swap 2 pop 2
            // _ [lkmh] *witness *utxos[N]_si

            {&assert_end_of_utxo_list(&field_input_utxos)}
            // _ [lkmh] *witness

            /* Outputs: each addition record commits to the matching output
               UTXO -- `KernelToOutputs`, absorbed. */
            dup 0 {&field_outputs} read_mem 1 pop 1
            // _ [lkmh] *witness num_outputs

            push 0
            // _ [lkmh] *witness num_outputs 0

            dup 2 {&field_output_utxos} {&field_utxos} addi 1
            // _ [lkmh] *witness num_outputs 0 *output_utxos[0]_si

            dup 3 {&field_outputs} addi 1
            // _ [lkmh] *witness num_outputs 0 *output_utxos[0]_si *outputs[0]

            call {for_all_addition_records}
            // _ [lkmh] *witness num_outputs num_outputs *output_utxos[N]_si *outputs[N]

            pop 1 swap 2 pop 2
            // _ [lkmh] *witness *output_utxos[N]_si

            {&assert_end_of_utxo_list(&field_output_utxos)}
            // _ [lkmh] *witness

            /* Recursively verify every input lock script and every type script
               halts. */

            // Divine the inner (transaction kernel MAST) root and
            // authenticate it against lkmh: it is the left child of the
            // LinkKernel root, so hashing it with the right sibling calculated
            // from the thruputs field must reconstruct it.
            divine {Digest::LEN}
            // _ [lkmh] *witness [inner_root]

            dup 5 {&field_thruputs}
            {&right_lkmh_node_from_thruputs}
            // _ [lkmh] *witness [inner_root] [right_sibling]

            dup 9 dup 9 dup 9 dup 9 dup 9
            // _ [lkmh] *witness [inner_root] [right_sibling] [inner_root]

            hash
            // _ [lkmh] *witness [inner_root] [parent]
            // (parent = hash_pair(inner_root, right_sibling): tasm `hash` takes
            // the top operand as the first argument, so inner_root sits on top.)

            dup 15 dup 15 dup 15 dup 15 dup 15
            // _ [lkmh] *witness [inner_root] [parent] [lkmh]

            assert_vector error_id {INNER_ROOT_MISMATCH_ERROR}
            pop {Digest::LEN}
            // _ [lkmh] *witness [inner_root]

            // lkmh is no longer needed. Its last use was the authentication
            // above. So overwrite it with `inner_root`.
            // Both script-claim templates read
            // `inner_root` from the bottom of the stack, kept there for the
            // rest of the program rather than in static memory.
            pick 5
            pick 10 pop 1 pick 9 pop 1 pick 8 pop 1 pick 7 pop 1 pick 6 pop 1
            // _ [inner_root] *witness

            /* Type scripts. Recollect the deduplicated, native-currency-first
               type-script-hash list over `input_utxos` then `output_utxos`
               (absorbing `CollectTypeScripts`), then recursively verify one
               halting proof per unique hash. */
            call {new_list}
            // _ [inner_root] *witness *tsh

            dup 0 {&push_native_currency_hash} call {list_push_digest}
            // _ [inner_root] *witness *tsh            (native currency seeded first)

            dup 1 {&field_input_utxos} {&field_utxos} read_mem 1 addi 2 push 0 swap 1
            // _ [inner_root] *witness *tsh N 0 *utxos[0]_si
            call {collect_from_utxos}
            pop 3
            // _ [inner_root] *witness *tsh

            dup 1 {&field_output_utxos} {&field_utxos} read_mem 1 addi 2 push 0 swap 1
            // _ [inner_root] *witness *tsh N 0 *output_utxos[0]_si
            call {collect_from_utxos}
            pop 3
            // _ [inner_root] *witness *tsh

            // The number of proofs must match the number of unique type scripts:
            // a shortfall would otherwise make the loop read a proof past the
            // list and fail obscurely inside `StarkVerify`.
            dup 0 read_mem 1 pop 1
            // _ [inner_root] *witness *tsh num_ts
            dup 2 {&field_type_scripts_halt} read_mem 1 pop 1
            // _ [inner_root] *witness *tsh num_ts num_proofs
            eq assert error_id {WRONG_NUMBER_OF_TYPE_SCRIPT_PROOFS_ERROR}
            // _ [inner_root] *witness *tsh

            // Build the type-script claim template:
            //  - input: [inner_root, H(input_utxos), H(output_utxos)] (all
            //    reversed)
            //  - output: []
            //  - program digest: is (re)populated per unique hash in the loop.
            push {3 * Digest::LEN} push 0
            call {new_claim}
            // _ [inner_root] *witness *tsh *claim *output *input *program_digest

            // input[0..5] <- reversed(inner_root), copied from the stack bottom.
            // Dupping from increasing depths (stride 2: one deeper per group
            // word, one shallower per push) copies the digest already reversed.
            dup 6 dup 8 dup 10 dup 12 dup 14
            dup 6 write_mem {Digest::LEN} pop 1
            // _ [inner_root] *witness *tsh *claim *output *input *program_digest

            // input[5..10] <- reversed(H(input_utxos))
            dup 5 {&field_with_size_input_utxos} call {hash_varlen}
            pick 1 pick 2 pick 3 pick 4
            dup 6 addi {Digest::LEN} write_mem {Digest::LEN} pop 1
            // _ [inner_root] *witness *tsh *claim *output *input *program_digest

            // input[10..15] <- reversed(H(output_utxos))
            dup 5 {&field_with_size_output_utxos} call {hash_varlen}
            pick 1 pick 2 pick 3 pick 4
            dup 6 addi {2 * Digest::LEN} write_mem {Digest::LEN} pop 1
            // _ [inner_root] *witness *tsh *claim *output *input *program_digest

            // Drop *output, *input; keep *claim and the program-digest slot.
            place 2 pop 2
            // _ [inner_root] *witness *tsh *claim *program_digest

            dup 2 read_mem 1 pop 1
            // _ [inner_root] *witness *tsh *claim *program_digest num_ts

            push 0
            dup 4 addi 1
            // _ [inner_root] *witness *tsh *claim *program_digest num_ts 0 *tsh[0]

            dup 6 {&field_type_scripts_halt} addi 1
            // _ [inner_root] *witness *tsh *claim *program_digest num_ts 0 *tsh[0] *proofs[0]_si

            call {verify_type_scripts}
            // _ [inner_root] *witness *tsh *claim *program_digest num_ts num_ts *tsh[N] *proofs[N]_si

            /* Ensure pointer is in ND region */
            pop_count

            pop 5 pop 2
            // _ [inner_root] *witness

            /* Lock scripts. One halting proof per input UTXO, against the same
               inner root. */
            push {Digest::LEN} push 0
            call {new_claim}
            // _ [inner_root] *witness *claim *output *input *program_digest

            // input[0..5] <- reversed(inner_root); see the type-script claim.
            dup 5 dup 7 dup 9 dup 11 dup 13
            dup 6 write_mem {Digest::LEN} pop 1
            // _ [inner_root] *witness *claim *output *input *program_digest

            place 2 pop 2
            // _ [inner_root] *witness *claim *program_digest

            // Check cardinality: one lock script proof per input (confirmed or
            // thruput) UTXO.
            dup 2 {&field_input_utxos} {&field_utxos} read_mem 1 pop 1
            // _ [inner_root] *witness *claim *program_digest num_utxos
            dup 3 {&field_lock_scripts_halt} read_mem 1 pop 1
            // _ [inner_root] *witness *claim *program_digest num_utxos num_proofs
            eq assert error_id {WRONG_NUMBER_OF_LOCK_SCRIPT_PROOFS_ERROR}
            // _ [inner_root] *witness *claim *program_digest

            dup 2 {&field_input_utxos} {&field_utxos} read_mem 1 pop 1
            // _ [inner_root] *witness *claim *program_digest num_utxos

            push 0
            // _ [inner_root] *witness *claim *program_digest num_utxos 0

            dup 4 {&field_input_utxos} {&field_utxos} addi 1
            // _ [inner_root] *witness *claim *program_digest num_utxos 0 *utxos[0]_si

            dup 5 {&field_lock_scripts_halt} addi 1
            // _ [inner_root] *witness *claim *program_digest num_utxos 0 *utxos[0]_si *proofs[0]_si

            call {verify_lock_scripts}
            // _ disc [inner_root] *witness *claim *program_digest num_utxos num_utxos *utxos[N]_si *proofs[N]_si

            /* Ensure pointer is in ND region */
            pop_count

            pop 5 pop 1
            // _ disc [inner_root] *witness

            pick 6
            // _ [inner_root] *witness disc
            // (`inner_root` stays in the digest slot: it is the dispatcher's
            // scratch space, and the dispatcher pops it unread.)

            addi {-(DISCRIMINANT_FOR_FORGE as isize) - 1}
            // _ [lkmh] *witness -1

            return
        );

        // Deliberately a copy of `RemovalRecordsIntegrity`'s loop rather than a
        // shared Rust emitter. RRI's program hash is consensus-pinned and thus
        // frozen: sharing source would couple a frozen program to this evolving
        // one, so a future edit here could only ever risk RRI's hash for no
        // upside (a frozen program cannot benefit from a shared fix). The two
        // copies are instead kept honest by `forge_confirmed_loop_matches_rri`,
        // which fails the moment they diverge.
        let for_all_confirmed_loop = triton_asm!(
            // INVARIANT: _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl
            {for_all_confirmed}:
                dup 3 dup 3 eq
                skiz return
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl

                /* utxo hash -> static memory */
                dup 1 read_mem 1 addi 2 swap 1
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl *utxos[i] utxos[i]_size

                call {hash_varlen}
                hint utxo_hash = stack[0..5]
                push {utxo_hash_alloc.write_address()}
                write_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl

                /* commitment randomness -> static memory */
                divine {u64_stack_size}
                push {aocl_leaf_index_alloc.write_address()}
                write_mem {u64_stack_size}
                pop 1

                divine {Digest::LEN}
                push {receiver_preimage_alloc.write_address()}
                write_mem {Digest::LEN}
                pop 1

                divine {Digest::LEN}
                push {sender_randomness_alloc.write_address()}
                write_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl

                /* canonical commitment */
                dup 0 {&field_peaks}
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl *aocl_peaks

                push 0 push 0 push 0 push 0 push 0
                push {receiver_preimage_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                hash
                // _ ... *aocl_peaks [receiver_digest]

                push {sender_randomness_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                push {utxo_hash_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                // _ ... *aocl_peaks [receiver_digest] [sender_randomness] [utxo_hash]

                call {ms_commit}
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl *aocl_peaks [canonical_commitment]

                /* AOCL membership */
                dup 6 {&field_mmr_num_leafs}
                addi 1 read_mem {u64_stack_size} pop 1
                push {aocl_leaf_index_alloc.read_address()}
                read_mem {u64_stack_size} pop 1
                // _ ... *aocl_peaks [canonical_commitment] [num_leafs; 2] [aocl_leaf_index; 2]

                call {mmr_verify}
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl

                /* computed vs. claimed absolute index set */
                push {aocl_leaf_index_alloc.read_address()}
                read_mem {u64_stack_size} pop 1
                push {receiver_preimage_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                push {sender_randomness_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                push {utxo_hash_alloc.read_address()}
                read_mem {Digest::LEN} pop 1
                // _ ... *aocl [aocl_leaf_index] [receiver_preimage] [sender_randomness] [utxo_hash]

                call {compute_absolute_indices}
                call {hash_absolute_indices}
                pop 1
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl [computed]

                dup 9 addi 1 {&field_indices}
                call {hash_absolute_indices}
                pop 1
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl [computed] [claimed]

                {&compare_digests}
                assert error_id {COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR}
                // _ *rrs[i]_si num_confirmed i *utxos[i]_si *aocl

                /* advance */
                swap 1 read_mem 1
                // _ *rrs[i]_si num_confirmed i *aocl utxos[i]_si (*utxos[i]_si-1)

                push {MAX_JUMP_LENGTH} dup 2 lt
                assert error_id {JUMP_OUT_OF_BOUNDS_ERROR}

                addi 2 add
                // _ *rrs[i]_si num_confirmed i *aocl *utxos[i+1]_si

                swap 1
                swap 2 addi 1 swap 2
                // _ *rrs[i]_si num_confirmed (i+1) *utxos[i+1]_si *aocl

                swap 4 read_mem 1
                // _ *aocl num_confirmed (i+1) *utxos[i+1]_si rrs[i]_si (*rrs[i]_si-1)

                push {MAX_JUMP_LENGTH} dup 2 lt
                assert error_id {JUMP_OUT_OF_BOUNDS_ERROR}

                addi 2 add
                // _ *aocl num_confirmed (i+1) *utxos[i+1]_si *rrs[i+1]_si

                swap 4
                // _ *rrs[i+1]_si num_confirmed (i+1) *utxos[i+1]_si *aocl

                recurse
        );

        let for_all_addition_records_loop = triton_asm!(
            // INVARIANT: _ num i *utxos[i]_si *addition_records[i]
            {for_all_addition_records}:
                dup 3 dup 3 eq
                skiz return
                // _ num_thruputs i *utxos[i]_si *thruputs[i]

                /* Output-style commitment randomness: the receiver *digest*,
                   not a preimage. Divined *before* the UTXO hash so that the
                   hash -- computed last and needed only here -- lands on top,
                   the order `ms_commit` wants, with no static-memory detour. */
                divine {Digest::LEN}
                // _ num_thruputs i *utxos[i]_si *thruputs[i] [receiver_digest]

                divine {Digest::LEN}
                // _ ... [receiver_digest] [sender_randomness]

                /* utxo hash on top; *utxos[i]_si now sits under the two divined
                   digests, hence `dup {2 * Digest::LEN + 1}`. */
                dup {2 * Digest::LEN + 1} read_mem 1 addi 2 swap 1
                // _ .. [receiver_digest] [sender_randomness] *utxos[i] size

                call {hash_varlen}
                hint utxo_hash = stack[0..5]
                // _ ... [receiver_digest] [sender_randomness] [utxo_hash]

                call {ms_commit}
                // _ num_thruputs i *utxos[i]_si *thruputs[i] [canonical_commitment]

                dup 5 addi {Digest::LEN - 1}
                read_mem {Digest::LEN} pop 1
                // _ ... *thruputs[i] [canonical_commitment] [claimed]

                {&compare_digests}
                assert error_id {UTXO_COMMITMENT_MISMATCH_ERROR}
                // _ num_thruputs i *utxos[i]_si *thruputs[i]

                /* advance */
                addi {Digest::LEN}
                // _ num_thruputs i *utxos[i]_si *thruputs[i+1]

                swap 1 read_mem 1
                // _ num_thruputs i *thruputs[i+1] utxos[i]_si (*utxos[i]_si-1)

                push {MAX_JUMP_LENGTH} dup 2 lt
                assert error_id {JUMP_OUT_OF_BOUNDS_ERROR}
                // _ num_thruputs i *thruputs[i+1] utxos[i]_si (*utxos[i]_si-1)

                addi 2 add
                // _ num_thruputs i *thruputs[i+1] *utxos[i+1]_si

                swap 1
                // _ num_thruputs i *utxos[i+1]_si *thruputs[i+1]

                swap 2 addi 1 swap 2
                // _ num_thruputs (i+1) *utxos[i+1]_si *thruputs[i+1]

                recurse
        );

        // Walk `input_utxos` and `lock_scripts_halt` in parallel (both
        // size-prefixed), stamping each UTXO's `lock_script_hash` into the
        // shared claim template's program-digest slot and recursively verifying
        // the matching halting proof against it.
        let verify_lock_scripts_loop = triton_asm!(
            // INVARIANT: _ *claim *pd num_utxos i *utxos[i]_si *proofs[i]_si
            {verify_lock_scripts}:
                dup 3 dup 3 eq skiz return
                // _ *claim *pd num_utxos i *utxos[i]_si *proofs[i]_si

                /* program-digest slot <- utxos[i].lock_script_hash */
                dup 1 addi 1 {&field_lock_script_hash}
                addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
                // _ *claim *pd num_utxos i *utxos[i]_si *proofs[i]_si [lock_script_hash]

                dup 9 write_mem {Digest::LEN} pop 1
                // _ *claim *pd num_utxos i *utxos[i]_si *proofs[i]_si

                /* verify lock_scripts_halt[i] against the claim */
                dup 5
                dup 1 addi 1
                call {stark_verify}
                // _ *claim *pd num_utxos i *utxos[i]_si *proofs[i]_si

                /* advance *proofs_si past this size-prefixed proof */
                read_mem 1 addi 1 add addi 1
                // _ *claim *pd num_utxos i *utxos[i]_si *proofs[i+1]_si

                /* advance *utxos_si past this size-prefixed UTXO */
                swap 1
                read_mem 1 addi 1 add addi 1
                swap 1
                // _ *claim *pd num_utxos i *utxos[i+1]_si *proofs[i+1]_si

                swap 2 addi 1 swap 2
                // _ *claim *pd num_utxos (i+1) *utxos[i+1]_si *proofs[i+1]_si

                recurse
        );

        // Walk the deduplicated type-script-hash list and `type_scripts_halt` in
        // parallel, stamping each unique hash into the shared claim template's
        // program-digest slot and recursively verifying the matching proof.
        // Mirrors `verify_lock_scripts`, but the program digest is the list
        // element itself (fixed `Digest::LEN` stride) rather than a UTXO field.
        let verify_type_scripts_loop = triton_asm!(
            // INVARIANT: _ *claim *pd num_ts i *tsh[i] *proofs[i]_si
            {verify_type_scripts}:
                dup 3 dup 3 eq skiz return
                // _ *claim *pd num_ts i *tsh[i] *proofs[i]_si

                /* program-digest slot <- type_script_hashes[i] */
                dup 1 addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1
                // _ *claim *pd num_ts i *tsh[i] *proofs[i]_si [ts_hash]

                dup 9 write_mem {Digest::LEN} pop 1
                // _ *claim *pd num_ts i *tsh[i] *proofs[i]_si

                /* verify type_scripts_halt[i] against the claim */
                dup 5
                dup 1 addi 1
                call {stark_verify}
                // _ *claim *pd num_ts i *tsh[i] *proofs[i]_si

                /* advance *proofs_si past this size-prefixed proof */
                read_mem 1 addi 1 add addi 1
                // _ *claim *pd num_ts i *tsh[i] *proofs[i+1]_si

                /* advance *tsh past this digest (fixed stride) */
                swap 1 addi {Digest::LEN} swap 1
                // _ *claim *pd num_ts i *tsh[i+1] *proofs[i+1]_si

                swap 2 addi 1 swap 2
                // _ *claim *pd num_ts (i+1) *tsh[i+1] *proofs[i+1]_si

                recurse
        );

        // Deduplicated type-script-hash collection, copied instruction-for-
        // instruction from `CollectTypeScripts` (renamed local labels and the
        // `TOO_MANY_COINS` error id aside). Kept honest by
        // `forge_collect_type_scripts_matches_cts`, which fails the moment the
        // three subroutines drift from their `CollectTypeScripts` originals.
        let collect_type_script_hashes = triton_asm!(
            // INVARIANT: _ *type_script_hashes N i *utxos[i]_si
            {collect_from_utxos}:
                dup 2 dup 2 eq
                skiz return
                // _ *tsh N i *utxos[i]_si

                dup 0 addi 1 {&field_coins}
                // _ *tsh N i *utxos[i]_si *coins

                read_mem 1 addi 2
                // _ *tsh N i *utxos[i]_si len *coins[0]_si

                push {MAX_NUM_COINS_PER_UTXO}
                dup 2
                lt
                assert error_id {TOO_MANY_COINS_ERROR}
                // _ *tsh N i *utxos[i]_si len *coins[0]_si

                push 0 swap 1
                // _ *tsh N i *utxos[i]_si len 0 *coins[0]_si

                call {collect_from_coins}
                // _ *tsh N i *utxos[i]_si len len *coins[len]_si

                /* Ensure pointer is inside allowed ND-memory region */
                pop_count

                pop 3
                // _ *tsh N i *utxos[i]_si

                read_mem 1 addi 2
                // _ *tsh N i size *utxos[i]

                /* Ensure forward jump, by ensuring size is u32 */
                dup 1
                pop_count
                pop 1

                add
                // _ *tsh N i *utxos[i+1]_si

                swap 1 addi 1 swap 1
                // _ *tsh N (i+1) *utxos[i+1]_si

                recurse

            // INVARIANT: _ *type_script_hashes * * * len j *coin[j]_si
            {collect_from_coins}:
                dup 2 dup 2 eq
                skiz return
                // _ *tsh * * * len j *coin[j]_si

                read_mem 1 addi 2
                // _ *tsh * * * len j size *coin[j]

                dup 7 dup 0 dup 2 {&field_type_script_hash}
                // _ ... *coin[j] *tsh *tsh *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ ... *coin[j] *tsh *tsh [digest]

                call {contains}
                // _ ... *coin[j] *tsh ([digest] in *tsh)

                push 0 eq
                // _ ... *coin[j] *tsh ([digest] not in *tsh)

                skiz call {push_ts_hash_from_coin}
                // _ ... *coin[j] garbage

                /* Ensure forward jump, by ensuring size is u32 */
                dup 2
                pop_count
                pop 2
                // _ *tsh * * * len j size *coin[j]

                add
                // _ *tsh * * * len j *coin[j+1]_si

                swap 1 addi 1 swap 1
                // _ *tsh * * * len (j+1) *coin[j+1]_si

                recurse

            // BEFORE: _ *coin[j] *type_script_hashes
            // AFTER:  _ *coin[j] *
            {push_ts_hash_from_coin}:
                dup 1
                // _ *coin[j] *tsh *coin[j]

                {&field_type_script_hash}
                // _ *coin[j] *tsh *digest

                addi {Digest::LEN-1} read_mem {Digest::LEN} pop 1
                // _ *coin[j] *tsh [digest]

                call {list_push_digest}
                // _ *coin[j]

                push {0x2b00b5}

                return
        );

        triton_asm!(
            {&payload}
            {&for_all_confirmed_loop}
            {&for_all_addition_records_loop}
            {&verify_lock_scripts_loop}
            {&verify_type_scripts_loop}
            {&collect_type_script_hashes}
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use neptune_mutator_set::commit;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestRunner;
    use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
    use test_strategy::proptest;

    use super::*;
    use crate::chaintx::mock_single_proof_digest;
    use crate::proof_abstractions::tasm::builtins as tasm;
    use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
    use crate::proof_abstractions::triton_vm_job_queue::vm_job_queue;
    use crate::transaction::primitive_witness::PrimitiveWitness;
    use crate::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::transaction::utxo::Utxo;
    use crate::transaction::validity::removal_records_integrity::RemovalRecordsIntegrity;
    use crate::type_scripts::native_currency_amount::NativeCurrencyAmount;

    impl ForgeWitness {
        /// Cheap test-only constructor: identical to
        /// [`produce`](Self::produce), except it skips lock-script proving.
        ///
        /// Gated behind `#[cfg(test)]` on purpose. `produce` is the sole
        /// *production* constructor -- a real `ForgeWitness` always carries its
        /// proofs, and there is no proofless path into live code. However, many
        /// tests (negative tests for example, but others too) don't touch
        /// proofs, and proving as a prerequisite makes running those tests take
        /// impractically long. These tests build their witnesses here; only the
        /// positive proof-verifying tests pay the steep price for `produce`.
        #[cfg(test)]
        pub(crate) fn without_proofs(lpw: &LinkPrimitiveWitness) -> Self {
            Self::build_from_parts(lpw, mock_single_proof_digest(0), vec![], vec![])
        }
    }

    /// The real instructions of the subroutine `label` -- everything between
    /// its label definition and the next one, keeping only `Instruction`
    /// elements, with static-memory addresses rebased by
    /// [`rebase_static_addresses`]. That drops the label, the assertion error
    /// ids (`AssertionContext`), type hints, and where in the static region the
    /// program happened to put its `kmalloc`s: exactly the parts that may
    /// legitimately differ between two copies of the same loop.
    fn extract_loop_body(code: &[LabelledInstruction], label: &str) -> Vec<LabelledInstruction> {
        let start = code
            .iter()
            .position(|i| matches!(i, LabelledInstruction::Label(l) if l == label))
            .unwrap_or_else(|| panic!("loop label `{label}` not found"));
        let body = code[start + 1..]
            .iter()
            .take_while(|i| !matches!(i, LabelledInstruction::Label(_)))
            .filter(|i| matches!(i, LabelledInstruction::Instruction(_)))
            .cloned()
            .collect_vec();

        rebase_static_addresses(&body)
    }

    /// Rewrite every `push` of a static-memory address to that address's
    /// distance below the top of the block the body touches.
    ///
    /// Two copies of a loop make the same `kmalloc`s, but not necessarily at the
    /// same ordinal: a program that allocates anything ahead of them pushes the
    /// whole block down, and every address in the copy shifts by a constant. The
    /// block's *internal* layout is the shared property, so that is what gets
    /// compared. An allocation inserted among the block's own slots, or one of
    /// them resized, moves the offsets relative to each other and still fails
    /// the comparison.
    ///
    /// The static region is a narrow, fixed range at the very top of the address
    /// space, so no honest small constant is mistaken for an address.
    fn rebase_static_addresses(body: &[LabelledInstruction]) -> Vec<LabelledInstruction> {
        use tasm_lib::library::STATIC_MEMORY_FIRST_ADDRESS;
        use tasm_lib::library::STATIC_MEMORY_LAST_ADDRESS;
        use tasm_lib::triton_vm::isa::instruction::AnInstruction;

        let offset_below_top = |address: BFieldElement| {
            (STATIC_MEMORY_LAST_ADDRESS.value()..=STATIC_MEMORY_FIRST_ADDRESS.value())
                .contains(&address.value())
                .then(|| STATIC_MEMORY_FIRST_ADDRESS.value() - address.value())
        };
        let pushed_offset = |instruction: &LabelledInstruction| match instruction {
            LabelledInstruction::Instruction(AnInstruction::Push(address)) => {
                offset_below_top(*address)
            }
            _ => None,
        };

        // The block's top: the smallest distance below the static region's top
        // that this body reaches. Nothing to rebase if it touches no addresses.
        let Some(base) = body.iter().filter_map(pushed_offset).min() else {
            return body.to_vec();
        };

        body.iter()
            .map(|instruction| match pushed_offset(instruction) {
                Some(offset) => {
                    LabelledInstruction::Instruction(AnInstruction::Push(bfe!(offset - base)))
                }
                None => instruction.clone(),
            })
            .collect()
    }

    /// `Forge` inlines a byte-for-byte copy of `RemovalRecordsIntegrity`'s
    /// confirmed-input loop (see the comment at its definition for why it is a
    /// copy and not a shared emitter). This guard fails the moment the two
    /// diverge. Imported-snippet call labels coincide because both programs
    /// import the same snippets; static-memory addresses coincide only up to
    /// where each program's block of four `kmalloc`s starts, which is what
    /// [`rebase_static_addresses`] normalizes away.
    #[test]
    fn forge_confirmed_loop_matches_rri() {
        let (_, rri_code) = RemovalRecordsIntegrity.library_and_code();
        let (_, forge_code) = LinkProof.library_and_code();

        let rri_loop = extract_loop_body(&rri_code, "for_all_utxos");
        let forge_loop = extract_loop_body(
            &forge_code,
            "neptune_consensus_chaintx_forge_for_all_confirmed",
        );

        assert!(!rri_loop.is_empty(), "extracted an empty RRI loop");
        assert_eq!(
            rri_loop, forge_loop,
            "Forge's confirmed-input loop has drifted from RemovalRecordsIntegrity's"
        );
    }

    /// Proves `loop_body` (hence `forge_confirmed_loop_matches_rri`) has teeth:
    /// two loops that differ in a real instruction compare unequal, while a
    /// difference only in the label or an error id -- the parametric parts --
    /// does not.
    #[test]
    fn loop_body_detects_divergence() {
        let base = triton_asm!(
            entry: dup 0 push 5 eq assert error_id {100_i128} addi 1 recurse
        );
        // Same body, different label and error id: must still compare equal.
        let parametric = triton_asm!(
            other: dup 0 push 5 eq assert error_id {200_i128} addi 1 recurse
        );
        // One real instruction changed: must compare unequal.
        let diverged = triton_asm!(
            entry: dup 0 push 5 eq assert error_id {100_i128} addi 2 recurse
        );

        let base_body = extract_loop_body(&base, "entry");
        assert!(!base_body.is_empty());
        assert_eq!(base_body, extract_loop_body(&parametric, "other"));
        assert_ne!(base_body, extract_loop_body(&diverged, "entry"));
    }

    /// The other half of the teeth: [`rebase_static_addresses`] must forgive a
    /// block of `kmalloc`s starting lower in the static region, and only that.
    /// Two slots that move *relative to each other* -- an allocation inserted
    /// among them, or one of them resized -- must still compare unequal.
    #[test]
    fn rebasing_forgives_a_shifted_block_and_nothing_else() {
        use tasm_lib::library::STATIC_MEMORY_FIRST_ADDRESS;

        let top = STATIC_MEMORY_FIRST_ADDRESS;
        let two_slots = |first: BFieldElement, second: BFieldElement| {
            triton_asm!(
                entry:
                    push {first} read_mem 5 pop 1
                    push {second} write_mem 2
                    push 5
                    recurse
            )
        };

        // The same two slots, five words further down: must compare equal.
        let block = two_slots(top, top - bfe!(4));
        let shifted_block = two_slots(top - bfe!(5), top - bfe!(9));
        assert_eq!(
            extract_loop_body(&block, "entry"),
            extract_loop_body(&shifted_block, "entry"),
        );

        // The gap between the two slots widened: must compare unequal.
        let resized_slot = two_slots(top, top - bfe!(5));
        assert_ne!(
            extract_loop_body(&block, "entry"),
            extract_loop_body(&resized_slot, "entry"),
        );

        // `push 5` is not an address and must survive rebasing untouched --
        // otherwise the normalization would forgive a real divergence.
        let diverged = triton_asm!(
            entry:
                push {top} read_mem 5 pop 1
                push {top - bfe!(4)} write_mem 2
                push 6
                recurse
        );
        assert_ne!(
            extract_loop_body(&block, "entry"),
            extract_loop_body(&diverged, "entry"),
        );
    }

    /// Rewrite calls to program-local subroutines (labelled `neptune_consensus_*`
    /// -- whose names legitimately differ between two copies) to a fixed
    /// placeholder, leaving calls to shared library imports (`tasmlib_*` /
    /// `tasm_*`, whose generated labels coincide) intact. Lets two copied
    /// subroutine bodies be compared across programs.
    fn normalize_local_calls(body: &[LabelledInstruction]) -> Vec<LabelledInstruction> {
        use tasm_lib::triton_vm::isa::instruction::AnInstruction;
        body.iter()
            .map(|instr| match instr {
                LabelledInstruction::Instruction(AnInstruction::Call(label))
                    if label.starts_with("neptune_consensus_") =>
                {
                    LabelledInstruction::Instruction(AnInstruction::Call("LOCAL".to_string()))
                }
                other => other.clone(),
            })
            .collect()
    }

    /// `Forge` inlines a near-verbatim copy of `CollectTypeScripts`' three
    /// type-script-hash collection subroutines (see the comment at their
    /// definition for why they are copied and not shared). This guard fails the
    /// moment any of them drifts. Calls to the copies' own local subroutines are
    /// normalized (those labels differ by design); error ids and labels are
    /// dropped by `extract_loop_body`, exactly as in
    /// `forge_confirmed_loop_matches_rri`. The `contains`/`push`
    /// library-import calls and the coin-field accessors coincide, so no other
    /// normalization is needed.
    #[test]
    fn forge_collect_type_scripts_matches_cts() {
        use crate::transaction::validity::collect_type_scripts::CollectTypeScripts;

        let (_, cts_code) = CollectTypeScripts.library_and_code();
        let (_, forge_code) = LinkProof.library_and_code();

        // (CollectTypeScripts label, Forge label) for each copied subroutine.
        let pairs = [
            (
                "neptune_consensus_transaction_collect_type_script_hashes_from_utxo",
                "neptune_consensus_chaintx_forge_collect_type_script_hashes_from_utxos",
            ),
            (
                "neptune_consensus_transaction_collect_type_script_hashes_from_coin",
                "neptune_consensus_chaintx_forge_collect_type_script_hashes_from_coins",
            ),
            (
                "neptune_consensus_transaction_push_digest_to_list",
                "neptune_consensus_chaintx_forge_push_type_script_hash_from_coin",
            ),
        ];

        for (cts_label, forge_label) in pairs {
            let cts = normalize_local_calls(&extract_loop_body(&cts_code, cts_label));
            let forge = normalize_local_calls(&extract_loop_body(&forge_code, forge_label));
            assert!(
                !cts.is_empty(),
                "extracted an empty CollectTypeScripts subroutine `{cts_label}`"
            );
            assert_eq!(
                cts, forge,
                "Forge's `{forge_label}` has drifted from CollectTypeScripts' `{cts_label}`"
            );
        }
    }

    /// The `Forge` branch of the `LinkProof` rust shadow, called by
    /// [`LinkProof::source`](super::super::link_proof::LinkProof) once it has
    /// read `lkmh` off stdin and matched the witness discriminant -- mirroring
    /// the tasm, where the dispatcher does exactly that before `call`ing this
    /// branch.
    pub(in crate::chaintx) fn forge_branch_source(lkmh: Digest, witness: ForgeWitnessMemory) {
        let input_utxos: &[Utxo] = &witness.input_utxos.utxos;
        let aocl: MmrAccumulator = witness.aocl;

        // authenticate the mutator set accumulator (mirrors the shared
        // `AuthenticateMsaAgainstTxk` snippet: bag only the AOCL, take the
        // swbfi/swbfa digests from the witness)
        let left = Tip5::hash_pair(aocl.bag_peaks(), witness.swbfi_bagged);
        let right = Tip5::hash_pair(witness.swbfa_hash, Digest::default());
        let msah: Digest = Tip5::hash_pair(left, right);
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::MutatorSetHash as u32,
            Tip5::hash(&msah),
            LinkKernel::MAST_HEIGHT as u32,
        );

        // authenticate the confirmed removal records and the thruputs
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::Inputs as u32,
            Tip5::hash(&witness.confirmed_inputs),
            LinkKernel::MAST_HEIGHT as u32,
        );
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::Thruputs as u32,
            Tip5::hash(&witness.thruputs),
            LinkKernel::MAST_HEIGHT as u32,
        );
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::Outputs as u32,
            Tip5::hash(&witness.outputs),
            LinkKernel::MAST_HEIGHT as u32,
        );

        // a LinkTx is never a coinbase transaction and never pre-merged
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::Coinbase as u32,
            no_coinbase_leaf(),
            LinkKernel::MAST_HEIGHT as u32,
        );
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::MergeBit as u32,
            merge_bit_false_leaf(),
            LinkKernel::MAST_HEIGHT as u32,
        );

        // the kernel's fee is a non-negative amount in range
        tasm::tasmlib_hashing_merkle_verify(
            lkmh,
            LinkKernelField::Fee as u32,
            Tip5::hash(&witness.fee),
            LinkKernel::MAST_HEIGHT as u32,
        );
        assert!(!witness.fee.is_negative());
        assert!(witness.fee <= NativeCurrencyAmount::max());

        // the two input kinds exactly cover the type-script-facing list
        let num_confirmed: usize = witness.confirmed_inputs.len();
        let num_thruputs: usize = witness.thruputs.len();
        assert_eq!(input_utxos.len(), num_confirmed + num_thruputs);

        let output_utxos: &[Utxo] = &witness.output_utxos.utxos;
        let num_outputs: usize = witness.outputs.len();
        assert_eq!(output_utxos.len(), num_outputs);

        // confirmed inputs: RemovalRecordsIntegrity, inlined
        let mut i: usize = 0;
        while i < num_confirmed {
            let utxo_hash = Tip5::hash(&input_utxos[i]);

            let aocl_leaf_index: u64 = tasm::tasmlib_io_read_secin___u64();
            let receiver_preimage: Digest = tasm::tasmlib_io_read_secin___digest();
            let sender_randomness: Digest = tasm::tasmlib_io_read_secin___digest();
            let addition_record: AdditionRecord =
                commit(utxo_hash, sender_randomness, receiver_preimage.hash());
            assert!(tasm::mmr_verify_from_secret_in_leaf_index_on_stack(
                &aocl.peaks(),
                aocl.num_leafs(),
                aocl_leaf_index,
                addition_record.canonical_commitment,
            ));

            let index_set = AbsoluteIndexSet::compute(
                utxo_hash,
                sender_randomness,
                receiver_preimage,
                aocl_leaf_index,
            );
            assert_eq!(index_set, witness.confirmed_inputs[i].absolute_indices);

            i += 1;
        }

        // thruputs: each commits to the matching tail input UTXO
        let mut j: usize = 0;
        while j < num_thruputs {
            let utxo_hash = Tip5::hash(&input_utxos[num_confirmed + j]);

            let receiver_digest: Digest = tasm::tasmlib_io_read_secin___digest();
            let sender_randomness: Digest = tasm::tasmlib_io_read_secin___digest();
            let addition_record: AdditionRecord =
                commit(utxo_hash, sender_randomness, receiver_digest);
            assert_eq!(addition_record, witness.thruputs[j]);

            j += 1;
        }

        // outputs: each addition record commits to the matching output UTXO
        let mut k: usize = 0;
        while k < num_outputs {
            let utxo_hash = Tip5::hash(&output_utxos[k]);

            let receiver_digest: Digest = tasm::tasmlib_io_read_secin___digest();
            let sender_randomness: Digest = tasm::tasmlib_io_read_secin___digest();
            let addition_record: AdditionRecord =
                commit(utxo_hash, sender_randomness, receiver_digest);
            assert_eq!(addition_record, witness.outputs[k]);

            k += 1;
        }

        // Divine the inner (height-3) TransactionKernel root and bind it to
        // lkmh: it is the left child of the LinkKernel root, so hashing it
        // with the right child must reconstruct lkmh. The right child is
        // computed, not divined: its subtree holds only the `Thruputs` leaf
        // (already authenticated above) and default-digest padding. Preimage
        // resistance then pins `inner_root` to the genuine left child -- but
        // only the *retained* value is authenticated, so the tasm must keep
        // this exact digest (not re-divine) and feed it to the claims below.
        let inner_root: Digest = tasm::tasmlib_io_read_secin___digest();
        let d1 = Digest::default();
        let d2 = Tip5::hash_pair(d1, d1);
        let d4 = Tip5::hash_pair(d2, d2);
        let thruputs_leaf = Tip5::hash_varlen(&witness.thruputs.encode());
        let n1 = Tip5::hash_pair(thruputs_leaf, d1);
        let n2 = Tip5::hash_pair(n1, d2);
        let right_child = Tip5::hash_pair(n2, d4);
        assert_eq!(lkmh, Tip5::hash_pair(inner_root, right_child));

        // Verify the scripts in the same order the tasm does: type scripts
        // first, then lock scripts. The order is immaterial to what is
        // proven, but the shadow must consume the witness proofs (and the
        // nondeterminism) in the same sequence as the program.

        // every unique type script must halt on the inner root plus the two
        // salted-UTXO hashes -- the input the type scripts see
        let type_script_input: Vec<BFieldElement> = [
            inner_root,
            Tip5::hash(&witness.input_utxos),
            Tip5::hash(&witness.output_utxos),
        ]
        .into_iter()
        .flat_map(|d| d.reversed().values())
        .collect();
        let type_script_hashes = Utxo::type_script_hashes(input_utxos.iter().chain(output_utxos));
        assert_eq!(type_script_hashes.len(), witness.type_scripts_halt.len());
        let mut ts: usize = 0;
        while ts < type_script_hashes.len() {
            let claim = Claim::new(type_script_hashes[ts]).with_input(type_script_input.clone());
            tasm::verify_stark(Stark::default(), &claim, &witness.type_scripts_halt[ts]);
            ts += 1;
        }

        // every input lock script must halt on that same inner kernel root
        assert_eq!(input_utxos.len(), witness.lock_scripts_halt.len());
        let lock_script_input: Vec<BFieldElement> = inner_root.reversed().values().to_vec();
        let mut l: usize = 0;
        while l < input_utxos.len() {
            let claim =
                Claim::new(input_utxos[l].lock_script_hash()).with_input(lock_script_input.clone());
            tasm::verify_stark(Stark::default(), &claim, &witness.lock_scripts_halt[l]);
            l += 1;
        }
    }

    fn deterministic_lpw(num_inputs: usize, num_thruputs: usize) -> LinkPrimitiveWitness {
        let mut test_runner = TestRunner::deterministic();
        let pw = PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), 2, 1)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        LinkPrimitiveWitness::from_primitive_witness(pw, num_thruputs)
    }

    /// A valid witness of fixed shape (1 confirmed input, 1 thruput, 2 outputs)
    /// with random contents. The shape is fixed -- not drawn from
    /// [`LinkPrimitiveWitness::arbitrary_strategy`], which allows zero thruputs
    /// -- so every index the rejection tests poke (`[0]` of each list) always
    /// exists.
    fn pokeable_lpw() -> proptest::strategy::BoxedStrategy<LinkPrimitiveWitness> {
        use proptest::strategy::Strategy;
        PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1)
            .prop_map(|pw| LinkPrimitiveWitness::from_primitive_witness(pw, 1))
            .boxed()
    }

    /// A deterministic fully proven witness, for the positive tests that
    /// recursively verify the lock scripts. Proving is slow, so keep the
    /// callers few.
    async fn deterministic_forge_witness_proven(
        num_inputs: usize,
        num_thruputs: usize,
    ) -> ForgeWitness {
        ForgeWitness::produce(
            &deterministic_lpw(num_inputs, num_thruputs),
            mock_single_proof_digest(0),
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap()
    }

    /// `Forge` writes nothing to stdout, so the assertion is that both the Rust
    /// shadow and the tasm run to completion: every `assert` in either one
    /// held.
    fn prop_positive(witness: ForgeWitness) {
        LinkProof
            .run_rust(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
        LinkProof
            .run_tasm(&witness.standard_input(), witness.nondeterminism())
            .unwrap();
    }

    /// The tree rebuilt from the stored leafs must be the kernel's own tree --
    /// otherwise `standard_input` and every authentication path are quietly
    /// wrong together, and the positive tests would still pass.
    #[proptest(cases = 4)]
    fn rebuilt_mast_tree_matches_the_kernel(
        #[strategy(LinkPrimitiveWitness::arbitrary_strategy())] lpw: LinkPrimitiveWitness,
    ) {
        let witness = ForgeWitness::without_proofs(&lpw);
        prop_assert_eq!(witness.mast_tree().root(), lpw.kernel.mast_hash());
        for field in [
            LinkKernelField::MutatorSetHash,
            LinkKernelField::Inputs,
            LinkKernelField::Thruputs,
            LinkKernelField::Coinbase,
            LinkKernelField::MergeBit,
        ] {
            prop_assert_eq!(
                witness
                    .mast_tree()
                    .authentication_structure(&[field.discriminant()])
                    .unwrap(),
                lpw.kernel.mast_path(field)
            );
        }
    }

    /// The inner height-3 root derived from the first eight leafs must equal
    /// the `TransactionKernel`'s own MAST hash -- the value lock and
    /// type scripts were proven against. If this drifts, every recursive
    /// script-proof claim is fed the wrong input and silently fails to bind.
    #[proptest(cases = 4)]
    fn inner_kernel_root_matches_transaction_kernel(
        #[strategy(LinkPrimitiveWitness::arbitrary_strategy())] lpw: LinkPrimitiveWitness,
    ) {
        let witness = ForgeWitness::without_proofs(&lpw);
        prop_assert_eq!(
            witness.inner_kernel_mast_hash(),
            lpw.kernel.kernel.mast_hash()
        );
        // the inner root and its right sibling reconstruct the LinkKernel root
        let (inner, right) = witness.inner_root_and_right_sibling();
        prop_assert_eq!(Tip5::hash_pair(inner, right), lpw.kernel.mast_hash());
    }

    /// Every confirmed/thruput split of a small transaction forges. `produce`
    /// proves the lock scripts; `Forge` recursively verifies them.
    #[tokio::test]
    async fn forge_accepts_valid_witnesses() {
        for num_inputs in 0..=3 {
            for num_thruputs in 0..=num_inputs {
                prop_positive(deterministic_forge_witness_proven(num_inputs, num_thruputs).await);
            }
        }
    }

    /// A transaction whose UTXOs carry timelocked coins succeeds `Forge`.
    ///
    /// This unit test actually exercises the deduplicated type-script loop with
    /// more than one entry -- the list is `[NativeCurrency, TimeLock]`.
    ///
    /// Native-currency-only witnesses (above) only ever reach the
    /// single-element path.
    #[tokio::test]
    async fn forge_accepts_timelocked_witness() {
        use neptune_primitives::network::Network;
        use neptune_primitives::timestamp::Timestamp;
        use proptest::strategy::ValueTree;
        use proptest_arbitrary_interop::arb;

        use crate::type_scripts::time_lock::neptune_arbitrary::arbitrary_primitive_witness_with_expired_timelocks;

        let mut test_runner = TestRunner::deterministic();
        let now = arb::<Timestamp>()
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        // Expired (released) timelocks: the transaction is *valid* -- so its
        // TimeLock type script halts and can be proven -- while still carrying a
        // TimeLock coin, forcing the two-element unique type-script list.
        let pw = arbitrary_primitive_witness_with_expired_timelocks(2, 2, 1, now)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let lpw = LinkPrimitiveWitness::from_primitive_witness(pw, 1);

        // Sanity: the witness really carries a timelock type script, so this
        // test is not silently a native-currency-only case.
        assert_eq!(
            2,
            Utxo::type_script_hashes(lpw.input_utxos.utxos.iter().chain(&lpw.output_utxos.utxos))
                .len()
        );

        let witness = ForgeWitness::produce(
            &lpw,
            mock_single_proof_digest(0),
            vm_job_queue(),
            TritonVmProofJobOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(2, witness.type_scripts_halt.len());
        prop_positive(witness.clone());
        assert!(witness.validate(Network::Main).await);
    }

    /// `validate` accepts a produced witness (so it predicts `Forge`'s
    /// acceptance) and rejects a tampered one -- both the inlined-integrity half
    /// and the lock-script-proof-coverage guard.
    #[tokio::test]
    async fn validate_matches_forge() {
        use neptune_primitives::network::Network;
        let network = Network::Main;

        let witness = deterministic_forge_witness_proven(2, 1).await;
        assert!(witness.validate(network).await);

        // tamper the thruput commitment randomness -> integrity check fails
        let mut bad_commitment = witness.clone();
        bad_commitment.thruput_sender_randomnesses[0] = Digest::default();
        assert!(!bad_commitment.validate(network).await);

        // drop a lock-script proof -> coverage guard fails
        let mut missing_proof = witness.clone();
        missing_proof.lock_scripts_halt.pop();
        assert!(!missing_proof.validate(network).await);

        // drop the (native-currency) type-script proof -> coverage guard fails
        let mut missing_type_proof = witness.clone();
        missing_type_proof.type_scripts_halt.pop();
        assert!(!missing_type_proof.validate(network).await);
    }

    /// The cheap integrity half accepts every valid proofless witness -- the
    /// exhaustive positive complement to the six per-branch rejection tests
    /// below, which needs no proving.
    #[proptest(cases = 20)]
    fn valid_witness_passes_integrity(
        #[strategy(LinkPrimitiveWitness::arbitrary_strategy())] lpw: LinkPrimitiveWitness,
    ) {
        prop_assert!(ForgeWitness::without_proofs(&lpw).validate_integrity());
    }

    /// A phantom input UTXO -- one backed by neither a removal record nor a
    /// thruput -- is the direct inflation path, since type scripts count every
    /// entry of `input_utxos` toward the input balance.
    #[proptest(cases = 4)]
    fn phantom_input_utxo_is_rejected(#[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        let phantom = witness.input_utxos.utxos[0].clone();
        witness.input_utxos.utxos.push(phantom);
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[CARDINALITY_MISMATCH_ERROR],
            )
            .unwrap();
    }

    /// The direct output-side inflation path: show the type scripts one set of
    /// output UTXOs while the kernel commits to addition records for another.
    /// Without `KernelToOutputs` absorbed into `Forge`, nothing catches this.
    #[proptest(cases = 4)]
    fn output_utxos_unbound_to_addition_records_is_rejected(
        #[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness,
    ) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        let inflated = witness.output_utxos.utxos[0].get_native_currency_amount()
            + NativeCurrencyAmount::coins(42);
        witness.output_utxos.utxos[0] =
            witness.output_utxos.utxos[0].new_with_native_currency_amount(inflated);
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[UTXO_COMMITMENT_MISMATCH_ERROR],
            )
            .unwrap();
    }

    /// The input-side twin, and the sharper of the two: show the type scripts a
    /// confirmed input UTXO that is not the one its removal record spends.
    ///
    /// Every entry of `input_utxos` counts toward the input balance, so a UTXO
    /// no record backs is money from nowhere -- and cardinality cannot see it,
    /// the count being untouched. What catches it is the inlined
    /// `RemovalRecordsIntegrity` membership check: the canonical commitment
    /// recomputed from the poked UTXO is no longer the AOCL leaf the membership
    /// proof authenticates, so `MmrVerifyFromSecretInLeafIndexOnStack` rejects
    /// before the index-set comparison downstream gets a look.
    ///
    /// `pokeable_lpw` puts the one confirmed input at index 0, the thruput after
    /// it; the thruput's own version of this is `tampered_thruput_is_rejected`.
    #[proptest(cases = 4)]
    fn confirmed_input_utxo_unbound_to_its_removal_record_is_rejected(
        #[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness,
    ) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        let inflated = witness.input_utxos.utxos[0].get_native_currency_amount()
            + NativeCurrencyAmount::coins(42);
        witness.input_utxos.utxos[0] =
            witness.input_utxos.utxos[0].new_with_native_currency_amount(inflated);
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                // The root comparison inside
                // `MmrVerifyFromSecretInLeafIndexOnStack`. tasm-lib names no
                // constant for it, so the id is written out.
                &[10],
            )
            .unwrap();
    }

    /// Likewise for the count: an output UTXO backed by no addition record.
    #[proptest(cases = 4)]
    fn phantom_output_utxo_is_rejected(#[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        let phantom = witness.output_utxos.utxos[0].clone();
        witness.output_utxos.utxos.push(phantom);
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[CARDINALITY_MISMATCH_ERROR],
            )
            .unwrap();
    }

    #[proptest(cases = 4)]
    fn tampered_thruput_is_rejected(#[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        witness.thruput_sender_randomnesses[0] = Digest::default();
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[UTXO_COMMITMENT_MISMATCH_ERROR],
            )
            .unwrap();
    }

    /// The removal records are bound to the kernel: adding one that the kernel
    /// does not carry fails authentication, *before* the cardinality check gets
    /// a chance to notice the count is off.
    #[proptest(cases = 4)]
    fn unauthenticated_removal_record_is_rejected(
        #[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness,
    ) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        witness
            .confirmed_inputs
            .push(witness.confirmed_inputs[0].clone());
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            )
            .unwrap();
    }

    /// Likewise for the thruputs leaf, which is the new leaf `LinkKernel` adds.
    #[proptest(cases = 4)]
    fn unauthenticated_thruput_is_rejected(#[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        witness.thruputs[0].canonical_commitment = Digest::default();
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            )
            .unwrap();
    }

    /// The tasm rejects a witness with fewer type-script proofs than unique type
    /// scripts: a proofless witness has otherwise-intact integrity, so `Forge`
    /// runs all the way to the type-script proof-count guard (native currency is
    /// always collected, so the deduplicated list is non-empty while
    /// `type_scripts_halt` is empty). This is the tasm analog of `validate`'s
    /// type-script coverage check -- and it needs no proving to reach.
    #[proptest(cases = 4)]
    fn missing_type_script_proof_is_rejected(
        #[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness,
    ) {
        let witness = ForgeWitness::without_proofs(&lpw);
        prop_assert!(witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[WRONG_NUMBER_OF_TYPE_SCRIPT_PROOFS_ERROR],
            )
            .unwrap();
    }

    /// Symmetric to the above, on the lock-script side. The type-script proofs
    /// must be intact to pass their guard and loop, so this needs a *produced*
    /// witness (unlike the proofless type-script case) -- then dropping a
    /// lock-script proof trips the lock-script count guard.
    #[tokio::test]
    async fn missing_lock_script_proof_is_rejected() {
        let mut witness = deterministic_forge_witness_proven(1, 0).await;
        witness.lock_scripts_halt.pop();
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[WRONG_NUMBER_OF_LOCK_SCRIPT_PROOFS_ERROR],
            )
            .unwrap();
    }

    /// A mutator-set accumulator that disagrees with the kernel's committed
    /// `MutatorSetHash` is rejected: the recomputed hash no longer authenticates
    /// against the `LinkKernel` MAST root. Sharper than the proof-free tier
    /// (which surfaces it only as `InvalidMembershipProof`). This is also the one
    /// negative test that exercises the shared `AuthenticateMsaAgainstTxk`
    /// snippet's rejection path.
    #[proptest(cases = 4)]
    fn bad_mutator_set_accumulator_is_rejected(
        #[strategy(pokeable_lpw())] lpw: LinkPrimitiveWitness,
    ) {
        let mut witness = ForgeWitness::without_proofs(&lpw);
        witness.swbfa_hash = Digest::default();
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
            )
            .unwrap();
    }

    /// A coinbase transaction, or one that has already been through `Merge`,
    /// cannot be forged. Both leafs are constants the branch authenticates
    /// directly, so a kernel holding anything else has the wrong *leaf*, not
    /// merely the wrong value -- hence `ROOT_MISMATCH` rather than an assert of
    /// `Forge`'s own.
    ///
    /// The kernel is poked before the witness is built, so the MAST tree, the
    /// claim and every authentication path are rebuilt around it together and
    /// the constant-leaf authentication is the only thing left to fail.
    ///
    /// `Chain`, `Update` and `Cast` each carry this negative already. `Forge`'s
    /// is the one that closes the pipeline: it is where a `LinkKernel` is minted
    /// rather than derived from one a `LinkProof` already vouches for, so every
    /// branch downstream is entitled to assume the two leafs by induction --
    /// `Fix` included, which is why it needs no coinbase negative of its own.
    #[proptest(cases = 4)]
    fn coinbase_or_merge_bit_on_the_forged_kernel_is_rejected(
        #[strategy(pokeable_lpw())] original: LinkPrimitiveWitness,
    ) {
        for modifier in [
            TransactionKernelModifier::default().coinbase(Some(NativeCurrencyAmount::coins(1))),
            TransactionKernelModifier::default().merge_bit(true),
        ] {
            let mut lpw = original.clone();
            lpw.kernel.kernel = modifier.modify(lpw.kernel.kernel);

            let witness = ForgeWitness::without_proofs(&lpw);
            prop_assert!(!witness.validate_integrity());
            LinkProof
                .test_assertion_failure(
                    witness.standard_input(),
                    witness.nondeterminism(),
                    &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
                )
                .unwrap();
        }
    }

    /// A confirmed removal record whose claimed absolute index set does not match
    /// the one recomputed from its UTXO and randomness is rejected -- the inlined
    /// `RemovalRecordsIntegrity` check that a bad index set (a double-spend path
    /// if unchecked) cannot slip through. The kernel is rebuilt around the poked
    /// record so its `Inputs` leaf still authenticates and the *index* check is
    /// the surviving failure (mirrors `removal_records_fail_on_bad_absolute_indices`).
    #[proptest(cases = 4)]
    fn bad_absolute_index_set_is_rejected(
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 1))]
        mut pw: PrimitiveWitness,
    ) {
        let mut inputs = pw.kernel.inputs.clone();
        inputs[0].absolute_indices.increment_bloom_filter_index(0);
        pw.kernel = TransactionKernelModifier::default()
            .inputs(inputs)
            .modify(pw.kernel);
        // 1 thruput => input[0] stays a confirmed input.
        let witness =
            ForgeWitness::without_proofs(&LinkPrimitiveWitness::from_primitive_witness(pw, 1));
        prop_assert!(!witness.validate_integrity());
        LinkProof
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR],
            )
            .unwrap();
    }
}
