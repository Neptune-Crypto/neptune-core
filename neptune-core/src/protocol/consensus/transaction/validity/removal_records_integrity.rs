use std::collections::HashMap;
use std::sync::OnceLock;

use field_count::FieldCount;
use get_size2::GetSize;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tasm_lib::data_type::DataType;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_static_size::HashStaticSize;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::merkle_verify::MerkleVerify;
use tasm_lib::library::Library;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::mmr::bag_peaks::BagPeaks;
use tasm_lib::mmr::verify_from_secret_in_leaf_index_on_stack::MmrVerifyFromSecretInLeafIndexOnStack;
use tasm_lib::neptune::mutator_set;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_membership_proof::MmrMembershipProof;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tasm_lib::twenty_first::util_types::mmr::shared_basic::leaf_index_to_mt_index_and_peak_index;

use crate::protocol::consensus::transaction::primitive_witness::SaltedUtxos;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::tasm::compute_absolute_indices::ComputeAbsoluteIndices;
use crate::protocol::consensus::transaction::PrimitiveWitness;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;

const COINBASE_HAS_INPUTS_ERROR: i128 = 1_000_000;
const COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR: i128 = 1_000_001;
const INPUT_UTXO_AND_REMOVAL_RECORDS_LENGTH_MISMATCH: i128 = 1_000_002;
const JUMP_OUT_OF_BOUNDS: i128 = 1_000_003;
const INPUT_UTXOS_SIZE_MANIPILATION: i128 = 1_000_004;

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    GetSize,
    BFieldCodec,
    FieldCount,
    TasmObject,
)]
pub struct RemovalRecordsIntegrityWitness {
    input_utxos: SaltedUtxos,
    membership_proofs: Vec<MsMembershipProof>,
    aocl_auth_paths: Vec<MmrMembershipProof>,
    coinbase: Option<NativeCurrencyAmount>,
    removal_records: Vec<RemovalRecord>,
    aocl: MmrAccumulator,
    swbfi: MmrAccumulator,
    swbfa_hash: Digest,
    mast_path_mutator_set: Vec<Digest>,
    mast_path_inputs: Vec<Digest>,
    mast_path_coinbase: Vec<Digest>,
    mast_root: Digest,
}

impl From<&PrimitiveWitness> for RemovalRecordsIntegrityWitness {
    fn from(primitive_witness: &PrimitiveWitness) -> Self {
        Self {
            input_utxos: primitive_witness.input_utxos.clone(),
            membership_proofs: primitive_witness.input_membership_proofs.clone(),
            aocl_auth_paths: primitive_witness
                .input_membership_proofs
                .iter()
                .map(|x| x.auth_path_aocl.to_owned())
                .collect(),
            coinbase: primitive_witness.kernel.coinbase,
            removal_records: primitive_witness.kernel.inputs.clone(),
            aocl: primitive_witness.mutator_set_accumulator.aocl.clone(),
            swbfi: primitive_witness
                .mutator_set_accumulator
                .swbf_inactive
                .clone(),
            swbfa_hash: Tip5::hash(&primitive_witness.mutator_set_accumulator.swbf_active),
            mast_path_mutator_set: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::MutatorSetHash),
            mast_path_inputs: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::Inputs),
            mast_path_coinbase: primitive_witness
                .kernel
                .mast_path(TransactionKernelField::Coinbase),
            mast_root: primitive_witness.kernel.mast_hash(),
        }
    }
}

/// The parts of the [`RemovalRecordsIntegrityWitness`] that are initialized in
/// memory at the start of each execution.
#[derive(Clone, Debug, BFieldCodec, TasmObject)]
struct RemovalRecordsIntegrityWitnessMemory {
    input_utxos: SaltedUtxos,
    coinbase: Option<NativeCurrencyAmount>,
    removal_records: Vec<RemovalRecord>,
    aocl: MmrAccumulator,
    swbfi: MmrAccumulator,
}

impl From<&RemovalRecordsIntegrityWitness> for RemovalRecordsIntegrityWitnessMemory {
    fn from(value: &RemovalRecordsIntegrityWitness) -> Self {
        Self {
            input_utxos: value.input_utxos.to_owned(),
            coinbase: value.coinbase,
            removal_records: value.removal_records.to_owned(),
            aocl: value.aocl.to_owned(),
            swbfi: value.swbfi.to_owned(),
        }
    }
}

impl SecretWitness for RemovalRecordsIntegrityWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let memory_part: RemovalRecordsIntegrityWitnessMemory = self.into();

        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &memory_part,
        );

        let mut nd_stream: Vec<BFieldElement> = self.swbfa_hash.reversed().values().to_vec();
        for msmp in &self.membership_proofs {
            let mut u64_as_stream = msmp.aocl_leaf_index.encode();
            u64_as_stream.reverse();
            nd_stream.extend(&u64_as_stream);

            nd_stream.extend(&msmp.receiver_preimage.reversed().values());
            nd_stream.extend(&msmp.sender_randomness.reversed().values());
        }

        // set digests
        let digests = [
            self.mast_path_mutator_set.clone(),
            self.mast_path_inputs.clone(),
            self.mast_path_coinbase.clone(),
            self.aocl_auth_paths
                .iter()
                .flat_map(|x| x.authentication_path.clone())
                .collect_vec(),
        ]
        .concat();

        NonDeterminism::new(nd_stream)
            .with_ram(memory)
            .with_digests(digests)
    }

    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.mast_root.reversed().values().to_vec())
    }

    fn output(&self) -> Vec<BFieldElement> {
        Tip5::hash(&self.input_utxos).values().to_vec()
    }

    fn program(&self) -> Program {
        RemovalRecordsIntegrity.program()
    }
}

#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount, BFieldCodec,
)]
pub struct RemovalRecordsIntegrity;

impl RemovalRecordsIntegrityWitness {
    pub fn pseudorandom_merkle_root_with_authentication_paths(
        seed: [u8; 32],
        tree_height: usize,
        leafs_and_indices: &[(Digest, u64)],
    ) -> (Digest, Vec<Vec<Digest>>) {
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut nodes: HashMap<u64, Digest> = HashMap::new();

        // populate nodes dictionary with leafs
        for (leaf, index) in leafs_and_indices {
            nodes.insert(*index, *leaf);
        }

        // walk up tree layer by layer
        // when we need nodes not already present, sample at random
        let mut depth = tree_height + 1;
        while depth > 0 {
            let mut working_indices = nodes
                .keys()
                .copied()
                .filter(|&i| u128::from(i) < (1 << depth) && u128::from(i) >= (1 << (depth - 1)))
                .collect_vec();
            working_indices.sort();
            working_indices.dedup();
            for wi in working_indices {
                let wi_odd = wi | 1;
                nodes
                    .entry(wi_odd)
                    .or_insert_with(|| rng.random::<Digest>());
                let wi_even = wi_odd ^ 1;
                nodes
                    .entry(wi_even)
                    .or_insert_with(|| rng.random::<Digest>());
                let hash = Tip5::hash_pair(nodes[&wi_even], nodes[&wi_odd]);
                nodes.insert(wi >> 1, hash);
            }
            depth -= 1;
        }

        // read out root
        let root = *nodes.get(&1).unwrap_or(&rng.random());

        // read out paths
        let paths = leafs_and_indices
            .iter()
            .map(|(_d, i)| {
                (0..tree_height)
                    .map(|j| *nodes.get(&((*i >> j) ^ 1)).unwrap())
                    .collect_vec()
            })
            .collect_vec();

        (root, paths)
    }

    pub fn pseudorandom_mmra_with_mps(
        seed: [u8; 32],
        leafs: &[Digest],
    ) -> (MmrAccumulator, Vec<(u64, MmrMembershipProof)>) {
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        // sample size of MMR
        let mut leaf_count = rng.next_u64();
        while leaf_count < leafs.len() as u64 {
            leaf_count = rng.next_u64();
        }
        let num_peaks = leaf_count.count_ones();

        // sample mmr leaf indices and calculate matching derived indices
        let leaf_indices = leafs
            .iter()
            .enumerate()
            .map(|(original_index, _leaf)| (original_index, rng.next_u64() % leaf_count))
            .map(|(original_index, mmr_index)| {
                let (mt_index, peak_index) =
                    leaf_index_to_mt_index_and_peak_index(mmr_index, leaf_count);
                (original_index, mmr_index, mt_index, peak_index)
            })
            .collect_vec();
        let leafs_and_indices = leafs.iter().copied().zip(leaf_indices).collect_vec();

        // iterate over all trees
        let mut peaks = vec![];
        let dummy_mp = MmrMembershipProof::new(vec![]);
        let mut mps = (0..leafs.len())
            .map(|i| (i as u64, dummy_mp.clone()))
            .collect_vec();
        for tree in 0..num_peaks {
            // select all leafs and merkle tree indices for this tree
            let leafs_and_mt_indices = leafs_and_indices
                .iter()
                .copied()
                .filter(
                    |(_leaf, (_original_index, _mmr_index, _mt_index, peak_index))| {
                        *peak_index == tree
                    },
                )
                .map(
                    |(leaf, (original_index, _mmr_index, mt_index, _peak_index))| {
                        (leaf, mt_index, original_index)
                    },
                )
                .collect_vec();
            if leafs_and_mt_indices.is_empty() {
                peaks.push(rng.random());
                continue;
            }

            // generate root and authentication paths
            let tree_height =
                u128::from(*leafs_and_mt_indices.first().map(|(_l, i, _o)| i).unwrap()).ilog2()
                    as usize;
            let (root, authentication_paths) =
                Self::pseudorandom_merkle_root_with_authentication_paths(
                    rng.random(),
                    tree_height,
                    &leafs_and_mt_indices
                        .iter()
                        .map(|(l, i, _o)| (*l, *i))
                        .collect_vec(),
                );

            // update peaks list
            peaks.push(root);

            // generate membership proof objects
            let membership_proofs = leafs_and_indices
                .iter()
                .copied()
                .filter(
                    |(_leaf, (_original_index, _mmr_index, _mt_index, peak_index))| {
                        *peak_index == tree
                    },
                )
                .zip(authentication_paths.into_iter())
                .map(
                    |(
                        (_leaf, (_original_index, mmr_index, _mt_index, _peak_index)),
                        authentication_path,
                    )| {
                        (mmr_index, MmrMembershipProof::new(authentication_path))
                    },
                )
                .collect_vec();

            // sanity check: test if membership proofs agree with peaks list (up until now)
            let dummy_remainder: Vec<Digest> = (peaks.len()..num_peaks as usize)
                .map(|_| rng.random())
                .collect_vec();
            let dummy_peaks = [peaks.clone(), dummy_remainder].concat();
            for (&(leaf, _mt_index, _original_index), (mmr_leaf_index, mp)) in
                leafs_and_mt_indices.iter().zip(membership_proofs.iter())
            {
                assert!(mp.verify(*mmr_leaf_index, leaf, &dummy_peaks, leaf_count));
            }

            // collect membership proofs in vector, with indices matching those of the supplied leafs
            for ((_leaf, _mt_index, original_index), (mmr_leaf_index, mp)) in
                leafs_and_mt_indices.iter().zip(membership_proofs.iter())
            {
                mps[*original_index] = (*mmr_leaf_index, mp.clone());
            }
        }

        let mmra = MmrAccumulator::init(peaks, leaf_count);

        // sanity check
        for (&leaf, (mmr_leaf_index, mp)) in leafs.iter().zip(mps.iter()) {
            assert!(mp.verify(*mmr_leaf_index, leaf, &mmra.peaks(), mmra.num_leafs()));
        }

        (mmra, mps)
    }
}

impl ConsensusProgram for RemovalRecordsIntegrity {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        type MmrAccumulatorTip5 = MmrAccumulator;
        const MAX_JUMP_LENGTH: usize = 2_000_000;

        let mut library = Library::new();

        let bag_peaks = library.import(Box::new(BagPeaks));
        let merkle_verify = library.import(Box::new(MerkleVerify));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let ms_commit = library.import(Box::new(mutator_set::commit::Commit));
        let mmr_verify = library.import(Box::new(MmrVerifyFromSecretInLeafIndexOnStack));

        let compute_absolute_indices = library.import(Box::new(ComputeAbsoluteIndices));
        let hash_absolute_indices = library.import(Box::new(HashStaticSize {
            size: AbsoluteIndexSet::static_length().expect("absolute indices have a static size"),
        }));

        let field_aocl = field!(RemovalRecordsIntegrityWitnessMemory::aocl);
        let field_swbfi = field!(RemovalRecordsIntegrityWitnessMemory::swbfi);
        let field_peaks = field!(MmrAccumulatorTip5::peaks);
        let field_input_utxos = field!(RemovalRecordsIntegrityWitnessMemory::input_utxos);
        let field_utxos = field!(SaltedUtxos::utxos);
        let field_utxos_with_size = field_with_size!(SaltedUtxos::utxos);
        let field_with_size_removal_records =
            field_with_size!(RemovalRecordsIntegrityWitnessMemory::removal_records);
        let field_with_size_input_utxos =
            field_with_size!(RemovalRecordsIntegrityWitnessMemory::input_utxos);
        let field_removal_records = field!(RemovalRecordsIntegrityWitnessMemory::removal_records);
        let field_with_size_coinbase =
            field_with_size!(RemovalRecordsIntegrityWitnessMemory::coinbase);
        let field_coinbase = field!(RemovalRecordsIntegrityWitnessMemory::coinbase);

        let for_all_utxos = "for_all_utxos".to_string();

        let authenticate_mutator_set_acc_against_txkmh = triton_asm!(
            // _ [txk_mast_hash] *witness
            dup 5
            dup 5
            dup 5
            dup 5
            dup 5
            // _ [txk_mast_hash] *witness [txk_mast_hash]

            push {TransactionKernel::MAST_HEIGHT}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h

            dup 6
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness

            push 0
            push 0
            push 0
            push 0
            push 1
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding]

            push 0
            push 0
            push 0
            push 0
            push 0
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [default]

            divine {Digest::LEN}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [default] [swbfa_hash]

            hash
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right]

            dup 10 {&field_swbfi}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] *swbfi

            call {bag_peaks}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [swbfi_hash]

            dup 15 {&field_aocl}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [swbfi_hash] *aocl

            call {bag_peaks}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [swbfi_hash] [aocl_hash]

            hash
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [right] [left]

            hash
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [padding] [msa_hash]

            sponge_init sponge_absorb
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness

            sponge_squeeze
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [garbage] [msa_hash_as_leaf]

            swap 5 pop 1
            swap 5 pop 1
            swap 5 pop 1
            swap 5 pop 1
            swap 5 pop 1
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [msa_hash_as_leaf]

            push {TransactionKernelField::MutatorSetHash as u32}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h *witness [msa_hash] i

            swap 6 pop 1
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i [msa_hash]

            call {merkle_verify}
            // _ [txk_mast_hash] *witness
        );

        let authenticate_removal_records_against_txkmh = triton_asm!(
            // _ [txk_mast_hash] *witness
            dup 5
            dup 5
            dup 5
            dup 5
            dup 5
            // _ [txk_mast_hash] *witness [txk_mast_hash]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Inputs as u32}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i

            dup 7 {&field_with_size_removal_records}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i *removal_records size

            call {hash_varlen}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i [removal_records_hash]

            call {merkle_verify}
            // _ [txk_mast_hash] *witness
        );

        let authenticate_coinbase_against_txkmh = triton_asm!(
            // _ [txk_mast_hash] *witness
            dup 5
            dup 5
            dup 5
            dup 5
            dup 5
            // _ [txk_mast_hash] *witness [txk_mast_hash]

            push {TransactionKernel::MAST_HEIGHT}
            push {TransactionKernelField::Coinbase as u32}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i

            dup 7 {&field_with_size_coinbase}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i *coinbase size

            call {hash_varlen}
            // _ [txk_mast_hash] *witness [txk_mast_hash] h i [coinbase_leaf]

            call {merkle_verify}
            // _ [txk_mast_hash] *witness
        );

        let assert_that_coinbase_transaction_does_not_have_inputs = triton_asm!(
            // _ [txk_mast_hash] *witness

            dup 0
            {&field_coinbase}
            // _ [txk_mast_hash] *witness *coinbase

            read_mem 1
            pop 1
            push 0
            eq
            // _ [txk_mast_hash] *witness (coinbase == None)

            dup 1 {&field_input_utxos} {&field_utxos}
            // _ [txk_mast_hash] *witness (coinbase == None) *utxos

            read_mem 1
            pop 1
            // _ [txk_mast_hash] *witness (coinbase == None) num_utxos

            push 0
            eq
            // _ [txk_mast_hash] *witness (coinbase == None) (num_utxos == 0)

            add
            // _ [txk_mast_hash] *witness ((coinbase == None) + (num_utxos == 0))

            /* Allowed result of st[0] is 1 or 2, 0 is not allowed. Possible
               results are {0, 1, 2} */

            pop_count
            assert error_id {COINBASE_HAS_INPUTS_ERROR}
            // _ [txk_mast_hash] *witness
        );

        let audit_preloaded_data = library.import(Box::new(VerifyNdSiIntegrity::<
            RemovalRecordsIntegrityWitnessMemory,
        >::default()));

        let payload = triton_asm! {
            /* read txkmh */
            read_io {Digest::LEN}
            hint txk_mast_hash = stack[0..5]
            // _ [txk_mast_hash]

            /* point to witness */
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint witness = stack[0]
            // _ [txk_mast_hash] *witness

            dup 0
            call {audit_preloaded_data}
            // _ [txk_mast_hash] *witness witness_size

            pop 1
            // _ [txk_mast_hash] *witness

            {&authenticate_mutator_set_acc_against_txkmh}
            // _ [txk_mast_hash] *witness


            /* authenticate divined removal records against txk mast hash */
            {&authenticate_removal_records_against_txkmh}
            // _ [txk_mast_hash] *witness

            /* authenticate divined coinbase against txk mast hash */
            {&authenticate_coinbase_against_txkmh}
            // _ [txk_mast_hash] *witness

            {&assert_that_coinbase_transaction_does_not_have_inputs}
            // _ [txk_mast_hash] *witness

            /* Prepare for main loop */
            dup 0 {&field_aocl}
            hint aocl = stack[0]
            // _ [txk_mast_hash] *witness *aocl

            dup 1 {&field_input_utxos} {&field_utxos}
            // _ [txk_mast_hash] *witness *aocl *utxos

            read_mem 1 addi 2
            // _ [txk_mast_hash] *witness *aocl num_utxos *utxos[0]_si

            push 0 swap 1
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si

            dup 4 {&field_removal_records}
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si *removal_records

            read_mem 1 addi 2
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si removal_records_len *removal_records[0]_si

            swap 1
            dup 4
            eq
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si *removal_records[0]_si (removal_records_len == num_utxos)

            assert error_id {INPUT_UTXO_AND_REMOVAL_RECORDS_LENGTH_MISMATCH}
            // _ [txk_mast_hash] *witness *aocl num_utxos 0 *utxos[0]_si *removal_records[0]_si

            swap 4
            hint aocl = stack[0]
            hint utxos_i_si = stack[1]
            hint i = stack[2]
            hint num_utxos = stack[3]
            hint removal_records_i_si = stack[4]
            // _ [txk_mast_hash] *witness *removal_records[0]_si num_utxos 0 *utxos[0]_si *aocl

            // INVARIANT: _ *witness *removal_records[0]_si num_utxos 0 *utxos[0]_si *aocl
            call {for_all_utxos}
            // _ [txk_mast_hash] *witness *removal_records[num_utxos]_si num_utxos num_utxos *utxos[num_utxos]_si *aocl

            pick 1 place 4
            // _ [txk_mast_hash] *witness *utxos[num_utxos]_si *removal_records[num_utxos]_si num_utxos num_utxos *aocl

            pop 4
            // _ [txk_mast_hash] *witness *utxos[num_utxos]_si

            /* compute and output hash of salted input UTXOs */
            dup 1
            // _ [txk_mast_hash] *witness *utxos[num_utxos]_si *witness

            place 7
            // _ *witness [txk_mast_hash] *witness *utxos[num_utxos]_si

            swap 1
            // _ *witness [txk_mast_hash] *utxos[num_utxos]_si *witness

            {&field_with_size_input_utxos}
            // _ *witness [txk_mast_hash] *utxos[num_utxos]_si *salted_input_utxos size

            dup 1 {&field_utxos_with_size}
            // _ *witness [txk_mast_hash] *utxos[num_utxos]_si *salted_input_utxos size *utxos size

            add
            // _ *witness [txk_mast_hash] *utxos[num_utxos]_si *salted_input_utxos size *utxos[num_utxos]_si

            pick 3 eq assert error_id {INPUT_UTXOS_SIZE_MANIPILATION}
            // _ *witness [txk_mast_hash] *salted_input_utxos size

            call {hash_varlen}
            // _ *witness [txk_mast_hash] [salted_input_utxos_hash]

            write_io 5
            // _ *witness [txk_mast_hash]

            pop {Digest::LEN}
            pop 1
            // _

            halt
        };

        let field_mmr_num_leafs = field!(MmrAccumulatorTip5::leaf_count);
        let field_indices = field!(RemovalRecord::absolute_indices);

        let compare_digests = DataType::Digest.compare();

        let u64_stack_size: u32 = DataType::U64.stack_size().try_into().unwrap();
        let aocl_leaf_index_alloc = library.kmalloc(u64_stack_size);

        let digest_stack_size: u32 = DataType::Digest.stack_size().try_into().unwrap();
        let receiver_preimage_alloc = library.kmalloc(digest_stack_size);
        let sender_randomness_alloc = library.kmalloc(digest_stack_size);
        let utxo_hash_alloc = library.kmalloc(digest_stack_size);

        let for_all_utxos_loop = triton_asm! {
            // INVARIANT: _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl
            {for_all_utxos}:
                /*
                    1. Check loop stop-condition
                    2. Calculate UTXO hash, store to static memory
                    3. Get AOCL leaf index, store to static memory
                    4. Get receiver preimage, store to static memory
                    5. Get sender randomness, store to static memory
                    6. Calculate canonical commitment
                    7. Verify AOCL-membership of canonical commitment
                    8. Calculate SWBF-indices
                    9. Verify equality with claimed SWBF-indices
                    10. Prepare for next loop iteration
                 */


                /* 1. */
                dup 3 dup 3 eq
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl (num_utxos == i)

                skiz return
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl


                /* 2. */
                dup 1
                read_mem 1
                addi 2
                swap 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *utxos[i] utxos[i]_size

                call {hash_varlen}
                hint utxo_hash = stack[0..5]
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [utxo_hash]

                push {utxo_hash_alloc.write_address()}
                write_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl


                /* 3. */
                divine {u64_stack_size}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [aocl_leaf_index]

                push {aocl_leaf_index_alloc.write_address()}
                write_mem {u64_stack_size}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl


                /* 4. */
                divine {Digest::LEN}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [receiver_preimage]

                push {receiver_preimage_alloc.write_address()}
                write_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl


                /* 5. */
                divine {Digest::LEN}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [sender_randomness]

                push {sender_randomness_alloc.write_address()}
                write_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl

                /* 6. */
                dup 0
                {&field_peaks}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks

                push 0
                push 0
                push 0
                push 0
                push 0
                push {receiver_preimage_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [default] [receiver_preimage]

                hash
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [receiver_digest]

                push {sender_randomness_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [receiver_digest] [sender_randomness]

                push {utxo_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [receiver_digest] [sender_randomness] [utxo_hash]

                call {ms_commit}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [canonical_commitment]


                /* 7. */
                dup 6 {&field_mmr_num_leafs}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [canonical_commitment] *num_leafs

                addi 1 read_mem {u64_stack_size} pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [canonical_commitment] [num_leafs]

                push {aocl_leaf_index_alloc.read_address()}
                read_mem {u64_stack_size}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *aocl_peaks [canonical_commitment] [num_leafs] [aocl_leaf_index]

                call {mmr_verify}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl

                /* 8. */
                push {aocl_leaf_index_alloc.read_address()}
                read_mem {u64_stack_size}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [aocl_leaf_index]

                push {receiver_preimage_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [aocl_leaf_index] [receiver_preimage]

                push {sender_randomness_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [aocl_leaf_index] [receiver_preimage] [sender_randomness]

                push {utxo_hash_alloc.read_address()}
                read_mem {Digest::LEN}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [aocl_leaf_index] [receiver_preimage] [sender_randomness] [utxo_hash]

                call {compute_absolute_indices}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl *absolute_indices

                call {hash_absolute_indices}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [computed_bloom_indices]

                /* 9. */
                dup 9
                addi 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [computed_bloom_indices] *rrs[i]

                {&field_indices}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [computed_bloom_indices] *claimed_indices[i]

                call {hash_absolute_indices}
                pop 1
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl [computed_bloom_indices_h] [claimed_indices_h]

                {&compare_digests}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl (computed_bloom_indices_h == claimed_indices_h)

                assert error_id {COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR}
                // _ *rrs[i]_si num_utxos i *utxos[i]_si *aocl

                /* 10. */
                swap 1
                read_mem 1
                // _ *rrs[i]_si num_utxos i *aocl utxos[i]_si (*utxos[i]_si-1)

                push {MAX_JUMP_LENGTH}
                // _ *rrs[i]_si num_utxos i *aocl utxos[i]_si (*utxos[i]_si-1) MAX_JUMP_LEN

                dup 2
                lt
                // _ *rrs[i]_si num_utxos i *aocl utxos[i]_si (*utxos[i]_si-1) (utxos[i]_si < MAX_JUMP_LEN)
                assert error_id {JUMP_OUT_OF_BOUNDS}

                addi 2
                // _ *rrs[i]_si num_utxos i *aocl utxos[i]_si *utxos[i]

                add
                // _ *rrs[i]_si num_utxos i *aocl *utxos[i+1]_si

                swap 1
                // _ *rrs[i]_si num_utxos i *utxos[i + 1]_si *aocl

                swap 2
                addi 1
                swap 2
                // _ *rrs[i]_si num_utxos (i + 1) *utxos[i + 1]_si *aocl

                swap 4
                read_mem 1
                // _ *aocl num_utxos (i + 1) *utxos[i + 1]_si rrs[i]_si (*rrs[i]_si-1)

                push {MAX_JUMP_LENGTH}
                // _ *aocl num_utxos (i + 1) *utxos[i + 1]_si rrs[i]_si (*rrs[i]_si-1) MAX_JUMP_LENGTH

                dup 2
                lt
                // _ *aocl num_utxos (i + 1) *utxos[i + 1]_si rrs[i]_si (*rrs[i]_si-1) (rrs[i]_si < MAX_JUMP_LENGTH)

                assert error_id {JUMP_OUT_OF_BOUNDS}
                // _ *aocl num_utxos (i + 1) *utxos[i + 1]_si rrs[i]_si (*rrs[i]_si-1)

                addi 2
                // _ *aocl num_utxos (i + 1) *utxos[i + 1]_si rrs[i]_si *rrs[i]

                add
                // _ *aocl num_utxos (i + 1) *utxos[i + 1]_si *rrs[i+1]_si

                swap 4
                // _ *rrs[i + 1]_si num_utxos (i + 1) *utxos[i + 1]_si *aocl

                recurse
        };

        let imports = library.all_imports();
        let code = triton_asm!(
            {&payload}
            {&for_all_utxos_loop}
            {&imports}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASH: OnceLock<Digest> = OnceLock::new();

        *HASH.get_or_init(|| self.program().hash())
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
pub mod neptune_arbitrary {
    use arbitrary::Arbitrary;

    use super::*;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelProxy;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;

    impl<'a> Arbitrary<'a> for RemovalRecordsIntegrityWitness {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let num_inputs = u.int_in_range(1..=3usize)?;
            let _num_outputs = u.int_in_range(1..=3usize)?;
            let _num_announcements = u.int_in_range(0..=2usize)?;

            let input_utxos: Vec<Utxo> = (0..num_inputs)
                .map(|_| u.arbitrary().unwrap())
                .collect_vec();
            let mut membership_proofs: Vec<MsMembershipProof> = (0..num_inputs)
                .map(|_| u.arbitrary().unwrap())
                .collect_vec();
            let addition_records: Vec<AdditionRecord> = input_utxos
                .iter()
                .zip(membership_proofs.iter())
                .map(|(utxo, msmp)| {
                    commit(
                        Tip5::hash(utxo),
                        msmp.sender_randomness,
                        msmp.receiver_preimage.hash(),
                    )
                })
                .collect_vec();
            let canonical_commitments = addition_records
                .iter()
                .map(|ar| ar.canonical_commitment)
                .collect_vec();
            let (aocl, mmr_mps) =
                Self::pseudorandom_mmra_with_mps(u.arbitrary()?, &canonical_commitments);
            assert_eq!(num_inputs, mmr_mps.len());
            assert_eq!(num_inputs, canonical_commitments.len());

            for ((idx, mp), &cc) in mmr_mps.iter().zip_eq(canonical_commitments.iter()) {
                assert!(
                    mp.verify(*idx, cc, &aocl.peaks(), aocl.num_leafs()),
                    "Returned MPs must be valid for returned AOCL"
                );
            }

            for (ms_mp, (_idx, mmr_mp)) in membership_proofs.iter_mut().zip(mmr_mps.iter()) {
                ms_mp.auth_path_aocl = mmr_mp.clone();
            }
            let swbfi: MmrAccumulator = u.arbitrary()?;
            let swbfa_hash: Digest = u.arbitrary()?;
            let arb_kernel: TransactionKernel = u.arbitrary()?;

            let new_inputs = input_utxos
                .iter()
                .zip(membership_proofs.iter())
                .map(|(utxo, msmp)| {
                    (
                        Tip5::hash(utxo),
                        msmp.sender_randomness,
                        msmp.receiver_preimage,
                        msmp.aocl_leaf_index,
                    )
                })
                .map(|(item, sr, rp, ali)| AbsoluteIndexSet::compute(item, sr, rp, ali))
                .map(|absolute_indices| RemovalRecord {
                    absolute_indices,
                    target_chunks: u.arbitrary().unwrap(),
                })
                .rev()
                .collect_vec();

            let kernel = TransactionKernelModifier::default()
                .mutator_set_hash(Tip5::hash_pair(
                    Tip5::hash_pair(aocl.bag_peaks(), swbfi.bag_peaks()),
                    Tip5::hash_pair(swbfa_hash, Digest::default()),
                ))
                .inputs(new_inputs)
                .modify(arb_kernel);

            let salted_utxos = SaltedUtxos::new(input_utxos);

            let aocl_auth_paths = membership_proofs
                .iter()
                .map(|x| x.auth_path_aocl.to_owned())
                .collect();

            let mast_root = kernel.mast_hash();
            let mast_path_mutator_set = kernel.mast_path(TransactionKernelField::MutatorSetHash);
            let mast_path_inputs = kernel.mast_path(TransactionKernelField::Inputs);
            let mast_path_coinbase = kernel.mast_path(TransactionKernelField::Coinbase);
            let TransactionKernelProxy {
                coinbase, inputs, ..
            } = kernel.into();

            Ok(RemovalRecordsIntegrityWitness {
                input_utxos: salted_utxos,
                membership_proofs,
                aocl_auth_paths,
                coinbase,
                aocl,
                swbfi,
                swbfa_hash,
                mast_path_mutator_set,
                mast_path_inputs,
                mast_path_coinbase,
                mast_root,
                removal_records: inputs,
            })
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use assert2::assert;
    use itertools::Itertools;
    use proptest::prop_assert_eq;
    use proptest::strategy::Strategy;
    use proptest::test_runner::TestCaseResult;
    use proptest::test_runner::TestRunner;
    use tasm_lib::hashing::merkle_verify::MerkleVerify;
    use test_strategy::proptest;

    use super::*;
    use crate::protocol::consensus::transaction::utxo::Utxo;
    use crate::protocol::consensus::transaction::TransactionKernelModifier;
    use crate::protocol::proof_abstractions::tasm::builtins as tasm;
    use crate::protocol::proof_abstractions::tasm::program::tests::test_program_snapshot;
    use crate::protocol::proof_abstractions::tasm::program::tests::ConsensusProgramSpecification;
    use crate::util_types::mutator_set::addition_record::AdditionRecord;
    use crate::util_types::mutator_set::commit;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;

    impl ConsensusProgramSpecification for RemovalRecordsIntegrity {
        fn source(&self) {
            let txk_digest: Digest = tasm::tasmlib_io_read_stdin___digest();

            let start_address: BFieldElement =
                FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
            let rriw: RemovalRecordsIntegrityWitnessMemory =
                tasm::decode_from_memory(start_address);

            // divine in the salted input UTXOs with hash
            let salted_input_utxos: &SaltedUtxos = &rriw.input_utxos;
            let input_utxos: &[Utxo] = &salted_input_utxos.utxos;

            // divine in the mutator set accumulator
            let aocl: MmrAccumulator = rriw.aocl;
            let swbfi: MmrAccumulator = rriw.swbfi;

            // authenticate the mutator set accumulator against the txk mast hash
            let aocl_mmr_bagged: Digest = aocl.bag_peaks();
            let inactive_swbf_bagged: Digest = swbfi.bag_peaks();
            let left = Tip5::hash_pair(aocl_mmr_bagged, inactive_swbf_bagged);
            let active_swbf_digest: Digest = tasm::tasmlib_io_read_secin___digest();
            let default = Digest::default();
            let right = Tip5::hash_pair(active_swbf_digest, default);
            let msah: Digest = Tip5::hash_pair(left, right);
            tasm::tasmlib_hashing_merkle_verify(
                txk_digest,
                TransactionKernelField::MutatorSetHash as u32,
                Tip5::hash(&msah),
                TransactionKernel::MAST_HEIGHT as u32,
            );

            // authenticate divined removal records against txk mast hash
            let removal_records_digest: Digest = Tip5::hash(&rriw.removal_records);
            tasm::tasmlib_hashing_merkle_verify(
                txk_digest,
                TransactionKernelField::Inputs as u32,
                removal_records_digest,
                TransactionKernel::MAST_HEIGHT as u32,
            );

            // authenticate coinbase against kernel mast hash
            let coinbase: Option<NativeCurrencyAmount> = rriw.coinbase;
            let coinbase_leaf: Digest = Tip5::hash(&coinbase);
            tasm::tasmlib_hashing_merkle_verify(
                txk_digest,
                TransactionKernelField::Coinbase as u32,
                coinbase_leaf,
                TransactionKernel::MAST_HEIGHT as u32,
            );

            // Assert that a coinbase transaction has no inputs.
            assert!(coinbase.is_none() || input_utxos.is_empty());

            // iterate over all input UTXOs
            let mut input_index: usize = 0;
            while input_index < input_utxos.len() {
                let utxo: &Utxo = &input_utxos[input_index];
                let utxo_hash = Tip5::hash(utxo);
                let claimed_absolute_indices: &AbsoluteIndexSet =
                    &rriw.removal_records[input_index].absolute_indices;

                // verify AOCL membership
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

                // calculate absolute index set
                let index_set = AbsoluteIndexSet::compute(
                    utxo_hash,
                    sender_randomness,
                    receiver_preimage,
                    aocl_leaf_index,
                );

                assert_eq!(index_set, *claimed_absolute_indices);

                input_index += 1;
            }

            // compute and output hash of salted input UTXOs
            let hash_of_inputs: Digest = Tip5::hash(salted_input_utxos);
            tasm::tasmlib_io_write_to_stdout___digest(hash_of_inputs);
        }
    }

    fn prop_positive(
        removal_records_integrity_witness: RemovalRecordsIntegrityWitness,
    ) -> TestCaseResult {
        let salted_inputs_utxos_hash = removal_records_integrity_witness.output();
        let rust_result = RemovalRecordsIntegrity
            .run_rust(
                &removal_records_integrity_witness.standard_input(),
                removal_records_integrity_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(salted_inputs_utxos_hash, rust_result.clone());

        let tasm_result = RemovalRecordsIntegrity
            .run_tasm(
                &removal_records_integrity_witness.standard_input(),
                removal_records_integrity_witness.nondeterminism(),
            )
            .unwrap();
        prop_assert_eq!(
            rust_result.clone(),
            tasm_result.clone(),
            "\ntasm output: [{}]\nbut expected: [{}]",
            tasm_result.iter().join(", "),
            rust_result.iter().join(", "),
        );

        Ok(())
    }

    #[test]
    fn small_deterministic() {
        for num_inputs in 0..=2 {
            for num_outputs in 0..=2 {
                for num_public_announcements in 0..=1 {
                    let mut test_runner = TestRunner::deterministic();
                    let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(
                        Some(num_inputs),
                        num_outputs,
                        num_public_announcements,
                    )
                    .new_tree(&mut test_runner)
                    .unwrap()
                    .current();
                    let witness = RemovalRecordsIntegrityWitness::from(&primitive_witness);
                    prop_positive(witness).unwrap();
                }
            }
        }
    }

    #[proptest(cases = 5)]
    fn removal_records_integrity_proptest_bigger(
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(7), 6, 2))]
        primitive_witness: PrimitiveWitness,
    ) {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        prop_positive(removal_records_integrity_witness)?;
    }

    #[proptest(cases = 5)]
    fn removal_records_integrity_proptest_smaller(
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2))]
        primitive_witness: PrimitiveWitness,
    ) {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        prop_positive(removal_records_integrity_witness)?;
    }

    #[proptest(cases = 5)]
    fn removal_records_integrity_proptest_empty(
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(0), 0, 2))]
        primitive_witness: PrimitiveWitness,
    ) {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        prop_positive(removal_records_integrity_witness)?;
    }

    #[test]
    fn removal_records_integrity_only_rust_shadowing() {
        let mut test_runner = TestRunner::deterministic();

        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        println!("primitive_witness: {primitive_witness}");
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        let salted_inputs_utxos_hash = removal_records_integrity_witness.output();
        let rust_result = RemovalRecordsIntegrity
            .run_rust(
                &removal_records_integrity_witness.standard_input(),
                removal_records_integrity_witness.nondeterminism(),
            )
            .unwrap();
        assert_eq!(salted_inputs_utxos_hash, rust_result.clone());
    }

    #[test]
    fn removal_records_integrity_unit_test() {
        let mut test_runner = TestRunner::deterministic();

        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        println!("primitive_witness: {primitive_witness}");
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        let property = prop_positive(removal_records_integrity_witness);
        assert!(property.is_ok(), "err: {}", property.unwrap_err());
    }

    #[test]
    fn removal_records_fail_on_bad_ms_acc() {
        let mut test_runner = TestRunner::deterministic();

        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mut bad_witness = RemovalRecordsIntegrityWitness::from(&primitive_witness);
        bad_witness.mast_path_mutator_set[1] = Digest::default();
        let assertion_failure = RemovalRecordsIntegrity.test_assertion_failure(
            bad_witness.standard_input(),
            bad_witness.nondeterminism(),
            &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
        );
        assert!(let Ok(_) = assertion_failure);
    }

    #[test]
    fn removal_records_fail_on_bad_mast_path_inputs() {
        let mut test_runner = TestRunner::deterministic();

        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mut bad_witness = RemovalRecordsIntegrityWitness::from(&primitive_witness);
        bad_witness.mast_path_inputs[1] = Digest::default();
        let assertion_failure = RemovalRecordsIntegrity.test_assertion_failure(
            bad_witness.standard_input(),
            bad_witness.nondeterminism(),
            &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
        );
        assert!(let Ok(_) = assertion_failure);
    }

    #[test]
    fn removal_records_fail_on_bad_coinbase_field() {
        let mut test_runner = TestRunner::deterministic();

        let primitive_witness = PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2)
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let mut bad_witness = RemovalRecordsIntegrityWitness::from(&primitive_witness);
        bad_witness.mast_path_coinbase[1] = Digest::default();
        let assertion_failure = RemovalRecordsIntegrity.test_assertion_failure(
            bad_witness.standard_input(),
            bad_witness.nondeterminism(),
            &[MerkleVerify::ROOT_MISMATCH_ERROR_ID],
        );
        assert!(let Ok(_) = assertion_failure);
    }

    #[test]
    fn removal_records_coinbase_tx_cannot_have_inputs() {
        let mut test_runner = TestRunner::deterministic();

        // Illegal transaction bc it has inputs *and* coinbase.
        let [bad_primitive_witness] =
            PrimitiveWitness::arbitrary_tuple_with_matching_mutator_sets_and_given_coinbase(
                [(1, 1, 1)],
                Some((NativeCurrencyAmount::coins(1), 0)),
            )
            .new_tree(&mut test_runner)
            .unwrap()
            .current();
        let bad_witness = RemovalRecordsIntegrityWitness::from(&bad_primitive_witness);
        let assertion_failure = RemovalRecordsIntegrity.test_assertion_failure(
            bad_witness.standard_input(),
            bad_witness.nondeterminism(),
            &[COINBASE_HAS_INPUTS_ERROR],
        );
        assert!(let Ok(_) = assertion_failure);
    }

    #[test]
    fn removal_record_fail_on_bad_absolute_indices_unit_test() {
        let mut test_runner = TestRunner::deterministic();

        let num_inputs = 2;
        let primitive_witness =
            PrimitiveWitness::arbitrary_with_size_numbers(Some(num_inputs), 2, 2)
                .new_tree(&mut test_runner)
                .unwrap()
                .current();

        for i in 0..num_inputs {
            let mut bad_pw = primitive_witness.clone();
            let mut bad_inputs = bad_pw.kernel.inputs.clone();
            bad_inputs[i]
                .absolute_indices
                .increment_bloom_filter_index(12);
            let bad_kernel = TransactionKernelModifier::default()
                .inputs(bad_inputs)
                .modify(bad_pw.kernel.clone());
            bad_pw.kernel = bad_kernel;
            let bad_witness = RemovalRecordsIntegrityWitness::from(&bad_pw);
            let assertion_failure = RemovalRecordsIntegrity.test_assertion_failure(
                bad_witness.standard_input(),
                bad_witness.nondeterminism(),
                &[COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR],
            );
            assert!(let Ok(_) = assertion_failure);
        }
    }

    #[proptest(cases = 4)]
    fn removal_records_fail_on_bad_absolute_indices_minimum_value(
        #[strategy(1..4usize)] _num_inputs: usize,
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(#_num_inputs), 4, 0))]
        mut bad_pw: PrimitiveWitness,
        #[strategy(0..#_num_inputs)] mutated_input: usize,
    ) {
        let mut bad_inputs = bad_pw.kernel.inputs.clone();

        // Ensure all possible words of (encoding of) minimum is mutated to
        // ensure entire data structure is hashed and compared. Missing just one
        // word in the hashing would make this snippet (and the entire
        // blockchain) unsound.
        let original_minimum = bad_inputs[mutated_input].absolute_indices.minimum();
        for term in [1, 1 << 32, 1 << 64, 1 << 96] {
            bad_inputs[mutated_input]
                .absolute_indices
                .set_minimum(original_minimum + term);
            let bad_kernel = TransactionKernelModifier::default()
                .inputs(bad_inputs.clone())
                .modify(bad_pw.kernel.clone());
            bad_pw.kernel = bad_kernel;
            let bad_witness = RemovalRecordsIntegrityWitness::from(&bad_pw);
            RemovalRecordsIntegrity.test_assertion_failure(
                bad_witness.standard_input(),
                bad_witness.nondeterminism(),
                &[COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR],
            )?;
        }
    }

    #[proptest(cases = 1)]
    fn removal_records_fail_on_bad_absolute_indices(
        #[strategy(PrimitiveWitness::arbitrary_with_size_numbers(Some(2), 2, 2))]
        good_witness: PrimitiveWitness,
        #[strategy(0usize..2)] mutated_input: usize,
    ) {
        // Loop over every single index (in absolute indices) to ensure that
        // they are all hashed in the check and we aren't accidently skipping
        // one of the indices. If we were, that would make the entire blockchain
        // unsound.
        for mutated_bloom_filter_index in 0..NUM_TRIALS as usize {
            let mut bad_pw = good_witness.clone();
            let mut bad_inputs = bad_pw.kernel.inputs.clone();
            bad_inputs[mutated_input]
                .absolute_indices
                .increment_bloom_filter_index(mutated_bloom_filter_index);
            let bad_kernel = TransactionKernelModifier::default()
                .inputs(bad_inputs)
                .modify(bad_pw.kernel.clone());
            bad_pw.kernel = bad_kernel;
            let bad_witness = RemovalRecordsIntegrityWitness::from(&bad_pw);
            RemovalRecordsIntegrity.test_assertion_failure(
                bad_witness.standard_input(),
                bad_witness.nondeterminism(),
                &[COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR],
            )?;
        }
    }

    test_program_snapshot!(
        RemovalRecordsIntegrity,
        "89a70f4bdf92fabbd605897dba7a22e21e9e7137325ee46aea354cacc3161d30ab1a8dac3de36931"
    );
}
