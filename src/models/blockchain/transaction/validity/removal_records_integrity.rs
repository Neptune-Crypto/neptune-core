use std::collections::HashSet;

use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use triton_opcodes::program::Program;
use triton_vm::{BFieldElement, Digest};
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use twenty_first::{shared_math::bfield_codec::BFieldCodec, util_types::mmr::mmr_trait::Mmr};

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::validity::ClaimSupport;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::{
    models::blockchain::shared::Hash,
    util_types::mutator_set::{
        mutator_set_kernel::get_swbf_indices, mutator_set_trait::commit,
        removal_record::AbsoluteIndexSet,
    },
};

use super::{SupportedClaim, TxValidationLogic};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct RemovalRecordsIntegrity {
    supported_claim: SupportedClaim,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct RemovalRecordsIntegrityWitness {
    pub input_utxos: Vec<Utxo>,
    pub membership_proofs: Vec<MsMembershipProof<Hash>>,
    pub aocl: MmrAccumulator<Hash>,
    pub swbfi: MmrAccumulator<Hash>,
    pub swbfa_hash: Digest,
    pub kernel: TransactionKernel,
}

#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec)]
struct RemovalRecordsIntegrityPublicInput {
    // hash of inputs + mutator set hash
    pub hash_of_kernel: Digest,
}

impl RemovalRecordsIntegrity {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claim: SupportedClaim::dummy_supported_claim(),
        }
    }

    fn verify_raw(public_input: &[BFieldElement], secret_input: &[BFieldElement]) {
        let hash_of_kernel = *Digest::decode(public_input)
            .expect("Could not decode public input in Removal Records Integrity :: verify_raw");

        // read and process witness data
        let witness = *RemovalRecordsIntegrityWitness::decode(secret_input).unwrap();

        // assert that the kernel from the witness matches the hash in the public input
        // now we can trust all data in kernel
        assert_eq!(hash_of_kernel, witness.kernel.mast_hash());

        // assert that the mutator set's MMRs in the witness match the kernel
        // now we can trust all data in these MMRs as well
        let mutator_set_hash = Hash::hash_pair(
            &Hash::hash_pair(&witness.aocl.bag_peaks(), &witness.swbfi.bag_peaks()),
            &Hash::hash_pair(&witness.swbfa_hash, &Digest::default()),
        );
        assert_eq!(witness.kernel.mutator_set_hash, mutator_set_hash);

        // How do we trust input UTXOs?
        // Because they generate removal records, and we can match
        // those against the removal records that are listed in the
        // kernel.
        let items = witness.input_utxos.iter().map(Hash::hash).collect_vec();

        // test that removal records listed in kernel match those derived from input utxos
        let digests_of_derived_index_sets = items
            .iter()
            .zip(witness.membership_proofs.iter())
            .map(|(utxo, msmp)| {
                AbsoluteIndexSet::new(&get_swbf_indices::<Hash>(
                    &Hash::hash(utxo),
                    &msmp.sender_randomness,
                    &msmp.receiver_preimage,
                    msmp.auth_path_aocl.leaf_index,
                ))
                .encode()
            })
            .map(|x| Hash::hash_varlen(&x))
            .collect::<HashSet<_>>();
        let digests_of_claimed_index_sets = witness
            .kernel
            .inputs
            .iter()
            .map(|input| input.absolute_indices.encode())
            .map(|e| Hash::hash_varlen(&e))
            .collect::<HashSet<_>>();
        assert_eq!(digests_of_derived_index_sets, digests_of_claimed_index_sets);

        // verify that all input utxos (mutator set items) live in the AOCL
        assert!(items
            .iter()
            .zip(witness.membership_proofs.iter())
            .map(|(item, msmp)| {
                (
                    commit::<Hash>(
                        item,
                        &msmp.sender_randomness,
                        &msmp.receiver_preimage.hash::<Hash>(),
                    ),
                    &msmp.auth_path_aocl,
                )
            })
            .all(|(cc, mp)| {
                mp.verify(
                    &witness.aocl.get_peaks(),
                    &cc.canonical_commitment,
                    witness.aocl.count_leaves(),
                )
                .0
            }));
    }
}

impl TxValidationLogic for RemovalRecordsIntegrity {
    fn unproven_from_primitive_witness(
        primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        let removal_records_integrity_witness = RemovalRecordsIntegrityWitness {
            input_utxos: primitive_witness.input_utxos.clone(),
            membership_proofs: primitive_witness.input_membership_proofs.clone(),
            kernel: tx_kernel.to_owned(),
            aocl: primitive_witness
                .mutator_set_accumulator
                .kernel
                .aocl
                .clone(),
            swbfi: primitive_witness
                .mutator_set_accumulator
                .kernel
                .swbf_inactive
                .clone(),
            swbfa_hash: Hash::hash(&primitive_witness.mutator_set_accumulator.kernel.swbf_active),
        };
        let witness_data = removal_records_integrity_witness.encode();
        let program = Program::default();

        Self {
            supported_claim: SupportedClaim {
                claim: triton_vm::Claim {
                    program_digest: Hash::hash_varlen(&program.encode()),
                    input: tx_kernel.mast_hash().encode(),
                    output: vec![],
                },
                support: ClaimSupport::SecretWitness(witness_data, program),
            },
        }
    }

    fn prove(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    fn verify(
        &self,
        _tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> bool {
        todo!()
    }
}
