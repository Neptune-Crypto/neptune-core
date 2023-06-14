use anyhow::bail;
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use triton_opcodes::program::Program;
use triton_vm::BFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::{shared_math::bfield_codec::BFieldCodec, util_types::mmr::mmr_trait::Mmr};

use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::validity::ClaimSupport;
use crate::util_types::mutator_set::ms_membership_proof::MsMembershipProof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_trait::MutatorSet;
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
    pub mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    pub kernel: TransactionKernel,
}

impl RemovalRecordsIntegrity {
    // TODO: Remove after implementing this struct
    pub fn dummy() -> Self {
        Self {
            supported_claim: SupportedClaim::dummy_supported_claim(),
        }
    }

    fn verify_raw(public_input: &[BFieldElement], secret_witness: &[BFieldElement]) {
        let removal_records_integrity_witness =
            *RemovalRecordsIntegrityWitness::decode(secret_witness).unwrap();
        let items = removal_records_integrity_witness
            .input_utxos
            .iter()
            .map(Hash::hash)
            .collect_vec();
        let mut digests_of_derived_index_sets = items
            .iter()
            .zip(removal_records_integrity_witness.membership_proofs.iter())
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
            .collect_vec();
        digests_of_derived_index_sets.sort();
        let mut digests_of_claimed_index_sets = removal_records_integrity_witness
            .kernel
            .inputs
            .iter()
            .map(|input| input.absolute_indices.encode())
            .map(|e| Hash::hash_varlen(&e))
            .collect_vec();
        digests_of_claimed_index_sets.sort();
        assert_eq!(digests_of_derived_index_sets, digests_of_claimed_index_sets);
        assert!(items
            .iter()
            .zip(removal_records_integrity_witness.membership_proofs.iter())
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
                    &removal_records_integrity_witness
                        .mutator_set_accumulator
                        .kernel
                        .aocl
                        .get_peaks(),
                    &cc.canonical_commitment,
                    removal_records_integrity_witness
                        .mutator_set_accumulator
                        .kernel
                        .aocl
                        .count_leaves(),
                )
                .0
            }));
        assert_eq!(
            removal_records_integrity_witness
                .mutator_set_accumulator
                .hash(),
            removal_records_integrity_witness.kernel.mutator_set_hash
        );
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
            mutator_set_accumulator: primitive_witness.mutator_set_accumulator.clone(),
            kernel: tx_kernel.to_owned(),
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
