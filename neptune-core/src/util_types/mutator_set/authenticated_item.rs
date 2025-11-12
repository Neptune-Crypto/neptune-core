use itertools::Itertools;
use tasm_lib::prelude::Digest;

use super::addition_record::AdditionRecord;
use super::ms_membership_proof::MsMembershipProof;
use super::mutator_set_accumulator::MutatorSetAccumulator;
use super::removal_record::RemovalRecord;

#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedItem {
    pub(crate) item: Digest,
    pub(crate) ms_membership_proof: MsMembershipProof,
}

impl AuthenticatedItem {
    /// Update the membership proofs of a list of authenticated items in
    /// anticipation of an addition.
    ///
    /// Does not verify that the membership proofs are valid.
    pub(crate) fn batch_update_from_addition(
        authenticated_items: &mut [&mut Self],
        mutator_set: &MutatorSetAccumulator,
        addition_record: AdditionRecord,
    ) {
        let items = authenticated_items.iter().map(|x| x.item).collect_vec();
        let mut ms_membership_proofs = authenticated_items
            .iter_mut()
            .map(|authenticated_item| &mut authenticated_item.ms_membership_proof)
            .collect_vec();
        let _ = MsMembershipProof::batch_update_from_addition(
            &mut ms_membership_proofs,
            &items,
            mutator_set,
            &addition_record,
        );
    }

    /// Update the membership proofs of a list of authenticated items in
    /// anticipation of one remove operation.
    pub(crate) fn batch_update_from_remove(
        authenticated_items: &mut [&mut Self],
        removal_record: &RemovalRecord,
    ) {
        let mut ms_membership_proofs = authenticated_items
            .iter_mut()
            .map(|authenticated_item| &mut authenticated_item.ms_membership_proof)
            .collect_vec();
        let _ =
            MsMembershipProof::batch_update_from_remove(&mut ms_membership_proofs, removal_record);
    }
}
