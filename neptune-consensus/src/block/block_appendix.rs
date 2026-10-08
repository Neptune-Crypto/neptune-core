use std::ops::Deref;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::block_height::BlockHeight;
use neptune_primitives::mast_hash::MastHash;
use neptune_primitives::network::Network;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::bfe;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::block_body::BlockBody;
use crate::block::validity::knows_mutator_set::KnowsMutatorSet;
use crate::block::validity::predecessor_is_valid::PredecessorIsValid;
use crate::block::validity::swbf_update::aggregation::SwbfUpdateAggregation;
use crate::block::validity::swbf_update::leaf::CorrectSwbfUpdate;
use crate::block::Block;
use crate::block::Claim;
use crate::block::ConsensusParameters;
use crate::block::Tip5;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::validity::single_proof::single_proof_claim;

pub const MAX_NUM_CLAIMS: usize = 500;

/// Encapsulates the claims proven by the block proof.
///
/// Every appendix claim has an identical input: the block body's hash; and an
/// identical output: the empty string.
///
/// The appendix is the keystone of soft-fork-friendly upgrades to the protocol.
/// The block proof establishes that all claims in the appendix are valid.
/// The appendix can softly be extended with new claims.
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, TasmObject, GetSize, Default,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct BlockAppendix {
    claims: Vec<Claim>,
}

impl BlockAppendix {
    pub fn new(claims: Vec<Claim>) -> Self {
        Self { claims }
    }

    pub(crate) fn claims_as_output(&self) -> Vec<BFieldElement> {
        self.claims
            .iter()
            .map(Tip5::hash)
            .flat_map(|d| d.values().to_vec())
            .collect()
    }

    /// The claims a block's appendix must hold that bind nothing of the
    /// parent, by program, version and input; the outputs are the proofs'
    /// business. The transaction's, and from hard fork epsilon on the
    /// predecessor claim under the network's table and genesis.
    pub fn consensus_claims_without_parent(
        block_body: &BlockBody,
        height: BlockHeight,
        parameters: &ConsensusParameters,
    ) -> Vec<Claim> {
        let consensus_rule_set = ConsensusRuleSet::infer_from(parameters.network, height);
        let tx_is_valid = Self::transaction_validity_claim(
            block_body.transaction_kernel.mast_hash(),
            consensus_rule_set,
        );
        let mut claims = vec![tx_is_valid];
        if consensus_rule_set.requires_predecessor_claim() {
            let input = PredecessorIsValid::claim_input(
                block_body.mast_hash(),
                height,
                Block::genesis_digest(parameters.network),
                &parameters.epochs,
            );
            claims.push(
                Claim::new(parameters.predecessor_program.hash())
                    .with_input(input)
                    .about_version(consensus_rule_set.triton_proof_version().version()),
            );
        }
        claims
    }

    /// Every claim a block's appendix must hold, by program, version and
    /// input, given its parent's hash and the mutator set after it: those
    /// above, and from hard fork epsilon on the composer's claim to know
    /// that mutator set, where the epoch requires reveals, and the SWBF
    /// update claim about the transaction on it.
    pub fn consensus_claims(
        block_body: &BlockBody,
        height: BlockHeight,
        parent_digest: Digest,
        parent_mutator_set: &MutatorSetAccumulator,
        parameters: &ConsensusParameters,
    ) -> Vec<Claim> {
        let consensus_rule_set = ConsensusRuleSet::infer_from(parameters.network, height);
        let mut claims = Self::consensus_claims_without_parent(block_body, height, parameters);
        if consensus_rule_set.requires_predecessor_claim() {
            let epoch = parameters.epochs.in_force_at(height);
            if !epoch.requires_mutator_set_reveals.is_zero() {
                claims.push(KnowsMutatorSet::claim(
                    parent_digest,
                    parent_mutator_set,
                    consensus_rule_set,
                ));
            }
            let input = CorrectSwbfUpdate::claim_input(
                parent_mutator_set,
                bfe!(CorrectSwbfUpdate::FIRST_LEAF_INDEX),
            );
            claims.push(
                Claim::new(SwbfUpdateAggregation::new().hash())
                    .with_input(input)
                    .about_version(consensus_rule_set.triton_proof_version().version()),
            );
        }
        claims
    }

    /// The required claims a block on this parent carries where the network
    /// mocks proofs: the transaction's, and from hard fork epsilon on the
    /// predecessor claim and the SWBF update claim with their outputs
    /// computed, nothing proven.
    pub fn mock_consensus_claims(
        block_body: &BlockBody,
        parent: &Block,
        network: Network,
    ) -> Vec<Claim> {
        let height = parent.header().height.next();
        let consensus_rule_set = ConsensusRuleSet::infer_from(network, height);
        let mut claims = vec![Self::transaction_validity_claim(
            block_body.transaction_kernel.mast_hash(),
            consensus_rule_set,
        )];
        if consensus_rule_set.requires_predecessor_claim() {
            let mutator_set = parent
                .mutator_set_accumulator_after()
                .expect("parent must have a fee");
            claims.push(PredecessorIsValid::claim_about(
                parent,
                block_body.mast_hash(),
                network,
            ));
            claims.push(SwbfUpdateAggregation::root_claim_without_proofs(
                &block_body.transaction_kernel.inputs,
                &mutator_set,
                0,
            ));
        }
        claims
    }

    /// The claim with this one's program, version and input, if the
    /// appendix holds one.
    pub fn find(&self, shape: &Claim) -> Option<&Claim> {
        self.claims.iter().find(|claim| {
            claim.program_digest == shape.program_digest
                && claim.version == shape.version
                && claim.input == shape.input
        })
    }

    pub(crate) fn transaction_validity_claim(
        transaction_kernel_mast_hash: Digest,
        consensus_rule_set: ConsensusRuleSet,
    ) -> Claim {
        single_proof_claim(transaction_kernel_mast_hash, consensus_rule_set)
    }

    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }
}

impl Deref for BlockAppendix {
    type Target = Vec<Claim>;

    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}

impl rand::distr::Distribution<BlockAppendix> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> BlockAppendix {
        use rand::RngExt;
        BlockAppendix {
            claims: (0..10)
                .map(|_| {
                    Claim::new(rng.random())
                        .with_input((0..10).map(|_| rng.random()).collect_vec())
                        .with_output((0..10).map(|_| rng.random()).collect_vec())
                })
                .collect_vec(),
        }
    }
}
