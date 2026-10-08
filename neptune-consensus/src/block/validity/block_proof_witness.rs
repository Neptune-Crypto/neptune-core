use get_size2::GetSize;
use itertools::Itertools;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::triton_vm::vm::NonDeterminism;
use tasm_lib::triton_vm::vm::PublicInput;
use tasm_lib::verifier::stark_verify::StarkVerify;

use super::block_primitive_witness::BlockPrimitiveWitness;
use super::block_program::BlockProgram;
use crate::block::block_body::BlockBody;
use crate::block::block_body::BlockBodyField;
use crate::block::BlockAppendix;
use crate::block::ConsensusParameters;
use crate::consensus_rule_set::ConsensusRuleSet;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::transaction::transaction_kernel::TransactionKernelField;
use crate::transaction::validity::neptune_proof::Proof;
use crate::transaction::validity::single_proof::single_proof_claim;
use crate::transaction::TransactionProof;

/// All information necessary to efficiently produce a proof for a block.
///
/// This is the witness for the [`BlockProgram`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct BlockProofWitness {
    pub(super) block_body: BlockBody,
    pub(crate) claims: Vec<Claim>,
    pub(crate) proofs: Vec<Proof>,
}

impl BlockProofWitness {
    pub fn new(block_body: BlockBody) -> Self {
        Self {
            block_body,
            claims: Vec::default(),
            proofs: Vec::default(),
        }
    }

    /// Add a claim to the appendix, along with a proof.
    fn with_claim(mut self, claim: Claim, proof: Proof) -> Self {
        self.claims.push(claim);
        self.proofs.push(proof);

        self
    }

    #[cfg(any(test, feature = "test-helpers"))]
    pub fn with_claim_test(self, claim: Claim, proof: Proof) -> Self {
        self.with_claim(claim, proof)
    }

    pub(crate) fn claims(&self) -> Vec<Claim> {
        self.claims.clone()
    }

    pub fn appendix(&self) -> BlockAppendix {
        BlockAppendix::new(self.claims())
    }

    pub fn produce(block_primitive_witness: BlockPrimitiveWitness) -> BlockProofWitness {
        let txk_mast_hash = block_primitive_witness
            .body()
            .transaction_kernel
            .mast_hash();

        let block_height = block_primitive_witness
            .predecessor_block
            .header()
            .height
            .next();
        let consensus_rule_set =
            ConsensusRuleSet::infer_from(block_primitive_witness.network, block_height);
        let tx_claim = single_proof_claim(txk_mast_hash, consensus_rule_set);
        let tx_proof = match &block_primitive_witness.transaction().proof {
            TransactionProof::SingleProof(proof) => proof.clone(),
            _ => {
                panic!(
                    "can only produce appendix witness from single-proof transaction; got {:?}",
                    block_primitive_witness.transaction().proof
                );
            }
        };

        // Add more claim/proof pairs here, when softforking.
        let mut witness =
            Self::new(block_primitive_witness.body().clone()).with_claim(tx_claim, tx_proof);

        // The predecessor claim and the SWBF update claim, with mock proofs
        // where the network mocks proofs. Proving them is the composer's,
        // not yet written.
        let network = block_primitive_witness.network;
        let predecessor = &block_primitive_witness.predecessor_block;
        if consensus_rule_set.requires_predecessor_claim() && network.use_mock_proof() {
            let body = block_primitive_witness.body();
            let claims = BlockAppendix::mock_consensus_claims(body, predecessor, network);
            for claim in claims.into_iter().skip(1) {
                witness = witness.with_claim(claim, Proof::valid_mock());
            }
        }

        if !consensus_rule_set.requires_predecessor_claim() || network.use_mock_proof() {
            let mutator_set = predecessor
                .mutator_set_accumulator_after()
                .expect("predecessor must have a fee");
            let required = BlockAppendix::consensus_claims(
                block_primitive_witness.body(),
                block_height,
                &mutator_set,
                &ConsensusParameters::for_network(network),
            );
            let appendix = witness.appendix();
            assert!(
                required.iter().all(|claim| appendix.find(claim).is_some()),
                "appendix witness must attest to the required claims",
            );
        }

        witness
    }
}

impl BlockProofWitness {
    pub fn standard_input(&self) -> PublicInput {
        self.block_body.mast_hash().reversed().values().into()
    }

    pub fn output(&self) -> Vec<BFieldElement> {
        self.claims().encode()
    }

    pub fn program(&self) -> Program {
        BlockProgram.program()
    }

    pub fn nondeterminism(&self) -> NonDeterminism {
        // put witness into memory
        let mut nondeterminism = NonDeterminism::new([]);
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self,
        );

        // feed the txk mast hash via individual tokens
        let txkmh = self.block_body.transaction_kernel.mast_hash();
        nondeterminism
            .individual_tokens
            .extend_from_slice(&txkmh.reversed().values());

        // add digests for Merkle authentication of tx fee
        let txk_auth_path = self.block_body.mast_path(BlockBodyField::TransactionKernel);
        nondeterminism.digests.extend_from_slice(&txk_auth_path);

        let fee_auth_path = self
            .block_body
            .transaction_kernel
            .mast_path(TransactionKernelField::Fee);
        nondeterminism.digests.extend_from_slice(&fee_auth_path);

        let merge_bit_auth_path = self
            .block_body
            .transaction_kernel
            .mast_path(TransactionKernelField::MergeBit);
        nondeterminism
            .digests
            .extend_from_slice(&merge_bit_auth_path);

        // modify nodeterminism in whichever way is necessary for verifying STARK proofs
        for (claim, proof) in self.claims.iter().zip_eq(&self.proofs) {
            StarkVerify::new_with_dynamic_layout(Stark::default()).update_nondeterminism(
                &mut nondeterminism,
                proof,
                claim,
            );
        }

        nondeterminism
    }
}
