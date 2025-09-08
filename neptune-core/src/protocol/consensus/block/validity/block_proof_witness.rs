use get_size2::GetSize;
use itertools::Itertools;
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
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::protocol::consensus::block::block_body::BlockBodyField;
use crate::protocol::consensus::block::BlockAppendix;
use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
use crate::protocol::consensus::transaction::transaction_kernel::TransactionKernelField;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;
use crate::protocol::consensus::transaction::validity::single_proof::single_proof_claim;
use crate::protocol::consensus::transaction::TransactionProof;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::protocol::proof_abstractions::tasm::program::ConsensusProgram;
use crate::protocol::proof_abstractions::SecretWitness;

/// All information necessary to efficiently produce a proof for a block.
///
/// This is the witness for the [`BlockProgram`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub(crate) struct BlockProofWitness {
    pub(super) block_body: BlockBody,
    pub(crate) claims: Vec<Claim>,
    pub(crate) proofs: Vec<Proof>,
}

impl BlockProofWitness {
    fn new(block_body: BlockBody) -> Self {
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

    #[cfg(test)]
    pub(crate) fn with_claim_test(self, claim: Claim, proof: Proof) -> Self {
        self.with_claim(claim, proof)
    }

    pub(crate) fn claims(&self) -> Vec<Claim> {
        self.claims.clone()
    }

    pub(crate) fn appendix(&self) -> BlockAppendix {
        BlockAppendix::new(self.claims())
    }

    pub(crate) fn produce(block_primitive_witness: BlockPrimitiveWitness) -> BlockProofWitness {
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
        let witness =
            Self::new(block_primitive_witness.body().clone()).with_claim(tx_claim, tx_proof);

        assert_eq!(
            BlockAppendix::consensus_claims(block_primitive_witness.body(), consensus_rule_set),
            witness.claims,
            "appendix witness must attest to expected claims",
        );

        witness
    }
}

impl SecretWitness for BlockProofWitness {
    fn standard_input(&self) -> PublicInput {
        self.block_body.mast_hash().reversed().values().into()
    }

    fn output(&self) -> Vec<BFieldElement> {
        self.claims().encode()
    }

    fn program(&self) -> Program {
        BlockProgram.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
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
        let stark_snippet = StarkVerify::new_with_dynamic_layout(Stark::default());
        for (claim, proof) in self.claims.iter().zip_eq(&self.proofs) {
            stark_snippet.update_nondeterminism(&mut nondeterminism, proof, claim);
        }

        nondeterminism
    }
}
