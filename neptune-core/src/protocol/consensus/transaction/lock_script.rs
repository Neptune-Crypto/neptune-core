use std::collections::HashMap;
use std::sync::Arc;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use get_size2::GetSize;
use itertools::Itertools;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;
use tasm_lib::twenty_first::tip5::digest::Digest;

use super::utxo::Utxo;
use crate::api::tx_initiation::builder::proof_builder::ProofBuilder;
use crate::api::tx_initiation::error::CreateProofError;
use crate::application::triton_vm_job_queue::TritonVmJobQueue;
use crate::protocol::consensus::transaction::Proof;
use crate::protocol::proof_abstractions::tasm::program::TritonVmProofJobOptions;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct LockScript {
    pub program: Program,
}

impl From<Vec<LabelledInstruction>> for LockScript {
    fn from(instrs: Vec<LabelledInstruction>) -> Self {
        Self {
            program: Program::new(&instrs),
        }
    }
}

impl From<&[LabelledInstruction]> for LockScript {
    fn from(instrs: &[LabelledInstruction]) -> Self {
        Self {
            program: Program::new(instrs),
        }
    }
}

impl LockScript {
    const BURN_ERROR: i128 = 1_000_300;

    pub fn new(program: Program) -> Self {
        Self { program }
    }

    pub fn anyone_can_spend() -> Self {
        Self {
            program: Program::new(&triton_asm!(
                read_io 5
                halt
            )),
        }
    }

    pub fn hash(&self) -> Digest {
        self.program.hash()
    }

    /// Generate a lock script that verifies knowledge of a hash preimage, given
    /// the after-image. This type of lock script is called "standard hash
    /// lock".
    ///
    /// Satisfaction of this lock script establishes the UTXO owner's assent to
    /// the transaction.
    pub fn standard_hash_lock_from_after_image(after_image: Digest) -> LockScript {
        let push_spending_lock_digest_to_stack = after_image
            .values()
            .iter()
            .rev()
            .map(|elem| triton_instr!(push elem.value()))
            .collect_vec();

        let instructions = triton_asm!(
            divine 5
            hash
            {&push_spending_lock_digest_to_stack}
            assert_vector
            read_io 5
            halt
        );

        instructions.into()
    }

    /// A lock script that is guaranteed to fail
    pub(crate) fn burn() -> Self {
        Self {
            program: triton_program! {
                push 0 assert error_id {Self::BURN_ERROR}
            },
        }
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> Arbitrary<'a> for LockScript {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let program = Program::arbitrary(u)?;
        Ok(LockScript { program })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct LockScriptAndWitness {
    pub program: Program,
    nd_memory: Vec<(BFieldElement, BFieldElement)>,
    nd_tokens: Vec<BFieldElement>,
    nd_digests: Vec<Digest>,
}

impl LockScriptAndWitness {
    pub fn new_with_nondeterminism(program: Program, witness: NonDeterminism) -> Self {
        Self {
            program,
            nd_memory: witness.ram.into_iter().collect(),
            nd_tokens: witness.individual_tokens,
            nd_digests: witness.digests,
        }
    }

    /// Create a [`LockScriptAndWitness`] whose lock script is a standard hash
    /// lock, from the preimage.
    pub(crate) fn standard_hash_lock_from_preimage(preimage: Digest) -> LockScriptAndWitness {
        let after_image = preimage.hash();
        let lock_script = LockScript::standard_hash_lock_from_after_image(after_image);
        LockScriptAndWitness::new_with_nondeterminism(
            lock_script.program,
            NonDeterminism::new(preimage.reversed().values()),
        )
    }

    #[cfg(test)]
    pub(crate) fn set_nd_tokens(&mut self, tokens: Vec<BFieldElement>) {
        self.nd_tokens = tokens;
    }

    pub fn new(program: Program) -> Self {
        Self {
            program,
            nd_memory: vec![],
            nd_tokens: vec![],
            nd_digests: vec![],
        }
    }

    pub fn new_with_tokens(program: Program, tokens: Vec<BFieldElement>) -> Self {
        Self {
            program,
            nd_memory: vec![],
            nd_tokens: tokens,
            nd_digests: vec![],
        }
    }

    pub fn nondeterminism(&self) -> NonDeterminism {
        NonDeterminism::new(self.nd_tokens.clone())
            .with_digests(self.nd_digests.clone())
            .with_ram(self.nd_memory.iter().copied().collect::<HashMap<_, _>>())
    }

    /// Determine if the given UTXO can be unlocked with this
    /// lock-script-and-witness pair.
    pub fn can_unlock(&self, utxo: &Utxo) -> bool {
        if self.program.hash() != utxo.lock_script_hash() {
            return false;
        }
        let any_digest = rand::rng().random::<Digest>();
        self.halts_gracefully(any_digest.values().into())
    }

    pub fn halts_gracefully(&self, public_input: PublicInput) -> bool {
        VM::run(self.program.clone(), public_input, self.nondeterminism()).is_ok()
    }

    /// Assuming the lock script halts gracefully, prove it.
    pub(crate) async fn prove(
        &self,
        public_input: PublicInput,
        triton_vm_job_queue: Arc<TritonVmJobQueue>,
        proof_job_options: TritonVmProofJobOptions,
    ) -> Result<Proof, CreateProofError> {
        let claim = Claim::new(self.program.hash()).with_input(public_input.individual_tokens);
        ProofBuilder::new()
            .program(self.program.clone())
            .claim(claim)
            .nondeterminism(|| self.nondeterminism())
            .job_queue(triton_vm_job_queue)
            .proof_job_options(proof_job_options)
            .build()
            .await
    }
}

#[cfg(any(test, feature = "arbitrary-impls"))]
impl<'a> Arbitrary<'a> for LockScriptAndWitness {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let program = Program::arbitrary(u)?;
        let tokens = Digest::arbitrary(u)?.reversed().values().to_vec();
        Ok(LockScriptAndWitness::new_with_tokens(program, tokens))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use num_traits::Zero;
    use proptest::prop_assert;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;
    use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;

    #[proptest]
    fn lock_script_halts_gracefully_prop(
        #[strategy(arb::<Digest>())] txk_mast_hash: Digest,
        #[strategy(arb::<Digest>())] seed: Digest,
        #[strategy(NativeCurrencyAmount::arbitrary_non_negative())] amount: NativeCurrencyAmount,
    ) {
        let (_utxos, lock_scripts_and_witnesses) =
            PrimitiveWitness::transaction_inputs_from_address_seeds_and_amounts(&[seed], &[amount]);
        prop_assert!(lock_scripts_and_witnesses.into_iter().all(|lsaw| lsaw
            .halts_gracefully(PublicInput::new(txk_mast_hash.reversed().values().to_vec()))));
    }

    #[test]
    fn lock_script_halts_gracefully_unit() {
        let txk_mast_hash = Digest::default();
        let seed = Digest::default();
        let amount = NativeCurrencyAmount::zero();

        let (_utxos, lock_scripts_and_witnesses) =
            PrimitiveWitness::transaction_inputs_from_address_seeds_and_amounts(&[seed], &[amount]);
        assert!(lock_scripts_and_witnesses.into_iter().all(|lsaw| lsaw
            .halts_gracefully(PublicInput::new(txk_mast_hash.reversed().values().to_vec()))));
    }
}
