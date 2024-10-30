use std::collections::HashMap;

use arbitrary::Arbitrary;
use get_size::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::tip5::Digest;

use crate::job_queue::triton_vm::TritonVmJobPriority;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::proof_abstractions::tasm::program::prove_consensus_program;
use crate::prelude::twenty_first;

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
}

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

impl From<LockScriptAndWitness> for LockScript {
    fn from(lock_script_and_witness: LockScriptAndWitness) -> Self {
        Self {
            program: lock_script_and_witness.program,
        }
    }
}

impl From<&LockScriptAndWitness> for LockScript {
    fn from(lock_script_and_witness: &LockScriptAndWitness) -> Self {
        Self {
            program: lock_script_and_witness.program.clone(),
        }
    }
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
            .with_ram(self.nd_memory.iter().cloned().collect::<HashMap<_, _>>())
    }

    pub fn halts_gracefully(&self, public_input: PublicInput) -> bool {
        VM::run(
            &self.program,
            public_input,
            NonDeterminism::new(self.nd_tokens.clone())
                .with_digests(self.nd_digests.clone())
                .with_ram(self.nd_memory.iter().cloned().collect::<HashMap<_, _>>()),
        )
        .is_ok()
    }

    /// Assuming the lock script halts gracefully, prove it.
    pub(crate) async fn prove(
        &self,
        public_input: PublicInput,
        triton_vm_job_queue: &TritonVmJobQueue,
        priority: TritonVmJobPriority,
    ) -> anyhow::Result<Proof> {
        let claim = Claim::new(self.program.hash()).with_input(public_input.individual_tokens);
        prove_consensus_program(
            self.program.clone(),
            claim,
            self.nondeterminism(),
            triton_vm_job_queue,
            priority,
        )
        .await
    }
}

impl<'a> Arbitrary<'a> for LockScriptAndWitness {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let program = Program::arbitrary(u)?;
        let tokens = Digest::arbitrary(u)?.reversed().values().to_vec();
        Ok(LockScriptAndWitness::new_with_tokens(program, tokens))
    }
}

#[cfg(test)]
mod test {
    use num_traits::Zero;
    use proptest::prop_assert;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
    use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;

    #[proptest]
    fn lock_script_halts_gracefully_prop(
        #[strategy(arb::<Digest>())] txk_mast_hash: Digest,
        #[strategy(arb::<Digest>())] seed: Digest,
        #[strategy(arb::<NeptuneCoins>())] amount: NeptuneCoins,
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
        let amount = NeptuneCoins::zero();

        let (_utxos, lock_scripts_and_witnesses) =
            PrimitiveWitness::transaction_inputs_from_address_seeds_and_amounts(&[seed], &[amount]);
        assert!(lock_scripts_and_witnesses.into_iter().all(|lsaw| lsaw
            .halts_gracefully(PublicInput::new(txk_mast_hash.reversed().values().to_vec()))));
    }
}
