use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::triton_vm::prelude::NonDeterminism;
use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::prelude::PublicInput;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::forge::ForgeWitness;
use super::forge::ForgeWitnessMemory;
use super::link_proof::LinkProof;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

/// Discriminant of [`LinkProofWitness::Forge`].
///
/// Consensus-critical: the `LinkProof` program branches on this value, so it is
/// pinned here and must never be reassigned. The remaining branches append:
///  - `Chain` = 1
///  - `Update` = 2,
///  - `Cast` = 3.
pub(crate) const DISCRIMINANT_FOR_FORGE: u64 = 0;

/// The witness for a link proof: which of the `LinkProof` branches produced this
/// [`LinkTx`](super::link_tx::LinkTx), plus that branch's secret
/// (non-deterministic) input.
///
/// Transaction-chaining analog of
/// [`SingleProofWitness`](crate::transaction::validity::single_proof::SingleProofWitness).
///
/// Note that `Fix` is deliberately *not* a variant here: `Fix` produces a
/// `SingleProof`, not a `LinkProof`, and therefore lives on `SingleProofWitness`.
///
/// The remaining branches -- `Chain`, `Update` and `Cast` -- are added together
/// with their witnesses and tasm programs, appended in that order (see
/// [`DISCRIMINANT_FOR_FORGE`]) so the wire layout of `Forge` never shifts
/// underneath them.
#[derive(Debug, Clone, BFieldCodec)]
pub enum LinkProofWitness {
    /// `LinkPrimitiveWitness -> LinkTx`: the entry point into the chain pipeline.
    Forge(Box<ForgeWitness>),
}

/// The memory image of a [`LinkProofWitness`]: what the `LinkProof` program
/// finds at address 0, and the *only* thing it decodes.
///
/// Each variant holds its branch's memory projection. This mirrors
/// [`LinkProofWitness`] the way [`ForgeWitnessMemory`] mirrors [`ForgeWitness`].
/// The discriminants are shared, so `LinkProof` may read one and dispatch on it
/// without caring which of the two enums produced the image.
#[derive(Debug, Clone, BFieldCodec)]
pub(super) enum LinkProofWitnessMemory {
    Forge(ForgeWitnessMemory),
}

// Required for `decode_from_memory`; `derive(TasmObject)` does not handle enums.
// Mirrors `SingleProofWitness`'s hand-written impl.
impl TasmObject for LinkProofWitnessMemory {
    fn label_friendly_name() -> String {
        "LinkProofWitnessMemory".to_string()
    }

    fn compute_size_and_assert_valid_size_indicator(
        _library: &mut Library,
    ) -> Vec<LabelledInstruction> {
        unimplemented!()
    }

    fn decode_iter<Itr: Iterator<Item = BFieldElement>>(
        iterator: &mut Itr,
    ) -> Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let discriminant = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::EmptySequence))?;
        let field_size = iterator
            .next()
            .ok_or(Box::new(BFieldCodecError::SequenceTooShort))?
            .value()
            .try_into()
            .map_err(|_| Box::new(BFieldCodecError::ElementOutOfRange))?;
        let field_data = iterator.take(field_size).collect_vec();

        match discriminant.value() {
            DISCRIMINANT_FOR_FORGE => Ok(Box::new(Self::Forge(*BFieldCodec::decode(&field_data)?))),
            // TODO: decode other variants here
            _ => Err(Box::new(BFieldCodecError::ElementOutOfRange)),
        }
    }
}

impl LinkProofWitness {
    pub fn from_forge(witness: ForgeWitness) -> Self {
        Self::Forge(Box::new(witness))
    }

    /// MAST hash of the [`LinkKernel`](super::link_kernel::LinkKernel) this
    /// witness attests to -- the public input of the `LinkProof` claim.
    pub fn kernel_mast_hash(&self) -> Digest {
        match self {
            Self::Forge(witness) => witness.kernel_mast_hash(),
        }
    }
}

// Every branch witness knows how to lay itself out; this enum only dispatches.
impl SecretWitness for LinkProofWitness {
    fn standard_input(&self) -> PublicInput {
        match self {
            Self::Forge(witness) => witness.standard_input(),
        }
    }

    fn output(&self) -> Vec<BFieldElement> {
        match self {
            Self::Forge(witness) => witness.output(),
        }
    }

    fn program(&self) -> Program {
        LinkProof.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        match self {
            Self::Forge(witness) => witness.nondeterminism(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;

    use proptest::prop_assert_eq;
    use tasm_lib::memory::encode_to_memory;
    use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
    use test_strategy::proptest;

    use super::*;
    use crate::chaintx::link_primitive_witness::LinkPrimitiveWitness;

    /// `ForgeWitness` is not `PartialEq` (it holds proofs), so round trips are
    /// compared on their encodings -- equivalent, since `encode` is injective.
    #[proptest]
    fn bfield_codec_round_trip(
        #[strategy(LinkPrimitiveWitness::arbitrary_strategy())] lpw: LinkPrimitiveWitness,
    ) {
        let original = LinkProofWitness::from_forge(ForgeWitness::without_proofs(&lpw));
        let decoded = *LinkProofWitness::decode(&original.encode()).unwrap();
        prop_assert_eq!(original.encode(), decoded.encode());
    }

    /// The memory image round-trips through `TasmObject::decode_iter` (the
    /// hand-written decoder, reached via `decode_from_memory`) -- the path the
    /// `LinkProof` program's rust shadow takes.
    #[proptest]
    fn memory_image_round_trip(
        #[strategy(LinkPrimitiveWitness::arbitrary_strategy())] lpw: LinkPrimitiveWitness,
    ) {
        let witness = ForgeWitness::without_proofs(&lpw);
        let original = LinkProofWitnessMemory::Forge((&witness).into());

        let mut memory = HashMap::default();
        let address = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        encode_to_memory(&mut memory, address, &original);
        let from_memory = *LinkProofWitnessMemory::decode_from_memory(&memory, address).unwrap();

        prop_assert_eq!(original.encode(), from_memory.encode());
    }

    /// The `LinkProof` program branches on the leading discriminant, and it
    /// reads that discriminant off the *memory* image, so both enums must agree
    /// on it.
    #[proptest]
    fn forge_discriminant_is_pinned(
        #[strategy(LinkPrimitiveWitness::arbitrary_strategy())] lpw: LinkPrimitiveWitness,
    ) {
        let witness = ForgeWitness::without_proofs(&lpw);
        let memory_image = LinkProofWitnessMemory::Forge((&witness).into());
        let expected = BFieldElement::new(DISCRIMINANT_FOR_FORGE);

        prop_assert_eq!(LinkProofWitness::from_forge(witness).encode()[0], expected);
        prop_assert_eq!(memory_image.encode()[0], expected);
    }
}
