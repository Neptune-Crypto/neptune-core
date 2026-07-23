use itertools::Itertools;
use neptune_primitives::mast_hash::MastHash;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Library;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::prelude::LabelledInstruction;
use tasm_lib::twenty_first::error::BFieldCodecError;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use super::link_witness::LinkWitness;

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
    /// `LinkWitness -> LinkTx`: the entry point into the chain pipeline.
    Forge(Box<LinkWitness>),
}

// Required for `decode_from_memory`; `derive(TasmObject)` does not handle enums.
// Mirrors `SingleProofWitness`'s hand-written impl.
impl TasmObject for LinkProofWitness {
    fn label_friendly_name() -> String {
        "LinkProofWitness".to_string()
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
            DISCRIMINANT_FOR_FORGE => Ok(Box::new(Self::Forge(Box::new(*BFieldCodec::decode(
                &field_data,
            )?)))),
            // TODO: decode other variants here
            _ => Err(Box::new(BFieldCodecError::ElementOutOfRange)),
        }
    }
}

impl LinkProofWitness {
    pub fn from_forge(witness: LinkWitness) -> Self {
        Self::Forge(Box::new(witness))
    }

    /// MAST hash of the [`LinkKernel`](super::link_kernel::LinkKernel) this
    /// witness attests to -- the public input of the `LinkProof` claim.
    pub fn kernel_mast_hash(&self) -> Digest {
        match self {
            Self::Forge(witness) => witness.kernel.mast_hash(),
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

    /// Round-trip through both decoders: `BFieldCodec` (derived) and
    /// `TasmObject::decode_iter` (hand-written, via `decode_from_memory` -- the
    /// path the `LinkProof` program takes).
    #[proptest]
    fn bfield_codec_round_trip(
        #[strategy(LinkWitness::arbitrary_strategy())] witness: LinkWitness,
    ) {
        let original = LinkProofWitness::from_forge(witness);
        let LinkProofWitness::Forge(original) = &original;

        let encoding = LinkProofWitness::from_forge(*original.clone()).encode();
        let LinkProofWitness::Forge(decoded) = *LinkProofWitness::decode(&encoding).unwrap();
        prop_assert_eq!(original.as_ref(), decoded.as_ref());

        let mut memory = HashMap::default();
        let address = FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
        encode_to_memory(
            &mut memory,
            address,
            &LinkProofWitness::from_forge(*decoded),
        );
        let LinkProofWitness::Forge(from_memory) =
            *LinkProofWitness::decode_from_memory(&memory, address).unwrap();
        prop_assert_eq!(original.as_ref(), from_memory.as_ref());
    }

    /// The `LinkProof` program branches on the leading discriminant, so pin it.
    #[proptest]
    fn forge_discriminant_is_pinned(
        #[strategy(LinkWitness::arbitrary_strategy())] witness: LinkWitness,
    ) {
        let encoding = LinkProofWitness::from_forge(witness).encode();
        prop_assert_eq!(encoding[0], BFieldElement::new(DISCRIMINANT_FOR_FORGE));
    }
}
