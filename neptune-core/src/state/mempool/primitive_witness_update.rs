use crate::protocol::consensus::transaction::primitive_witness::PrimitiveWitness;

/// A primitive-witness backed transaction that must be upgraded to be valid
/// under a new mutator set.
#[derive(Debug, Clone)]
pub struct PrimitiveWitnessUpdate {
    /// The deprecated primitive witness, before applying a mutator set update.
    pub(crate) old_primitive_witness: PrimitiveWitness,
}

impl PrimitiveWitnessUpdate {
    pub(crate) fn new(old_primitive_witness: PrimitiveWitness) -> Self {
        Self {
            old_primitive_witness,
        }
    }
}
