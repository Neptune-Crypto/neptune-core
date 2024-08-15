use itertools::Itertools;

use crate::models::blockchain::transaction;
use crate::models::blockchain::type_scripts::native_currency::NativeCurrencyWitness;
use crate::models::blockchain::type_scripts::TypeScript;
use crate::models::blockchain::type_scripts::TypeScriptWitness;
use crate::models::consensus::ValidationLogic;
use crate::models::consensus::ValidityAstType;
use crate::models::consensus::ValidityTree;
use crate::models::consensus::WitnessType;

pub struct TypeScriptsHalt {
    pub type_scripts: Vec<TypeScript>,
    pub witnesses: Vec<Box<dyn TypeScriptWitness>>,
}

impl From<transaction::PrimitiveWitness> for TypeScriptsHalt {
    fn from(primitive_witness: transaction::PrimitiveWitness) -> Self {
        let witness = NativeCurrencyWitness {
            input_salted_utxos: primitive_witness.input_utxos.clone(),
            output_salted_utxos: primitive_witness.output_utxos.clone(),
            kernel: primitive_witness.kernel.clone(),
        };
        // todo: read out type script hashes
        // and look them up
        Self {
            type_scripts: vec![TypeScript::native_currency()],
            witnesses: vec![Box::new(witness)],
        }
    }
}

impl ValidationLogic for TypeScriptsHalt {
    fn vast(&self) -> ValidityTree {
        ValidityTree::new(
            ValidityAstType::All(
                self.witnesses
                    .iter()
                    .map(|witness| witness.vast())
                    .collect_vec(),
            ),
            WitnessType::Decomposition,
        )
    }
}
