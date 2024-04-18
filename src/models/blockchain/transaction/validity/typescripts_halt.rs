use crate::models::{
    blockchain::{
        transaction,
        type_scripts::{native_currency::NativeCurrencyWitness, TypeScript, TypeScriptWitness},
    },
    consensus::{ValidationLogic, ValidityAstType, ValidityTree, WitnessType},
};

use itertools::Itertools;

// #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
// pub struct BasicTypeScriptWitness {
//     type_script: TypeScript,
//     input_utxos: SaltedUtxos,
//     output_utxos: SaltedUtxos,
//     transaction_kernel: TransactionKernel,
// }

// impl TypeScriptWitness for BasicTypeScriptWitness {
//     fn transaction_kernel(&self) -> TransactionKernel {
//         self.transaction_kernel.clone()
//     }

//     fn salted_input_utxos(&self) -> SaltedUtxos {
//         self.input_utxos.clone()
//     }

//     fn salted_output_utxos(&self) -> SaltedUtxos {
//         self.output_utxos.clone()
//     }

//     fn from_primitive_witness(primitive_transaction_witness: &PrimitiveWitness) -> Self {
//         Self {
//             type_script: TypeScript::new(NativeCurrency.program()),
//             input_utxos: primitive_transaction_witness.input_utxos.clone(),
//             output_utxos: primitive_transaction_witness.output_utxos.clone(),
//             transaction_kernel: primitive_transaction_witness.kernel.clone(),
//         }
//     }
// }

// impl SecretWitness for BasicTypeScriptWitness {
//     fn standard_input(&self) -> PublicInput {
//         self.type_script_standard_input()
//     }

//     fn nondeterminism(&self) -> NonDeterminism {
//         todo!()
//     }
// }

// impl ValidationLogic for BasicTypeScriptWitness {
//     fn vast(&self) -> ValidityAST {
//         ValidityAST::new(
//             ValidityAstType::Atomic(
//                 self.type_script.program,
//                 Claim::new(self.type_script.hash())
//                     .with_input(self.type_script_standard_input().individual_tokens),
//             ),
//             WitnessType::RawWitness(self.nondeterminism().into()),
//         )
//     }
// }

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
