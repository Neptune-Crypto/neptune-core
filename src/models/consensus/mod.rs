use crate::models::blockchain::type_scripts::native_currency::NativeCurrency;
use crate::models::blockchain::type_scripts::time_lock::TimeLock;
use crate::Hash;
use get_size::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use strum::Display;
/// This file contains abstractions for verifying consensus logic using TritonVM STARK
/// proofs. The concrete logic is specified in the directories `transaction` and `block`.
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::program::Program;
use tasm_lib::triton_vm::stark::Stark;
use tasm_lib::twenty_first::shared_math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::shared_math::bfield_codec::BFieldCodec;
use tasm_lib::Digest;
use triton_vm::prelude::Claim;
use triton_vm::prelude::NonDeterminism;
use triton_vm::prelude::Proof;
use triton_vm::prelude::PublicInput;

use self::tasm::program::ConsensusError;
use self::tasm::program::ConsensusProgram;

pub mod mast_hash;
pub mod tasm;

/// The claim to validiy of a block or transaction (a *validity claim*) is a Boolean
/// expression for which we build an abstract syntax tree. Nodes in this tree assume
/// the value true or false and those values propagate up through disjunction and
/// conjunction gates to the root. The validity claim is true iff the root of this
/// tree evaluates to true.
///
/// Every terminal ("atomic") node in this tree can be supported by a raw witness.
/// Every terminal or non-terminal node in this tree can be supported by a proof. In
/// the end, if the validity claim is valid it should be supported by one (recursive)
/// proof.

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum ValidityAstType {
    /// The validity claim is true axiomatically, by definition. E.g.: the genesis
    /// block.
    Axiom,
    /// The root of a validity tree, containing the hash of the object it pertains
    /// to.
    Root(Digest, Box<ValidityTree>),
    /// A decomposition of the validity claim into a disjunction of smaller claims.
    /// The disjunction is true iff one of the subclaims is true.
    Any(Vec<ValidityTree>),
    /// A decomposition of the validity claim into a conjunction of smaller claims.
    /// The conjunction is true iff all of the subclaims are true.
    All(Vec<ValidityTree>),
    /// The validity claim does not decompose into clauses. We have reached the
    /// terminal stage of the analytical process. This claim is atomic and there is
    /// a dedicated raw witness that proves it.
    Atomic(Option<Box<Program>>, Claim, WhichProgram),
}

impl core::hash::Hash for ValidityAstType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}

impl ValidityAstType {}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, Hash)]
pub struct RawWitness {
    tokens: Vec<BFieldElement>,
    ram: Vec<(BFieldElement, BFieldElement)>,
    digests: Vec<Digest>,
}

impl From<NonDeterminism<BFieldElement>> for RawWitness {
    fn from(nondeterminism: NonDeterminism<BFieldElement>) -> Self {
        Self {
            tokens: nondeterminism.individual_tokens,
            ram: nondeterminism.ram.into_iter().collect_vec(),
            digests: nondeterminism.digests,
        }
    }
}

impl From<RawWitness> for NonDeterminism<BFieldElement> {
    fn from(value: RawWitness) -> Self {
        Self {
            individual_tokens: value.tokens.clone(),
            ram: value.ram.iter().cloned().collect(),
            digests: value.digests.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub enum WitnessType {
    /// A single proof for the entire claim, typically produced via recursion.
    Proof(Proof),
    RawWitness(RawWitness),
    /// As we do not have recursion yet, sometimes we just need to take things on faith.
    /// This should be depracated before mainnet launch, or just not accepted in the
    /// peer loop.
    Faith,
    /// As the claim decomposes into a conjunction or disjunction or smaller claims,
    /// it is those smaller claims not this one that need supporting raw witnesses.
    Decomposition,
    /// No witness.
    None,
}

impl core::hash::Hash for WitnessType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encode().hash(state);
    }
}

/// An abstract syntax tree that evaluates to true if the block or transaction is
/// valid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, Hash)]
pub struct ValidityTree {
    pub vast_type: ValidityAstType,
    pub witness_type: WitnessType,
}

impl Default for ValidityTree {
    fn default() -> Self {
        Self {
            vast_type: ValidityAstType::Axiom,
            witness_type: WitnessType::Faith,
        }
    }
}

impl ValidityTree {
    pub fn new(vast_type: ValidityAstType, witness_type: WitnessType) -> Self {
        Self {
            vast_type,
            witness_type,
        }
    }

    pub fn root(object_hash: Digest, tree: ValidityTree) -> Self {
        Self {
            witness_type: WitnessType::None,
            vast_type: ValidityAstType::Root(object_hash, Box::new(tree)),
        }
    }

    pub fn none() -> Self {
        Self {
            witness_type: WitnessType::None,
            vast_type: ValidityAstType::Axiom,
        }
    }

    /// Convenience constructor
    pub fn all(vasts: Vec<Self>) -> Self {
        Self {
            witness_type: WitnessType::Decomposition,
            vast_type: ValidityAstType::All(vasts),
        }
    }

    /// Convenience constructor
    pub fn any(vasts: Vec<Self>) -> Self {
        Self {
            witness_type: WitnessType::Decomposition,
            vast_type: ValidityAstType::Any(vasts),
        }
    }

    /// Convenience constructor
    pub fn axiom() -> Self {
        Self {
            vast_type: ValidityAstType::Axiom,
            witness_type: WitnessType::Faith,
        }
    }

    pub fn verify(&self, kernel_hash: Digest) -> bool {
        match &self.vast_type {
            ValidityAstType::Root(object_digest, tree) => {
                *object_digest == kernel_hash && tree.verify(kernel_hash)
            }
            ValidityAstType::Any(clauses) => {
                clauses.iter().any(|clause| clause.verify(kernel_hash))
            }
            ValidityAstType::All(clauses) => {
                clauses.iter().all(|clause| clause.verify(kernel_hash))
            }
            ValidityAstType::Atomic(maybe_program, claim, which_program) => {
                let WitnessType::RawWitness(raw_witness) = &self.witness_type else {
                    return false;
                };
                if let Some(program) = maybe_program {
                    if program.labelled_instructions().is_empty() {
                        which_program
                            .run(claim.input.clone().into(), raw_witness.clone().into())
                            .is_ok()
                    } else {
                        program
                            .run(claim.input.clone().into(), raw_witness.clone().into())
                            .is_ok()
                    }
                } else {
                    false
                }
            }
            ValidityAstType::Axiom => true,
        }
    }

    pub fn prove(&mut self) {
        match &mut self.vast_type {
            ValidityAstType::Root(_object_digest, tree) => {
                tree.prove();
                self.witness_type = tree.witness_type.clone();
                tree.witness_type = WitnessType::None;
            }
            ValidityAstType::Axiom => {}
            ValidityAstType::Any(branches) => {
                branches.iter_mut().for_each(|branch| {
                    branch.prove();
                });
                // can't use recursion yet, so faith instead
                self.witness_type = WitnessType::Faith;
                self.vast_type = ValidityAstType::Any(vec![])
            }
            ValidityAstType::All(branches) => {
                branches.iter_mut().for_each(|branch| {
                    branch.prove();
                });
                // can't use recursion yet, so faith instead
                self.witness_type = WitnessType::Faith;
                self.vast_type = ValidityAstType::All(vec![])
            }
            ValidityAstType::Atomic(program, claim, which_program) => {
                if program.is_some()
                    && !program.as_ref().unwrap().labelled_instructions().is_empty()
                {
                    if let WitnessType::RawWitness(raw_witness) = &self.witness_type {
                        let nondeterminism: NonDeterminism<BFieldElement> =
                            raw_witness.clone().into();
                        let proof = triton_vm::prove(
                            Stark::default(),
                            claim,
                            program.as_deref().unwrap(),
                            nondeterminism,
                        )
                        .unwrap_or_else(|_| panic!("proving {which_program} ..."));
                        *program = None;
                        self.witness_type = WitnessType::Proof(proof);
                    }
                }
            }
        }
    }
}

/// A `SecretWitness` is data that makes a `ConsensusProgram` halt gracefully, but
/// that should be hidden behind a zero-knowledge proof. Phrased differently, after
/// proving the matching `ConsensusProgram`, the `SecretWitness` should be securely
/// deleted.
pub trait SecretWitness {
    /// The program's (public/standard) input
    fn standard_input(&self) -> PublicInput;

    /// The program's (standard/public) output.
    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program;

    fn claim(&self) -> Claim {
        Claim::new(self.program().hash::<Hash>())
            .with_input(self.standard_input().individual_tokens)
            .with_output(self.output())
    }

    /// The non-determinism for the VM that this witness corresponds to
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement>;

    // fn verify(&self) -> bool {
    //     if self.consensus_program().code().is_empty() {
    //         self.consensus_program()
    //             .program()
    //             .run(self.standard_input(), self.nondeterminism())
    //             .is_ok()
    //     } else {
    //         self.consensus_program()
    //             .run(
    //                 &self.standard_input().individual_tokens,
    //                 self.nondeterminism(),
    //             )
    //             .is_ok()
    //     }
    // }
}

pub trait ValidationLogic {
    fn vast(&self) -> ValidityTree;
}

/// This enum lists all programs featured anywhere in the consensus logic. It is for
/// development purposes only. After we have recursion, it should be phased out. The
/// purpose of this enum is to a) benefit debugging efforts, and b) rely on rust
/// shadows when we do not have all programs in tasm.`1`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, GetSize, Display)]
pub enum WhichProgram {
    LockScriptHalts,
    LockScriptsHalt,
    TypeScriptsHalt,
    TimeLock,
    NativeCurrency,
    RemovalRecordsIntegrity,
    MutatorSetUpdate,
    Merger,
}

impl WhichProgram {
    pub fn run(
        &self,
        public_input: PublicInput,
        non_determinism: NonDeterminism<BFieldElement>,
    ) -> Result<Vec<BFieldElement>, ConsensusError> {
        match self {
            WhichProgram::TimeLock => {
                TimeLock.run(&public_input.individual_tokens, non_determinism)
            }
            WhichProgram::NativeCurrency => {
                NativeCurrency.run(&public_input.individual_tokens, non_determinism)
            }
            WhichProgram::LockScriptHalts => todo!(),
            WhichProgram::LockScriptsHalt => todo!(),
            WhichProgram::TypeScriptsHalt => todo!(),
            WhichProgram::RemovalRecordsIntegrity => todo!(),
            WhichProgram::MutatorSetUpdate => todo!(),
            WhichProgram::Merger => todo!(),
        }
    }
}
