use std::ops::Deref;
use std::ops::DerefMut;

use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Library;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof as VmProof;

use crate::protocol::consensus::transaction::BFieldCodec;
use crate::triton_vm::prelude::LabelledInstruction;
use crate::BFieldElement;

/// defines Mock proof behaviors. (private)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
enum MockProofBehavior {
    ValidMock,
    InvalidMock,
}

/// represents a triton-vm proof that can optionally be mocked.
///
/// Mock proofs are useful for testing and simulations because they can be generated
/// instantly on commodity hardware whereas real proofs can take minutes on powerful
/// machines and simply be impossible to generate on weaker devices.
///
/// In particular the regtest network (mode) uses mock proofs so that transactions
/// and blocks can be generated quickly at will.
///
/// As of this writing no other network uses mock proofs and mock proofs are
/// explicitly disallowed on Mainnet.  See
/// [Network::use_mock_proof()](crate::application::config::network::Network::use_mock_proof()).
///
/// The proof can be of three types:
/// 1. standard.      not a mock proof
/// 2. valid-mock.    a mock proof that passes validation (if mock proofs are allowed)
/// 3. invalid-mock.  a mock proof that fails validation (if mock proofs are allowed, or not)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, GetSize)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct NeptuneProof {
    proof: VmProof,
}

impl BFieldCodec for NeptuneProof {
    type Error = <VmProof as BFieldCodec>::Error;

    fn decode(sequence: &[BFieldElement]) -> Result<Box<Self>, Self::Error> {
        Ok(Box::new(Self {
            proof: *VmProof::decode(sequence)?,
        }))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        self.proof.encode()
    }

    fn static_length() -> Option<usize> {
        VmProof::static_length()
    }
}

impl TasmObject for NeptuneProof {
    fn label_friendly_name() -> String {
        VmProof::label_friendly_name()
    }

    fn compute_size_and_assert_valid_size_indicator(
        library: &mut Library,
    ) -> Vec<LabelledInstruction> {
        VmProof::compute_size_and_assert_valid_size_indicator(library)
    }

    fn decode_iter<Itr: Iterator<Item = BFieldElement>>(
        iterator: &mut Itr,
    ) -> Result<Box<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let elems: Vec<BFieldElement> = iterator.collect();
        let mockable_proof = Self::decode(&elems)?;
        Ok(mockable_proof)
    }
}

impl Deref for NeptuneProof {
    type Target = VmProof;

    fn deref(&self) -> &Self::Target {
        &self.proof
    }
}

impl DerefMut for NeptuneProof {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.proof
    }
}

impl From<NeptuneProof> for VmProof {
    fn from(mp: NeptuneProof) -> VmProof {
        mp.proof
    }
}

impl From<Vec<BFieldElement>> for NeptuneProof {
    fn from(v: Vec<BFieldElement>) -> Self {
        Self { proof: VmProof(v) }
    }
}

impl From<VmProof> for NeptuneProof {
    fn from(proof: VmProof) -> Self {
        Self { proof }
    }
}

impl NeptuneProof {
    /// creates an invalid standard proof (not a mock proof)
    pub(crate) fn invalid() -> Self {
        Self {
            proof: VmProof(vec![]),
        }
    }

    /// creates an invalid proof (not a mock proof) of a specified length, in
    /// number of b-field elements.
    #[cfg(test)]
    pub fn invalid_with_size(len: usize) -> Self {
        use num_traits::ConstZero;

        Self {
            proof: VmProof(vec![BFieldElement::ZERO; len]),
        }
    }

    /// create a mock proof and specify if valid or invalid.
    pub fn mock(valid: bool) -> Self {
        let behavior = if valid {
            MockProofBehavior::ValidMock
        } else {
            MockProofBehavior::InvalidMock
        };
        Self {
            proof: VmProof(behavior.encode()),
        }
    }

    /// create a mock proof that will pass validation (if mock proofs are allowed)
    pub fn valid_mock(_claim: Claim) -> Self {
        Self {
            proof: VmProof(MockProofBehavior::ValidMock.encode()),
        }
    }

    /// create a mock proof that will fail validation (if mock proofs are allowed, or not)
    pub fn invalid_mock(_claim: Claim) -> Self {
        Self {
            proof: VmProof(MockProofBehavior::InvalidMock.encode()),
        }
    }

    /// indicates if this is a standard proof (not a mock proof)
    pub fn is_standard(&self) -> bool {
        !self.is_valid_mock() && !self.is_invalid_mock()
    }

    /// indicates if this is a mock proof
    pub fn is_mock(&self) -> bool {
        self.is_valid_mock() || self.is_invalid_mock()
    }

    /// indicates if this is a valid mock proof
    pub fn is_valid_mock(&self) -> bool {
        self.matches_behavior(MockProofBehavior::ValidMock)
    }

    /// indicates if this is an invalid mock proof
    pub fn is_invalid_mock(&self) -> bool {
        self.matches_behavior(MockProofBehavior::InvalidMock)
    }

    fn matches_behavior(&self, target: MockProofBehavior) -> bool {
        if let Ok(behavior) = MockProofBehavior::decode(&self.proof.0) {
            *behavior == target
        } else {
            false
        }
    }
}

// Proof is aliased to NeptuneProof this is done to avoid lots of diffs
// wherever Proof is used.  we can remove this alias if/when code is updated to
// use NeptuneProof directly
pub type Proof = NeptuneProof;
