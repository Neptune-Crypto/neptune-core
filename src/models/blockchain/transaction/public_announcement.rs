use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// represents arbitrary data that can be stored in a transaction on the public blockchain
///
/// initially these are used for transmitting encrypted secrets necessary
/// for a utxo recipient to identify and claim it.
///
/// See [Transaction]
#[derive(
    Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, Default, TasmObject,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(arbitrary::Arbitrary))]
pub struct PublicAnnouncement {
    pub message: Vec<BFieldElement>,
}

impl PublicAnnouncement {
    pub fn new(message: Vec<BFieldElement>) -> Self {
        Self { message }
    }
}
