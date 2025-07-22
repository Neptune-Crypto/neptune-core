use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

#[derive(
    Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec, TasmObject, GetSize,
)]
#[cfg_attr(
    any(test, feature = "arbitrary-impls"),
    derive(arbitrary::Arbitrary, Default)
)]
pub struct GuesserReceiverData {
    pub receiver_digest: Digest,
    pub lock_script_hash: Digest,
}
