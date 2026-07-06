//! Foundational, low-level primitives shared across neptune-cash: a consensus
//! [`Timestamp`](timestamp::Timestamp) type and the [`MastHash`](mast_hash::MastHash)
//! trait for computing Merkle-tree-based authenticated hashes of structured data.

// Re-exported at the crate root so the `BFieldCodec`/`TasmObject` derive macros
// (which generate `crate::twenty_first` / `crate::triton_vm` / `crate::tasm_lib`
// paths) resolve.
pub use tasm_lib;
pub use tasm_lib::prelude::triton_vm;
pub use tasm_lib::prelude::twenty_first;

pub mod block_height;
pub mod block_selector;
pub mod data_directory;
pub mod difficulty_control;
pub mod mast_hash;
pub mod network;
pub mod timestamp;
