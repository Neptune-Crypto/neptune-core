use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::twenty_first::prelude::Mmr;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;

use crate::application::json_rpc::core::model::block::transaction_kernel::RpcTransactionKernel;
use crate::protocol::consensus::block::block_body::BlockBody;
use crate::util_types::mutator_set::active_window::ActiveWindow;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcMmrAccumulator {
    pub leaf_count: u64,
    pub peaks: Vec<Digest>,
}

impl From<&MmrAccumulator> for RpcMmrAccumulator {
    fn from(mmr: &MmrAccumulator) -> Self {
        Self {
            leaf_count: mmr.num_leafs(),
            peaks: mmr.peaks(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RpcActiveWindow(pub Vec<u32>);

impl From<&ActiveWindow> for RpcActiveWindow {
    fn from(window: &ActiveWindow) -> Self {
        Self(window.to_vec_u32())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcMutatorSetAccumulator {
    pub aocl: RpcMmrAccumulator,
    pub swbf_inactive: RpcMmrAccumulator,
    pub swbf_active: RpcActiveWindow,
}

impl From<&MutatorSetAccumulator> for RpcMutatorSetAccumulator {
    fn from(set: &MutatorSetAccumulator) -> Self {
        Self {
            aocl: RpcMmrAccumulator::from(&set.aocl),
            swbf_inactive: RpcMmrAccumulator::from(&set.swbf_inactive),
            swbf_active: RpcActiveWindow::from(&set.swbf_active),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockBody {
    pub transaction_kernel: RpcTransactionKernel,
    pub mutator_set_accumulator: RpcMutatorSetAccumulator,
    pub lock_free_mmr_accumulator: RpcMmrAccumulator,
    pub block_mmr_accumulator: RpcMmrAccumulator,
}

impl From<&BlockBody> for RpcBlockBody {
    fn from(body: &BlockBody) -> Self {
        Self {
            transaction_kernel: RpcTransactionKernel::from(&body.transaction_kernel),
            mutator_set_accumulator: RpcMutatorSetAccumulator::from(
                &body.mutator_set_accumulator_without_guesser_fees(),
            ),
            lock_free_mmr_accumulator: RpcMmrAccumulator::from(&body.lock_free_mmr_accumulator),
            block_mmr_accumulator: RpcMmrAccumulator::from(&body.block_mmr_accumulator),
        }
    }
}
