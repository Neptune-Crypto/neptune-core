use std::sync::Arc;

use futures::channel::oneshot;
use libp2p::Multiaddr;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::Digest;

use crate::api::export::SpendingKey;
use crate::application::loops::main_loop::proof_upgrader::UpgradeJob;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::Block;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::state::wallet::expected_utxo::ExpectedUtxo;
use crate::state::wallet::monitored_utxo::MonitoredUtxo;

#[derive(Clone, Debug, strum::Display)]
pub(crate) enum MainToMiner {
    /// Communicates that a new block is now considered canonical
    NewBlock,

    Shutdown,

    /// Communicates to miner that it should work on a new block proposal.
    /// This message may only be sent when the delta in guesser fees between the
    /// old proposal and the new proposal meets a threshold value.
    NewBlockProposal,

    /// Main has received a new block or block proposal, and the miner should
    /// stop all work until it receives a [MainToMiner::Continue] message.
    WaitForContinue,

    /// Used to communicate that main loop has received the block or block
    /// proposal from the miner, and that miner can start a new task.
    Continue,

    StopMining,
    StartMining,

    StartSyncing,
    StopSyncing,
    // SetCoinbasePubkey,
}

impl MainToMiner {
    pub(crate) fn get_type(&self) -> &str {
        match self {
            MainToMiner::NewBlock => "new block",
            MainToMiner::Shutdown => "shutdown",
            MainToMiner::NewBlockProposal => "new block proposal",
            MainToMiner::WaitForContinue => "wait for continue",
            MainToMiner::Continue => "continue",
            MainToMiner::StopMining => "stop mining",
            MainToMiner::StartMining => "start mining",
            MainToMiner::StartSyncing => "start syncing",
            MainToMiner::StopSyncing => "stop syncing",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NewBlockFound {
    pub block: Box<Block>,
}

#[derive(Clone, Debug, strum::Display)]
pub(crate) enum MinerToMain {
    NewBlockFound(NewBlockFound),
    BlockProposal(Box<(Block, Vec<ExpectedUtxo>)>),

    /// Request main loop to shut down entire application and return the
    /// indicated exit code.
    Shutdown(i32),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct BlockProposalNotification {
    pub(crate) body_mast_hash: Digest,
    pub(crate) guesser_fee: NativeCurrencyAmount,
    pub(crate) height: BlockHeight,
}

impl From<&Block> for BlockProposalNotification {
    fn from(value: &Block) -> Self {
        Self {
            body_mast_hash: value.body().mast_hash(),
            guesser_fee: value.body().transaction_kernel.fee,
            height: value.header().height,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ClaimUtxoData {
    /// Some(mutxo) if UTXO has already been mined. Otherwise, None.
    pub(crate) prepared_monitored_utxo: Option<MonitoredUtxo>,

    /// Indicates if wallet already expects this UTXO.
    pub(crate) has_expected_utxo: bool,

    pub(crate) expected_utxo: ExpectedUtxo,
}

/// represents messages that can be sent from RPC server to main loop.
#[derive(Clone, Debug, strum::Display)]
pub enum RPCServerToMain {
    BroadcastTx(Arc<Transaction>),
    PerformTxProofUpgrade(Box<UpgradeJob>),
    BroadcastMempoolTransactions,
    BroadcastBlockProposal,
    ClearMempool,
    ProofOfWorkSolution(Box<Block>),
    Shutdown,
    PauseMiner,
    RestartMiner,
    SetTipToStoredBlock(Digest),
    UpdateStatus,

    // Used by JSON-RPC
    SubmitTx(Box<Transaction>),
    RescanAnnounced {
        first: BlockHeight,
        last: BlockHeight,
        keys: Vec<SpendingKey>,
    },
    RescanExpected {
        first: BlockHeight,
        last: BlockHeight,
    },
    RescanOutgoing {
        first: BlockHeight,
        last: BlockHeight,
    },
    RescanGuesserRewards {
        first: BlockHeight,
        last: BlockHeight,
    },
    Ban(Multiaddr),
    Unban(Multiaddr),
}

pub trait Cancelable: Send + Sync {
    fn is_canceled(&self) -> bool;
}

impl<T: Send + Sync> Cancelable for oneshot::Sender<T> {
    fn is_canceled(&self) -> bool {
        self.is_canceled()
    }
}
