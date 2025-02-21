//! This module defines states used by the `MiningStateMachine`.
//!
//! There are 4 primary inter-related enums:
//!
//! 1. MiningState
//! 2. MiningStateData
//! 3. MiningStatus
//! 4. MiningEvent
//!
//! 1 to 3 all have (must have) the same variants as they all represent
//! the same states, but for different usages.
//!
//! [MiningState] defines the basic states without any associated data.
//! The `MiningStateMachine` defines allowed transitions between these
//! states.
//!
//! [MiningStateData] variants include a timestamp and data related to
//! processing, such as a proposed-block.
//!
//! [MiningStatus] is intended for display purposes.  Variants include
//! short informational summaries that can be serialized over the wire
//! efficiently.
//!
//! [MiningEvent] represents events that the MiningStateMachine can handle
//! in order to transition between states.  These events may have associated
//! data.

use std::hash::Hash;
use std::sync::Arc;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

use crate::models::blockchain::block::Block;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;

pub(super) type ProposedBlock = Arc<Block>;

/// Defines the possible states of the `MiningStateMachine`.
/// The `MiningStateMachine` defines allowed transitions between these
/// states.
///
/// There is a notion of a "Happy Path" which is an ordered
/// set of states that progress for each block during mining.
///
/// The same ordered set of happy-path states applies to both
/// composing and guessing roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter)]
#[repr(u8)]
pub(crate) enum MiningState {
    // ---- happy path ----
    Init = 0,
    AwaitBlockProposal = 1,
    Composing = 2,
    AwaitBlock = 3,
    Guessing = 4,
    NewTipBlock = 5,
    // ---- end happy path ----
    ComposeError = 6,
    Paused = 7,   // Rpc, SyncBlocks, NeedConnection
    UnPaused = 8, // transitional state.
    Disabled = 9,
    Shutdown = 10,
}

/// Associates processing data with each state.
///
/// note: variants must match those of [MiningState]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum MiningStateData {
    Disabled(SystemTime),
    Init(SystemTime),
    Paused(SystemTime, Vec<MiningPausedReason>), // Rpc, SyncBlocks, NeedConnection
    UnPaused(SystemTime),
    AwaitBlockProposal(SystemTime),
    AwaitBlock(SystemTime, ProposedBlock),
    Composing(SystemTime),
    Guessing(SystemTime, ProposedBlock),
    NewTipBlock(SystemTime),
    ComposeError(SystemTime),
    Shutdown(SystemTime),
}

/// associates display/summary data with each state.
///
/// This type is intended for RPC API usage.  As such it implements
/// Serialize and Deserialize.
///
/// note: variants must match those of [MiningState]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MiningStatus {
    Disabled(SystemTime),
    Init(SystemTime),
    Paused(SystemTime, Vec<MiningPausedReason>), // Rpc, SyncBlocks, NeedConnection
    UnPaused(SystemTime),
    AwaitBlockProposal(SystemTime),
    AwaitBlock(SystemTime, BlockSummary),
    Composing(SystemTime),
    Guessing(SystemTime, BlockSummary),
    NewTipBlock(SystemTime),
    ComposeError(SystemTime),
    Shutdown(SystemTime),
}

/// defines events that the `MiningStateMachine` can handle.
#[derive(Clone)]
pub(crate) enum MiningEvent {
    /// initialize. reset. restart.
    /// each time a block is found, we begin with Init.
    Init,

    /// signals the start of mining.
    /// Composers should receive a StartComposing event.
    /// Guessers wait here until a block proposal is found.
    AwaitBlockProposal,

    /// signals to begin composing.
    StartComposing,

    /// signals to begin guessing.
    StartGuessing,

    /// signals mining is paused via RPC
    PauseByRpc,

    /// signals mining is unpaused via RPC
    UnPauseByRpc,

    /// signals mining is paused while syncing blocks
    PauseBySyncBlocks,

    /// signals mining is unpaused after syncing blocks
    UnPauseBySyncBlocks,

    /// signals mining is paused because we need a connection
    PauseByNeedConnection,

    /// signals mining is unpaused because we got a connection
    UnPauseByNeedConnection,

    /// signals we received a new block proposal
    NewBlockProposal(ProposedBlock),

    /// signals we received a new tip block
    NewTipBlock,

    /// signals that an error occurred while composing.
    ComposeError,

    /// signals that mining is shutting down.
    Shutdown,
}

/// Indicates reason for being in the Paused state.
///
/// note that Paused state can have multiple `MiningPausedReason`
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, strum::EnumIter)]
pub enum MiningPausedReason {
    /// paused by rpc. (user)
    Rpc,

    /// syncing blocks
    SyncBlocks,

    /// need peer connections
    NeedConnection,
}

/// intended for summarizing a proposed block for the Guessing state.
///
/// Intended to be sent via RPC API.  So it implements Serialize and
/// Deserialize.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BlockSummary {
    pub num_inputs: usize,
    pub num_outputs: usize,
    pub total_coinbase: NativeCurrencyAmount,
    pub total_guesser_fee: NativeCurrencyAmount,
}

// This file contains several inter-related enums and it is useful to
// present them one after another (above).
//
// To keep things organized, we place the impl for each one into its
// own module below.  We could also consider making a file for each.

mod mining_event_impl {
    use super::*;

    impl MiningEvent {
        fn name(&self) -> &str {
            match self {
                Self::Init => "init",
                Self::AwaitBlockProposal => "await-block-proposal",
                Self::StartComposing => "start-composing",
                Self::StartGuessing => "start-guessing",
                Self::PauseByRpc => "pause-by-rpc",
                Self::UnPauseByRpc => "unpause-by-rpc",
                Self::PauseBySyncBlocks => "pause-by-sync-blocks",
                Self::UnPauseBySyncBlocks => "unpause-by-sync-blocks",
                Self::PauseByNeedConnection => "pause-by-need-connection",
                Self::UnPauseByNeedConnection => "unpause-by-need-connection",
                Self::NewBlockProposal(_) => "new-block-proposal",
                Self::NewTipBlock => "new-tip-block",
                Self::ComposeError => "compose-error",
                Self::Shutdown => "shutdown",
            }
        }
    }

    // we impl Debug in order to prevent writing out entire block in log(s)
    impl std::fmt::Debug for MiningEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.name())
        }
    }

    impl std::fmt::Display for MiningEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.name())
        }
    }
}

mod mining_state_impl {
    use super::*;

    impl MiningState {
        pub(super) fn name(&self) -> &str {
            match *self {
                Self::Disabled => "disabled",
                Self::Init => "initializing",
                Self::Paused => "paused",
                Self::UnPaused => "unpaused",
                Self::AwaitBlockProposal => "await block proposal",
                Self::AwaitBlock => "await block",
                Self::Composing => "composing",
                Self::Guessing => "guessing",
                Self::NewTipBlock => "new tip block",
                Self::ComposeError => "composer error",
                Self::Shutdown => "shutdown",
            }
        }
    }

    impl From<&MiningStatus> for MiningState {
        fn from(s: &MiningStatus) -> MiningState {
            match *s {
                MiningStatus::Disabled(_) => MiningState::Disabled,
                MiningStatus::Init(_) => MiningState::Init,
                MiningStatus::Paused(..) => MiningState::Paused,
                MiningStatus::UnPaused(_) => MiningState::UnPaused,
                MiningStatus::AwaitBlockProposal(_) => MiningState::AwaitBlockProposal,
                MiningStatus::AwaitBlock(..) => MiningState::AwaitBlock,
                MiningStatus::Composing(_) => MiningState::Composing,
                MiningStatus::Guessing(..) => MiningState::Guessing,
                MiningStatus::NewTipBlock(_) => MiningState::NewTipBlock,
                MiningStatus::ComposeError(_) => MiningState::ComposeError,
                MiningStatus::Shutdown(_) => MiningState::Shutdown,
            }
        }
    }

    impl From<&MiningStateData> for MiningState {
        fn from(s: &MiningStateData) -> Self {
            match *s {
                MiningStateData::Disabled(_) => MiningState::Disabled,
                MiningStateData::Init(_) => MiningState::Init,
                MiningStateData::Paused(..) => MiningState::Paused,
                MiningStateData::UnPaused(_) => MiningState::UnPaused,
                MiningStateData::AwaitBlockProposal(_) => MiningState::AwaitBlockProposal,
                MiningStateData::AwaitBlock(..) => MiningState::AwaitBlock,
                MiningStateData::Composing(_) => MiningState::Composing,
                MiningStateData::Guessing(..) => MiningState::Guessing,
                MiningStateData::NewTipBlock(_) => MiningState::NewTipBlock,
                MiningStateData::ComposeError(_) => MiningState::ComposeError,
                MiningStateData::Shutdown(_) => MiningState::Shutdown,
            }
        }
    }

    impl std::fmt::Display for MiningState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.name())
        }
    }
}

mod mining_state_data_impl {
    use std::hash::Hasher;

    use super::*;

    impl TryFrom<MiningState> for MiningStateData {
        type Error = anyhow::Error;

        /// note that:
        ///
        ///   1. MiningStateData::Guessing is not supported.
        ///   2. MiningStateData::Paused will use MiningPausedReason::Rpc
        fn try_from(state: MiningState) -> Result<Self, Self::Error> {
            Ok(match state {
                MiningState::Disabled => MiningStateData::disabled(),
                MiningState::Init => MiningStateData::init(),
                MiningState::AwaitBlockProposal => MiningStateData::await_block_proposal(),
                MiningState::AwaitBlock => anyhow::bail!("unsupported usage"),
                MiningState::Composing => MiningStateData::composing(),
                MiningState::Guessing => anyhow::bail!("unsupported usage"),
                MiningState::NewTipBlock => MiningStateData::new_tip_block(),
                MiningState::ComposeError => MiningStateData::compose_error(),
                MiningState::Shutdown => MiningStateData::shutdown(),
                MiningState::Paused => MiningStateData::paused(MiningPausedReason::Rpc),
                MiningState::UnPaused => MiningStateData::unpaused(),
            })
        }
    }

    impl MiningStateData {
        pub fn disabled() -> Self {
            Self::Disabled(SystemTime::now())
        }

        pub fn init() -> Self {
            Self::Init(SystemTime::now())
        }

        pub fn paused(reason: MiningPausedReason) -> Self {
            Self::Paused(SystemTime::now(), vec![reason])
        }

        pub fn unpaused() -> Self {
            Self::UnPaused(SystemTime::now())
        }

        pub fn await_block_proposal() -> Self {
            Self::AwaitBlockProposal(SystemTime::now())
        }

        pub fn await_block(proposed_block: ProposedBlock) -> Self {
            Self::AwaitBlock(SystemTime::now(), proposed_block)
        }

        pub fn composing() -> Self {
            Self::Composing(SystemTime::now())
        }

        pub fn guessing(proposed_block: ProposedBlock) -> Self {
            Self::Guessing(SystemTime::now(), proposed_block)
        }

        pub fn new_tip_block() -> Self {
            Self::NewTipBlock(SystemTime::now())
        }

        pub fn compose_error() -> Self {
            Self::ComposeError(SystemTime::now())
        }

        pub fn shutdown() -> Self {
            Self::Shutdown(SystemTime::now())
        }

        pub fn is_init(&self) -> bool {
            self.state() == MiningState::Init
        }

        pub fn is_composing(&self) -> bool {
            self.state() == MiningState::Composing
        }

        pub fn is_guessing(&self) -> bool {
            self.state() == MiningState::Guessing
        }

        pub fn is_shutdown(&self) -> bool {
            self.state() == MiningState::Shutdown
        }

        pub fn state(&self) -> MiningState {
            MiningState::from(self)
        }

        pub(crate) fn name(&self) -> String {
            self.state().name().to_owned()
        }

        pub fn since(&self) -> SystemTime {
            match *self {
                Self::Disabled(t) => t,
                Self::Init(t) => t,
                Self::Paused(t, _) => t,
                Self::UnPaused(t) => t,
                Self::AwaitBlockProposal(t) => t,
                Self::AwaitBlock(t, _) => t,
                Self::Composing(t) => t,
                Self::Guessing(t, _) => t,
                Self::NewTipBlock(t) => t,
                Self::ComposeError(t) => t,
                Self::Shutdown(t) => t,
            }
        }

        // returns hash of this MiningStateData, using [std::hash::DefaultHasher].
        pub fn std_hash(&self) -> u64 {
            let mut s = std::hash::DefaultHasher::new();
            self.hash(&mut s);
            s.finish()
        }
    }
}

mod mining_status_impl {
    use std::time::Duration;

    use itertools::Itertools;

    use super::*;

    impl MiningStatus {
        /// returns time when mining entered this status.
        pub fn since(&self) -> SystemTime {
            match *self {
                Self::Disabled(t) => t,
                Self::Init(t) => t,
                Self::Paused(t, _) => t,
                Self::UnPaused(t) => t,
                Self::AwaitBlockProposal(t) => t,
                Self::AwaitBlock(t, _) => t,
                Self::Composing(t) => t,
                Self::Guessing(t, _) => t,
                Self::NewTipBlock(t) => t,
                Self::ComposeError(t) => t,
                Self::Shutdown(t) => t,
            }
        }

        /// returns a list of reasons why mining is paused.
        /// empty if not paused.
        pub fn paused_reasons(&self) -> &[MiningPausedReason] {
            match self {
                Self::Paused(_, reasons) => reasons,
                _ => &[],
            }
        }
    }

    impl std::fmt::Display for MiningStatus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let input_output_info = match self {
                Self::Guessing(_, info) => {
                    format!(" {}/{}", info.num_inputs, info.num_outputs)
                }
                _ => String::default(),
            };

            let work_type_and_duration = match self {
                Self::Disabled(_) => MiningState::from(self).to_string(),
                Self::Paused(t, reasons) => {
                    format!(
                        "paused for {}  ({})",
                        human_duration_secs(&t.elapsed()),
                        reasons.iter().map(|r| r.description()).join(", ")
                    )
                }
                _ => format!(
                    "{} for {}",
                    MiningState::from(self),
                    human_duration_secs(&self.since().elapsed()),
                ),
            };
            let reward = match self {
                Self::Guessing(_, block_summary) => format!(
                    "; total guesser reward: {}",
                    block_summary.total_guesser_fee
                ),
                _ => String::default(),
            };

            write!(f, "{work_type_and_duration}{input_output_info}{reward}",)
        }
    }

    impl From<&MiningStateData> for MiningStatus {
        fn from(ms: &MiningStateData) -> Self {
            match ms {
                MiningStateData::Disabled(t) => Self::Disabled(*t),
                MiningStateData::Init(t) => Self::Init(*t),
                MiningStateData::Paused(t, r) => Self::Paused(*t, r.clone()),
                MiningStateData::UnPaused(t) => Self::UnPaused(*t),
                MiningStateData::AwaitBlockProposal(t) => Self::AwaitBlockProposal(*t),
                MiningStateData::AwaitBlock(t, p) => Self::AwaitBlock(*t, (&**p).into()),
                MiningStateData::Composing(t) => Self::Composing(*t),
                MiningStateData::Guessing(t, b) => Self::Guessing(*t, (&**b).into()),
                MiningStateData::NewTipBlock(t) => Self::NewTipBlock(*t),
                MiningStateData::ComposeError(t) => Self::ComposeError(*t),
                MiningStateData::Shutdown(t) => Self::Shutdown(*t),
            }
        }
    }

    // formats a duration in human readable form, to seconds precision.
    // eg: 7h 5m 23s
    fn human_duration_secs(
        duration_exact: &Result<Duration, std::time::SystemTimeError>,
    ) -> String {
        // remove sub-second component, so humantime ends with seconds.
        // also set to 0 if any error.
        let duration_to_secs = duration_exact
            .as_ref()
            .map(|v| *v - Duration::from_nanos(v.subsec_nanos().into()))
            .unwrap_or(Duration::ZERO);
        humantime::format_duration(duration_to_secs).to_string()
    }
}

mod mining_paused_reason_impl {
    use super::*;

    impl MiningPausedReason {
        pub fn description(&self) -> &str {
            match self {
                Self::Rpc => "user",
                Self::SyncBlocks => "syncing blocks",
                Self::NeedConnection => "await connections",
            }
        }
    }

    impl std::fmt::Display for MiningPausedReason {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let desc = self.description();
            write!(f, "{}", desc)
        }
    }
}

mod block_summary_impl {
    use super::*;

    impl From<&Block> for BlockSummary {
        fn from(b: &Block) -> Self {
            Self {
                num_inputs: b.body().transaction_kernel.inputs.len(),
                num_outputs: b.body().transaction_kernel.outputs.len(),
                total_coinbase: b.body().transaction_kernel.coinbase.unwrap_or_default(),
                total_guesser_fee: b.body().transaction_kernel.fee,
            }
        }
    }
}
