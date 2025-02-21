//! This module implements [MiningStateMachine], a finite-state-machine
//! specific to neptune-core mining.
//!
//! The [MiningStateMachine] has been implemented with the following
//! objectives/reasons:
//!
//! 1. Simplify the complex code in the mining loop so it is
//!    more maintainable.
//!
//! 2. Facilitate a lock-free mining loop, which means less
//!    possibility of delay for miners.
//!
//! 3. Cleanly support granular display of mining-status, so user can
//!    see a message like "waiting for block proposal" rather than
//!    just "inactive".
//!
//! 4. consolidate/unify pause and unpause logic, since pausing
//!    can occur for different reasons.
//!
//! 5. Make the core logic of transitioning between mining states
//!    testable via unit tests.
//!
//!
//! States and events are defined in [super::mining_status].
//!
//! A set of allowed state transitions is defined for each state.
//! I.e. each state can be followed only by certain allowed states.
//!
//! The state-machine basically responds to events and determines
//! what the next state should be. It then verifies that it is allowed
//! to transition from the present state to the next state.
//!
//! If the state transition is not allowed:
//!  a) the event is ignored, or
//!  b) an error is returned.
//!
//! The exact behavior depends on the `strict_state_transitions` setting
//! of [MiningStateMachine].

use itertools::Itertools;

use super::mining_status::MiningEvent;
use super::mining_status::MiningPausedReason;
use super::mining_status::MiningState;
use super::mining_status::MiningStateData;

// Defines the allowed transitions between states.
//
// The order of sub-arrays is important.  Each sub-array is indexed by the
// integer value of the corresponding MiningState variant.  Eg:
//
//  MiningState::Init = 0                 --> index 0.
//  MiningState::AwaitBlockProposal = 1   --> index 1.
//  MiningState::Composing = 2            --> index 2.
//
// Each sub-array contains the set of states that are allowed to occur after the
// indexed state.
//
// The "happy path" represents the expected progression of states during normal
// mining.  see also: state_machine_tests::worker::HAPPY_PATH_STATE_TRANSITIONS
#[rustfmt::skip]
const MINING_STATE_TRANSITIONS: [&[MiningState]; 11] = [

    // ----- start happy path -----

    // MiningState::Init
    &[
        MiningState::AwaitBlockProposal,
        MiningState::NewTipBlock,
        MiningState::Paused,
        MiningState::Shutdown,
    ],

    // MiningState::AwaitBlockProposal
    &[
        MiningState::Composing,
        MiningState::Paused,
        MiningState::Shutdown,
        MiningState::NewTipBlock,
    ],

    // MiningState::Composing
    &[
        MiningState::AwaitBlock,
        MiningState::ComposeError,
        MiningState::Paused,
        MiningState::Shutdown,
        MiningState::NewTipBlock,
    ],

    // MiningState::AwaitBlock
    &[
        MiningState::Guessing,
        MiningState::Paused,
        MiningState::Shutdown,
        MiningState::NewTipBlock,
    ],

    // MiningState::Guessing
    &[
        MiningState::NewTipBlock,
        MiningState::Paused,
        MiningState::Shutdown,
    ],

    // MiningState::NewTipBlock
    &[
        MiningState::Init,
        MiningState::Paused,
        MiningState::Shutdown,
    ],

    // ---- end happy path ----

    // MiningState::ComposeError
    &[
        MiningState::Shutdown
    ],

    // MiningState::Paused
    &[
        MiningState::UnPaused,
        MiningState::Shutdown
    ],

    // MiningState::UnPaused
    &[
        MiningState::Init,
        MiningState::Shutdown
    ],

    // MiningState::Disabled
    &[],


    // MiningState::Shutdown
    &[],
];

/// see module description.
#[derive(Debug, Clone)]
pub(crate) struct MiningStateMachine {
    state_data: MiningStateData, // holds a MiningState.

    paused_while_syncing: bool,
    paused_by_rpc: bool,
    paused_need_connection: bool,

    config: MiningStateMachineConfig,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid state transition from {:?} to {:?}", old_state, new_state)]
pub(crate) struct InvalidStateTransition {
    pub old_state: MiningState,
    pub new_state: MiningState,
}

/// configuration for [MiningStateMachine]
#[derive(Debug, Clone)]
pub(crate) struct MiningStateMachineConfig {
    // should we compose?
    pub role_compose: bool,

    // should we guess?
    pub role_guess: bool,

    // true: return error on invalid state transitions.
    // false: ignore invalid state transitions, return Ok()
    pub strict_state_transitions: bool,
}

impl MiningStateMachine {
    pub fn new(config: MiningStateMachineConfig) -> Self {
        let myself = Self {
            config,
            state_data: MiningStateData::init(),
            paused_while_syncing: false,
            paused_by_rpc: false,
            paused_need_connection: false,
        };
        tracing::debug!("new {:?}", myself);
        myself
    }

    pub fn config(&self) -> &MiningStateMachineConfig {
        &self.config
    }

    pub(crate) fn state_data(&self) -> &MiningStateData {
        &self.state_data
    }

    /// handles a single [MiningEvent].
    pub fn handle_event(&mut self, event: MiningEvent) -> Result<(), InvalidStateTransition> {
        tracing::debug!(
            "handle_event: old_state: {}, event: {}",
            self.state_data.name(),
            event,
        );

        match event {
            MiningEvent::Init => self.advance_with(MiningStateData::init())?,

            MiningEvent::AwaitBlockProposal => {
                self.advance_with(MiningStateData::await_block_proposal())?
            }

            MiningEvent::StartComposing => self.advance_with(MiningStateData::composing())?,

            MiningEvent::StartGuessing if self.state_data.state() == MiningState::AwaitBlock => {
                match &self.state_data {
                    MiningStateData::AwaitBlock(_, proposed_block) => {
                        self.advance_with(MiningStateData::guessing(proposed_block.clone()))?
                    }
                    _ => unreachable!(),
                }
            }
            // out-of-order event.  we can't call
            // advance_with(MiningEventData::guessing(proposed_block)) because
            // we don't have a proposed-block.
            MiningEvent::StartGuessing => {
                if self.config.strict_state_transitions {
                    return Err(InvalidStateTransition {
                        old_state: self.state_data.state(),
                        new_state: MiningState::Guessing,
                    });
                }
            }

            MiningEvent::PauseByRpc => self.pause_by_rpc(),
            MiningEvent::UnPauseByRpc => self.unpause_by_rpc(),

            MiningEvent::PauseBySyncBlocks => self.pause_by_sync_blocks(),
            MiningEvent::UnPauseBySyncBlocks => self.unpause_by_sync_blocks(),

            MiningEvent::PauseByNeedConnection => self.pause_by_need_connection(),
            MiningEvent::UnPauseByNeedConnection => self.unpause_by_need_connection(),

            // if new-block-proposal arrives while we are guessing, then we need
            // to update the existing mining state_data, rather than advance to next
            // state.  (without this special case, if we just advance, it still
            // works, but guessing time resets to time of latest block proposal,
            // instead of when guessing actually started.)
            MiningEvent::NewBlockProposal(proposal)
                if self.state_data.state() == MiningState::Guessing =>
            {
                self.set_state_data(MiningStateData::Guessing(self.state_data.since(), proposal));
            }
            // same as above, but this applies to AwaitBlock
            MiningEvent::NewBlockProposal(proposal)
                if self.state_data.state() == MiningState::AwaitBlock =>
            {
                self.set_state_data(MiningStateData::AwaitBlock(
                    self.state_data.since(),
                    proposal,
                ));
            }
            MiningEvent::NewBlockProposal(proposal) => {
                // guesser skips Composing state.
                if self.config.role_guess
                    && self.state_data.state() == MiningState::AwaitBlockProposal
                {
                    self.advance_with(MiningStateData::composing())?;
                }
                self.advance_with(MiningStateData::await_block(proposal))?;
            }

            MiningEvent::NewTipBlock => self.advance_with(MiningStateData::new_tip_block())?,

            MiningEvent::ComposeError => self.advance_with(MiningStateData::compose_error())?,

            MiningEvent::Shutdown => self.advance_with(MiningStateData::shutdown())?,
        }
        Ok(())
    }

    // advances to input state-data if allowed.
    //
    // returns error if not allowed and in strict_transitions mode.
    // silently ignores input if not allowed and not in strict mode.
    fn advance_with(
        &mut self,
        new_state_data: MiningStateData,
    ) -> Result<(), InvalidStateTransition> {
        tracing::debug!(
            "advance_with: old_state: {}, new_state: {}",
            self.state_data.name(),
            new_state_data.name()
        );

        // special handling for pause.
        if let MiningStateData::Paused(_, ref reasons) = new_state_data {
            assert!(!reasons.is_empty());
            for reason in reasons {
                self.pause(reason)
            }
        } else if self.config.strict_state_transitions {
            self.ensure_allowed(&new_state_data)?;
            self.set_state_data(new_state_data);
        } else if self.allowed(&new_state_data) {
            self.set_state_data(new_state_data);
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn exec_states(
        &mut self,
        states: Vec<MiningStateData>,
    ) -> Result<(), InvalidStateTransition> {
        for state in states {
            self.advance_with(state)?
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn exec_events(
        &mut self,
        events: Vec<MiningEvent>,
    ) -> Result<(), InvalidStateTransition> {
        for event in events {
            self.handle_event(event)?
        }
        Ok(())
    }

    // sets new StateData and logs a debug msg.
    fn set_state_data(&mut self, new_state_data: MiningStateData) {
        self.state_data = new_state_data;
        tracing::debug!("set new state: {}", self.state_data.name());
    }

    // merges two Paused state-data together and sets.
    //   1. keeps timestamp of the original state-data.
    //   2. appends reasons(s) of new state-data to original state-data reasons.
    //   3. ensures reasons are unique.
    //
    // panics if old or new state-data is not Paused.
    fn merge_paused_state_data(&mut self, new_state_data: MiningStateData) -> MiningStateData {
        match (self.state_data.clone(), new_state_data) {
            (
                MiningStateData::Paused(old_time, mut old_reasons),
                MiningStateData::Paused(_, mut new_reasons),
            ) => {
                old_reasons.append(&mut new_reasons);
                // ensure unique
                MiningStateData::Paused(old_time, old_reasons.into_iter().unique().collect())
            }
            (_, MiningStateData::Paused(t, reasons)) => MiningStateData::Paused(t, reasons),
            _ => panic!("attempted to merge MiningStateData other than Paused"),
        }
    }

    fn pause(&mut self, reason: &MiningPausedReason) {
        match reason {
            MiningPausedReason::Rpc => self.pause_by_rpc(),
            MiningPausedReason::SyncBlocks => self.pause_by_sync_blocks(),
            MiningPausedReason::NeedConnection => self.pause_by_need_connection(),
        };
    }

    fn pause_by_need_connection(&mut self) {
        if !self.paused_need_connection {
            let reason = MiningPausedReason::NeedConnection;
            let new_state_data = MiningStateData::paused(reason);
            if self.allowed(&new_state_data) {
                let merged = self.merge_paused_state_data(new_state_data);
                self.set_state_data(merged);
            }
            self.paused_need_connection = true;
        }
    }

    fn unpause_by_need_connection(&mut self) {
        if self.paused_need_connection {
            let _ = self.advance_with(MiningStateData::unpaused());
            let _ = self.advance_with(MiningStateData::init());

            self.paused_need_connection = false;
        }
    }

    fn pause_by_rpc(&mut self) {
        if !self.paused_by_rpc {
            let reason = MiningPausedReason::Rpc;
            let new_state_data = MiningStateData::paused(reason);
            if self.allowed(&new_state_data) {
                let merged = self.merge_paused_state_data(new_state_data);
                self.set_state_data(merged);
            }
            self.paused_by_rpc = true;
        }
    }

    fn unpause_by_rpc(&mut self) {
        if self.paused_by_rpc {
            let _ = self.advance_with(MiningStateData::unpaused());
            let _ = self.advance_with(MiningStateData::init());

            self.paused_by_rpc = false;
        }
    }

    fn pause_by_sync_blocks(&mut self) {
        if !self.paused_while_syncing {
            let reason = MiningPausedReason::SyncBlocks;
            let new_state_data = MiningStateData::paused(reason);
            if self.allowed(&new_state_data) {
                let merged = self.merge_paused_state_data(new_state_data);
                self.set_state_data(merged);
            }
            self.paused_while_syncing = true;
        }
    }

    fn unpause_by_sync_blocks(&mut self) {
        if self.paused_while_syncing {
            let _ = self.advance_with(MiningStateData::unpaused());
            let _ = self.advance_with(MiningStateData::init());

            self.paused_while_syncing = false;
        }
    }

    // check if a given target state-data can be transitioned to or not.
    //
    // the general case is to check if the target state is allowed
    // for the current state in the STATE_TRANSITIONS_TABLE.
    //
    // however some special cases are checked first:
    //   1. Allow Init to be specified when already in Init state.
    //   2. Allow same StateData (no change).
    //   3. Only allow Disabled state if mining not enabled.
    //   4. Only allow Shutdown when we have been paused in more than one way.
    //      (once pause count returns to 1, normal rules apply)
    fn allowed(&self, state_data: &MiningStateData) -> bool {
        let state = state_data.state();

        // we normally don't allow state equality since state-data variant data (eg
        // timestamps) can differ between 2 MiningStateData with same state.
        // We make an exception for Init because otherwise it can't be
        // manually set.
        if state == self.state_data.state() {
            state == MiningState::Init
        } else if *state_data == self.state_data {
            true
        } else if !self.mining_enabled() {
            state == MiningState::Disabled
        } else if self.paused_count() > 1 {
            state == MiningState::Shutdown
        } else {
            // enforce state-transitions defined in MINING_STATE_TRANSITIONS
            let s = state_data.state();
            let allowed_states: &[MiningState] =
                MINING_STATE_TRANSITIONS[self.state_data.state() as usize];
            allowed_states.iter().any(|v| *v == s)
        }
    }

    fn paused_count(&self) -> u8 {
        self.paused_by_rpc as u8
            + self.paused_while_syncing as u8
            + self.paused_need_connection as u8
    }

    fn ensure_allowed(
        &self,
        new_state_data: &MiningStateData,
    ) -> Result<(), InvalidStateTransition> {
        if self.allowed(new_state_data) {
            Ok(())
        } else {
            Err(InvalidStateTransition {
                old_state: self.state_data.state(),
                new_state: new_state_data.state(),
            })
        }
    }

    pub fn mining_enabled(&self) -> bool {
        self.config.role_compose || self.config.role_guess
    }

    pub fn can_start_guessing(&self) -> bool {
        self.config.role_guess && self.state_data.state() == MiningState::AwaitBlock
    }

    pub fn is_guessing(&self) -> bool {
        self.config.role_guess && self.state_data.state() == MiningState::Guessing
    }

    pub fn can_start_composing(&self) -> bool {
        self.config.role_compose && self.state_data.state() == MiningState::AwaitBlockProposal
    }

    pub fn is_composing(&self) -> bool {
        self.config().role_compose && self.state_data.state() == MiningState::Composing
    }
}

#[cfg(test)]
mod state_machine_tests {

    use tracing_test::traced_test;

    use super::*;

    const PAUSE_EVENTS: &[MiningEvent] = &[
        MiningEvent::PauseByNeedConnection,
        MiningEvent::PauseByRpc,
        MiningEvent::PauseBySyncBlocks,
    ];
    const UNPAUSE_EVENTS: &[MiningEvent] = &[
        MiningEvent::UnPauseByNeedConnection,
        MiningEvent::UnPauseByRpc,
        MiningEvent::UnPauseBySyncBlocks,
    ];

    // verifies that machine can progress through all states in the mining happy path.
    // for every combination of machine config
    #[traced_test]
    #[test]
    fn compose_and_guess_happy_path() -> anyhow::Result<()> {
        for mut machine in worker::machine_matrix() {
            let result = machine.exec_states(worker::compose_and_guess_happy_path());

            if !machine.mining_enabled() && machine.config().strict_state_transitions {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok());
            }
        }

        Ok(())
    }

    // verifies that pause event can occur during every state in the mining
    // happy path, for every combination of machine config and pause event
    #[traced_test]
    #[test]
    fn can_pause_all_along_happy_path() -> anyhow::Result<()> {
        // test that all pause events can occur along happy path.
        for (machine, pause_event) in worker::machine_event_matrix(PAUSE_EVENTS) {
            if machine.mining_enabled() {
                worker::can_pause_all_along_happy_path(machine, pause_event.to_owned())?;
            }
        }
        Ok(())
    }

    // verifies that every pause event can occur during every reachable state
    // for every combination of machine config and pause event
    #[traced_test]
    #[test]
    fn can_pause_during_every_state() -> anyhow::Result<()> {
        // test that all pause events can occur during every state
        for (machine, pause_event) in worker::machine_event_matrix(PAUSE_EVENTS) {
            worker::can_pause_during_every_state(machine, pause_event.to_owned())?;
        }
        Ok(())
    }

    // verifies that pause events only cause a mining state change for
    // certain starting states -- for every possible combination of machine
    // config and pause event
    #[traced_test]
    #[test]
    fn pause_changes_only_certain_states() -> anyhow::Result<()> {
        // test that all pause events only change correct states
        for (machine, pause_event) in worker::machine_event_matrix(PAUSE_EVENTS) {
            worker::pause_changes_only_certain_states(machine, pause_event.to_owned())?;
        }
        Ok(())
    }

    // verifies that unpause events only cause a mining state change for
    // certain starting states -- for every combination of machine and
    // pause/unpause event pair.
    #[traced_test]
    #[test]
    fn unpause_changes_only_certain_states() -> anyhow::Result<()> {
        // test that all unpause events only change correct states
        for (machine, pause_event, unpause_event) in
            worker::machine_matched_events_matrix(&worker::all_pause_and_unpause_events())
        {
            worker::unpause_changes_only_certain_states(machine, pause_event, unpause_event)?;
        }
        Ok(())
    }

    // verifies that all pause/unpause events work in any order for any state
    // for every possible machine config.
    #[traced_test]
    #[test]
    fn mixed_pause_unpause_types() -> anyhow::Result<()> {
        for machine in worker::machine_matrix() {
            worker::mixed_pause_unpause_types(machine)?;
        }
        Ok(())
    }

    // executes all events in composer+guesser role happy path and verifies no
    // errors unless the machine is not mining and in strict_state_transitions
    // mode.
    #[traced_test]
    #[test]
    fn events_happy_path() -> anyhow::Result<()> {
        for mut machine in worker::machine_matrix() {
            tracing::debug!("machine config: {:?}", machine.config());
            let result = machine.exec_events(worker::events_happy_path());

            if !machine.mining_enabled() && machine.config().strict_state_transitions {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok());
            }
        }
        Ok(())
    }

    // executes all events in composer role happy path and verifies no errors
    // unless the machine is not mining and in strict_state_transitions mode.
    #[traced_test]
    #[test]
    fn compose_happy_path() -> anyhow::Result<()> {
        for mut machine in worker::machine_matrix() {
            tracing::debug!("machine config: {:?}", machine.config());
            let result = machine.exec_events(worker::events_happy_path());

            if !machine.mining_enabled() && machine.config().strict_state_transitions {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok());
            }
        }
        Ok(())
    }

    // executes all events in guesser role happy path and verifies no errors
    // unless the machine is not mining and in strict_state_transitions mode.
    #[traced_test]
    #[test]
    fn guess_happy_path() -> anyhow::Result<()> {
        for mut machine in worker::machine_matrix() {
            tracing::debug!("machine config: {:?}", machine.config());
            let result = machine.exec_events(worker::events_happy_path());

            if !machine.mining_enabled() && machine.config().strict_state_transitions {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok());
            }
        }
        Ok(())
    }

    #[traced_test]
    #[tokio::test]
    async fn new_block_proposal_replaces_old() -> anyhow::Result<()> {
        for machine in worker::machine_matrix() {
            tracing::debug!("machine config: {:?}", machine.config());
            worker::new_block_proposal_replaces_old(machine).await?;
        }
        Ok(())
    }

    mod worker {
        use std::sync::Arc;

        use rand::rng;
        use rand::seq::SliceRandom;
        use strum::IntoEnumIterator;

        use super::super::super::mining_status::ProposedBlock;
        use super::*;
        use crate::config_models::network::Network;
        use crate::tests::shared::make_mock_block_guesser_preimage_and_guesser_fraction_random;
        use crate::Block;

        #[rustfmt::skip]
        const HAPPY_PATH_STATE_TRANSITIONS: &[MiningState] = &[
            MiningState::Init,
            MiningState::AwaitBlockProposal,
            MiningState::Composing,
            MiningState::AwaitBlock,
            MiningState::Guessing,
            MiningState::NewTipBlock,
        ];

        // returns a list of MiningStateMachine, one for every possible configuration.
        pub fn machine_matrix() -> Vec<MiningStateMachine> {
            let iter_bool = [true, false];
            itertools::iproduct!(iter_bool, iter_bool, iter_bool)
                .map(|(strict_state_transitions, role_compose, role_guess)| {
                    vec![MiningStateMachine::new(MiningStateMachineConfig {
                        strict_state_transitions,
                        role_compose,
                        role_guess,
                    })]
                })
                .flatten()
                .collect()
        }

        // returns a list (matrix) of every possible machine config
        // and every event from input list.
        pub fn machine_event_matrix(
            iter_event: &[MiningEvent],
        ) -> Vec<(MiningStateMachine, MiningEvent)> {
            itertools::iproduct!(machine_matrix(), iter_event)
                .map(|(machine, event)| vec![(machine, event.clone())])
                .flatten()
                .collect()
        }

        // returns a list (matrix) of every possible machine config
        // and every (MiningEvent, MiningEvent) from input list.
        pub fn machine_matched_events_matrix(
            matched_events: &[(MiningEvent, MiningEvent)],
        ) -> Vec<(MiningStateMachine, MiningEvent, MiningEvent)> {
            itertools::iproduct!(machine_matrix(), matched_events)
                .map(|(machine, events)| vec![(machine, events.0.clone(), events.1.clone())])
                .flatten()
                .collect()
        }

        // returns a list of every pause event with its matching unpause event.
        pub fn all_pause_and_unpause_events() -> Vec<(MiningEvent, MiningEvent)> {
            PAUSE_EVENTS
                .iter()
                .cloned()
                .zip(UNPAUSE_EVENTS.iter().cloned())
                .collect()
        }

        // returns all MiningStateData in the happy path for compose+guess role.
        pub(super) fn compose_and_guess_happy_path_states() -> Vec<MiningState> {
            HAPPY_PATH_STATE_TRANSITIONS
                .iter()
                .cycle()
                .take(HAPPY_PATH_STATE_TRANSITIONS.len() + 1)
                .copied()
                .collect_vec()
        }

        pub fn compose_and_guess_happy_path() -> Vec<MiningStateData> {
            compose_and_guess_happy_path_states()
                .into_iter()
                .map(state_to_state_data)
                .collect_vec()
        }

        pub fn state_to_state_data(state: MiningState) -> MiningStateData {
            match state {
                MiningState::AwaitBlock => MiningStateData::await_block(fake_proposed_block()),
                MiningState::Guessing => MiningStateData::guessing(fake_proposed_block()),
                _ => MiningStateData::try_from(state).unwrap(),
            }
        }

        pub(super) async fn new_block_proposal_replaces_old(
            mut machine: MiningStateMachine,
        ) -> anyhow::Result<()> {
            for initial_state in [MiningState::AwaitBlock, MiningState::Guessing] {
                machine.state_data = match initial_state {
                    MiningState::AwaitBlock => MiningStateData::await_block(fake_proposed_block()),
                    MiningState::Guessing => MiningStateData::guessing(fake_proposed_block()),
                    _ => unreachable!(),
                };
                let initial_since = machine.state_data.since();

                // default fraction is 0.5, so 0.75 is different.
                let guesser_fraction = 0.75;

                // generate a new block, as our proposed block
                let (new_block, _) = make_mock_block_guesser_preimage_and_guesser_fraction_random(
                    &fake_proposed_block(),
                    None,
                    guesser_fraction,
                )
                .await;

                let arc_new_block = Arc::new(new_block);

                machine.handle_event(MiningEvent::NewBlockProposal(arc_new_block.clone()))?;

                // verify we are still in initial state.
                assert!(machine.state_data.state() == initial_state);

                // verify state timestamp hasn't changed.
                assert!(machine.state_data.since() == initial_since);

                // verify that the proposed block has been updated in the state data.
                match machine.state_data {
                    MiningStateData::Guessing(_, p) => {
                        assert_eq!(p, arc_new_block);
                    }
                    MiningStateData::AwaitBlock(_, p) => {
                        assert_eq!(p, arc_new_block);
                    }
                    _ => unreachable!(),
                }
            }
            Ok(())
        }

        // verifies that input pause event succeeds without error for every
        // reachable starting-state, for provided machine.
        pub(super) fn can_pause_during_every_state(
            machine_in: MiningStateMachine,
            pause_event: MiningEvent,
        ) -> anyhow::Result<()> {
            // for each state, we make a new state-machine and force it
            // to the target state, then pause it.
            for state_data in all_reachable_state_data(&machine_in) {
                let mut machine = machine_in.clone();
                tracing::debug!(
                    "state: {}, machine config: {:?}",
                    state_data.state(),
                    machine.config()
                );
                machine.state_data = state_data;
                machine.handle_event(pause_event.clone())?;
            }
            Ok(())
        }

        // verifies that pausing only causes mining state to change for
        // selected starting states.
        pub(super) fn pause_changes_only_certain_states(
            machine_in: MiningStateMachine,
            pause_event: MiningEvent,
        ) -> anyhow::Result<()> {
            // for each state, we make a new machine and force it to the target state, then pause it.
            for state_data in all_reachable_state_data(&machine_in) {
                let mut machine = machine_in.clone();
                tracing::debug!(
                    "state: {}, machine config: {:?}",
                    state_data.state(),
                    machine.config()
                );
                machine.state_data = state_data.clone();
                machine.handle_event(pause_event.clone())?;

                let ss = state_data.state();
                let ms = machine.state_data.state();
                let ps = MiningState::Paused;

                // certain states should not switch to Paused state.
                // (although the machine updates the appropiate pause
                // flag internally)

                match ss {
                    MiningState::Init => assert_eq!(ms, ps),
                    MiningState::AwaitBlockProposal => assert_eq!(ms, ps),
                    MiningState::Composing => assert_eq!(ms, ps),
                    MiningState::AwaitBlock => assert_eq!(ms, ps),
                    MiningState::Guessing => assert_eq!(ms, ps),
                    MiningState::NewTipBlock => assert_eq!(ms, ps),
                    MiningState::ComposeError => assert_eq!(ms, ss),
                    MiningState::Paused => assert_eq!(ms, ps),
                    MiningState::UnPaused => assert_eq!(ms, ss),
                    MiningState::Disabled => assert_eq!(ms, ss),
                    MiningState::Shutdown => assert_eq!(ms, ss),
                }
            }
            Ok(())
        }

        // verifies that unpausing only causes mining state to change for
        // selected starting states.
        pub(super) fn unpause_changes_only_certain_states(
            machine_in: MiningStateMachine,
            pause_event: MiningEvent,
            unpause_event: MiningEvent,
        ) -> anyhow::Result<()> {
            // for each state, we make a new state-machine and force it
            // to the target state, then pause and unpause it.
            for state_data in all_reachable_state_data(&machine_in) {
                let mut machine = machine_in.clone();
                tracing::debug!(
                    "state: {}, machine config: {:?}",
                    state_data.state(),
                    machine.config()
                );
                machine.state_data = state_data.clone();
                machine.handle_event(pause_event.clone())?;
                machine.handle_event(unpause_event.clone())?;

                let ss = state_data.state();
                let ms = machine.state_data.state();
                let is = MiningState::Init;

                // certain states should not switch state after UnPause
                // (although the machine updates the appropiate pause
                // flag internally)

                match ss {
                    MiningState::Init => assert_eq!(ms, is),
                    MiningState::AwaitBlockProposal => assert_eq!(ms, is),
                    MiningState::Composing => assert_eq!(ms, is),
                    MiningState::AwaitBlock => assert_eq!(ms, is),
                    MiningState::Guessing => assert_eq!(ms, is),
                    MiningState::NewTipBlock => assert_eq!(ms, is),
                    MiningState::ComposeError => assert_eq!(ms, ss),
                    MiningState::Paused => assert_eq!(ms, is),
                    MiningState::UnPaused => assert_eq!(ms, is),
                    MiningState::Disabled => assert_eq!(ms, ss),
                    MiningState::Shutdown => assert_eq!(ms, ss),
                }
            }
            Ok(())
        }

        // verifies that all pause/unpause events work in any order for any state
        // for a given state machine (config).
        //
        // puts machine into random states and then handles all possible pause and unpause
        // events in random order.
        //
        // verifies that machine's pause flags and count match our own.
        pub(super) fn mixed_pause_unpause_types(
            mut machine: MiningStateMachine,
        ) -> anyhow::Result<()> {
            // for each state, we force machine to the target state, then pause and unpause it.

            let mut paused_by_rpc = false;
            let mut paused_while_syncing = false;
            let mut paused_need_connection = false;

            let mut state_data = all_reachable_state_data(&machine);
            let mut events = all_pause_and_unpause_events()
                .into_iter()
                .flat_map(|(a, b)| [a, b])
                .collect_vec();

            for _ in 0..50 {
                state_data.shuffle(&mut rng());
                events.shuffle(&mut rng());

                // force to this random state_data.  (not allowed by API)
                machine.state_data = state_data.first().cloned().unwrap();

                for event in events.iter() {
                    match *event {
                        MiningEvent::PauseByNeedConnection => paused_need_connection = true,
                        MiningEvent::UnPauseByNeedConnection => paused_need_connection = false,
                        MiningEvent::PauseByRpc => paused_by_rpc = true,
                        MiningEvent::UnPauseByRpc => paused_by_rpc = false,
                        MiningEvent::PauseBySyncBlocks => paused_while_syncing = true,
                        MiningEvent::UnPauseBySyncBlocks => paused_while_syncing = false,
                        _ => {}
                    }
                    machine.handle_event(event.clone())?;
                }
            }

            // verify that machine pause flags match ours.
            assert_eq!(paused_by_rpc, machine.paused_by_rpc);
            assert_eq!(paused_while_syncing, machine.paused_while_syncing);
            assert_eq!(paused_need_connection, machine.paused_need_connection);

            let paused_count =
                paused_by_rpc as u8 + paused_while_syncing as u8 + paused_need_connection as u8;
            assert_eq!(paused_count, machine.paused_count());

            Ok(())
        }

        // returns all state_data variants that can be reached by the input machine.
        fn all_reachable_state_data(machine: &MiningStateMachine) -> Vec<MiningStateData> {
            if machine.mining_enabled() {
                all_enabled_state_data()
            } else {
                vec![MiningStateData::disabled()]
            }
        }

        // returns all state_data, including different pause reasons, that can be reached
        // by a machine with mining enabled. (role_compose or role_guess)
        fn all_enabled_state_data() -> Vec<MiningStateData> {
            MiningState::iter()
                .filter(|s| *s != MiningState::Disabled)
                .flat_map(|state| match state {
                    MiningState::Paused => MiningPausedReason::iter()
                        .map(MiningStateData::paused)
                        .collect_vec(),
                    _ => vec![state_to_state_data(state)],
                })
                .collect()
        }

        // attempts to handle input pause event for every state in the happy path.
        pub(super) fn can_pause_all_along_happy_path(
            machine_in: MiningStateMachine,
            pause_event: MiningEvent,
        ) -> anyhow::Result<()> {
            // for each state_data in happy path, we make a new state-machine and advance it
            // to the target state, then pause it.
            for state_data in compose_and_guess_happy_path() {
                let mut machine = machine_in.clone();
                tracing::debug!(
                    "state: {}, machine config: {:?}",
                    state_data.state(),
                    machine.config()
                );
                advance_init_to_state(&mut machine, state_data.state())?;
                machine.handle_event(pause_event.clone())?;
            }
            Ok(())
        }

        // advances along the happy path from current state (which should be init)
        // to a target state using the ::advance_with() method.
        fn advance_init_to_state(
            machine: &mut MiningStateMachine,
            target: MiningState,
        ) -> anyhow::Result<()> {
            for state_data in compose_and_guess_happy_path() {
                let state = state_data.state();
                machine.advance_with(state_data)?;
                if state == target {
                    break;
                }
            }
            Ok(())
        }

        pub fn fake_proposed_block() -> ProposedBlock {
            Arc::new(Block::genesis(Network::Main))
        }

        // return list of events for composer to advance along happy path
        // from init all the way back to init.
        pub(super) fn events_happy_path() -> Vec<MiningEvent> {
            vec![
                MiningEvent::Init,
                MiningEvent::AwaitBlockProposal,
                MiningEvent::StartComposing,
                MiningEvent::NewBlockProposal(fake_proposed_block()), // Composing   --> AwaitBlock
                MiningEvent::StartGuessing,
                MiningEvent::NewTipBlock,
                MiningEvent::Init,
            ]
        }
    }
}
