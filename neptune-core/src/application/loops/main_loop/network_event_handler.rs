use crate::application::loops::main_loop::MainLoopHandler;
use crate::application::loops::main_loop::MutableMainLoopState;
use crate::application::network::channel::NetworkEvent;

impl MainLoopHandler {
    #[allow(
        clippy::unnecessary_wraps,
        reason = "anticipate more complex events, capable of triggering failures"
    )]
    pub(super) fn handle_network_event(
        &self,
        event: NetworkEvent,
        main_loop_state: &mut MutableMainLoopState,
    ) -> anyhow::Result<()> {
        match event {
            NetworkEvent::NewPeerLoop { loop_handle } => {
                main_loop_state.task_handles.push(loop_handle);
            }
        }

        Ok(())
    }
}
