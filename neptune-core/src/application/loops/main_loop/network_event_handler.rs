use crate::application::loops::main_loop::MainLoopHandler;
use crate::application::loops::main_loop::MutableMainLoopState;
use crate::application::network::channel::NetworkEvent;

impl MainLoopHandler {
    #[allow(
        clippy::unnecessary_wraps,
        reason = "anticipate more complex events, capable of triggering failures"
    )]
    pub(super) async fn handle_network_event(
        &self,
        event: NetworkEvent,
        main_loop_state: &mut MutableMainLoopState,
    ) -> anyhow::Result<()> {
        match event {
            NetworkEvent::PeerConnected {
                peer_id,
                handshake: _,
                address: _,
                loop_handle,
            } => {
                main_loop_state.task_handles.push(loop_handle);

                if let Some(sync_loop) = &main_loop_state.maybe_sync_loop {
                    sync_loop.send_add_peer(peer_id).await;
                }
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                if let Some(sync_loop) = &main_loop_state.maybe_sync_loop {
                    sync_loop.send_remove_peer(peer_id).await;
                }
            }
        }

        Ok(())
    }
}
