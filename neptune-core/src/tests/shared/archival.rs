use crate::protocol::consensus::block::Block;
use crate::state::archival_state::ArchivalState;

/// Set a new block as tip
pub(crate) async fn add_block_to_archival_state(
    archival_state: &mut ArchivalState,
    new_block: Block,
) -> anyhow::Result<()> {
    archival_state.write_block_as_tip(&new_block).await?;

    archival_state.update_mutator_set(&new_block).await.unwrap();

    archival_state
        .append_to_archival_block_mmr(&new_block)
        .await;

    Ok(())
}
