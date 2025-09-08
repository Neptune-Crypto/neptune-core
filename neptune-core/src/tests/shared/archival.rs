use crate::protocol::consensus::block::Block;
use crate::state::archival_state::ArchivalState;
use crate::state::database::PeerDatabases;

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

/// Return an archival state populated with the genesis block
pub(crate) async fn mock_genesis_archival_state(
    network: crate::api::export::Network,
) -> (
    ArchivalState,
    PeerDatabases,
    crate::application::config::data_directory::DataDirectory,
) {
    let data_dir = super::files::unit_test_data_directory(network).unwrap();

    let genesis = Block::genesis(network);
    let archival_state = ArchivalState::new(data_dir.clone(), genesis, network).await;
    let peer_db =
        crate::state::networking_state::NetworkingState::initialize_peer_databases(&data_dir)
            .await
            .unwrap();

    (archival_state, peer_db, data_dir)
}
