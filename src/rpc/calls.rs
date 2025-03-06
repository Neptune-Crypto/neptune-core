use crate::{
    models::{
        blockchain::block::difficulty_control::{Difficulty, ProofOfWork},
        state::GlobalStateLock,
    },
    VERSION,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use tasm_lib::prelude::Digest;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    version: String,
    peer_count: usize,
    syncing: bool,
    mempool_size: usize,
    archival: bool,
}

pub async fn node_info(State(state): State<GlobalStateLock>) -> Json<NodeInfo> {
    let state = state.lock_guard().await;

    let peer_count = state.net.peer_map.len();
    let syncing = state.net.sync_anchor.is_some();
    let mempool_size = state.mempool.len();
    let archival = state.chain.is_archival_node();

    Json(NodeInfo {
        version: VERSION.to_string(),
        peer_count,
        syncing,
        mempool_size,
        archival,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    network: String,
    tip_hash: String,
    height: u64,
    difficulty: Difficulty,
}

pub async fn network_info(State(state): State<GlobalStateLock>) -> Json<NetworkInfo> {
    let cli = state.cli();
    let state = state.lock_guard().await;
    let tip = state.chain.light_state();

    Json(NetworkInfo {
        network: cli.network.to_string(),
        tip_hash: tip.hash().to_hex(),
        height: tip.header().height.into(),
        difficulty: tip.header().difficulty,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockInfo {
    hash: String,
    previous_hash: String,
    height: u64,
    timestamp: u64,
    difficulty: Difficulty,
    cumulative_work: ProofOfWork,
    coinbase_reward: String,
    canonical: bool,
}

pub async fn block_info(
    Path(hash): Path<String>,
    State(state): State<GlobalStateLock>,
) -> Result<Json<BlockInfo>, StatusCode> {
    let state = state.lock_guard().await;
    let archival_state = state.chain.archival_state();

    let digest = if let Ok(digest) = Digest::try_from_hex(&hash) {
        digest
    } else {
        let block_height: u64 = hash.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
        let digests = archival_state
            .block_height_to_block_digests(block_height.into())
            .await;
        digests.first().cloned().ok_or(StatusCode::NOT_FOUND)?
    };

    let block = archival_state
        .get_block(digest)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let header = block.header();
    let is_canonical = archival_state
        .block_belongs_to_canonical_chain(digest)
        .await;

    Ok(Json(BlockInfo {
        hash: block.hash().to_hex(),
        previous_hash: header.prev_block_digest.to_hex(),
        height: header.height.into(),
        timestamp: header.timestamp.0.value(),
        difficulty: header.difficulty,
        cumulative_work: header.cumulative_proof_of_work,
        coinbase_reward: block.coinbase_amount().to_nau().to_string(),
        canonical: is_canonical,
    }))
}
