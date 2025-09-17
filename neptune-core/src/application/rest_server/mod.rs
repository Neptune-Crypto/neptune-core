use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum_extra::response::ErasedJson;
use block_selector::BlockSelectorExtended;
use bytes::Buf;
use get_size2::GetSize;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::prelude::MerkleTree;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::*;

use crate::api::export::AdditionRecord;
use crate::application::rpc::server::NeptuneRPCServer;
use crate::protocol::consensus::block::block_height::BlockHeight;
use crate::protocol::consensus::block::block_info::BlockInfo;
use crate::protocol::consensus::block::block_kernel::BlockKernel;
use crate::protocol::consensus::block::block_selector::BlockSelector;
use crate::protocol::consensus::block::mutator_set_update::MutatorSetUpdate;
use crate::protocol::consensus::block::BlockProof;
use crate::protocol::consensus::transaction::Transaction;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::state::mempool::upgrade_priority::UpgradePriority;
use crate::twenty_first::prelude::BFieldCodec;
use crate::util_types::mutator_set::archival_mutator_set::MsMembershipProofEx;
use crate::util_types::mutator_set::archival_mutator_set::RequestMsMembershipProofEx;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::removal_record_list::RemovalRecordList;
use crate::Block;
use crate::RPCServerToMain;

/// An enum of error handlers for the REST API server.
#[derive(Debug)]
pub struct RestError(pub String);

impl IntoResponse for RestError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl From<anyhow::Error> for RestError {
    fn from(err: anyhow::Error) -> Self {
        Self(err.to_string())
    }
}

/// Allow caller to get the block hash without a valid proof to save bandwidth
/// and space in the application.
#[derive(Deserialize)]
struct BlockQuery {
    include_proof: bool,
}

/// Data structure for sharing a block with an external program.
///
/// If the `proof` value is not the actual proof of the block, the `proof_leaf`
/// value can be used to recalculate the block hash.
#[derive(Debug, Clone, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct ExportedBlock {
    pub kernel: BlockKernel,
    pub proof: BlockProof,
    pub proof_leaf: Digest,

    // this is only here as an optimization for Block::hash()
    // so that we lazily compute the hash at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[get_size(ignore)]
    digest: OnceLock<Digest>,
}

impl ExportedBlock {
    pub fn from_block(block: Block, include_proof: bool) -> Self {
        let (kernel, proof) = block.into_kernel_and_proof();
        let proof_leaf = Tip5::hash_varlen(&proof.encode());
        let proof = if include_proof {
            proof
        } else {
            BlockProof::Invalid
        };
        Self {
            proof_leaf,
            digest: OnceLock::default(),
            kernel,
            proof,
        }
    }

    /// Calculate the block hash without assuming that the proof is valid.
    fn mast_hash(&self) -> Digest {
        let block_header_leaf = Tip5::hash_varlen(&self.kernel.header.mast_hash().encode());
        let body_leaf = Tip5::hash_varlen(&self.kernel.body.mast_hash().encode());
        let appendix_leaf = Tip5::hash_varlen(&self.kernel.appendix.encode());
        let kernel_leafs = [
            block_header_leaf,
            body_leaf,
            appendix_leaf,
            Digest::default(),
        ];
        let kernel_hash = MerkleTree::sequential_frugal_root(&kernel_leafs).unwrap();
        let block_leafs = [Tip5::hash_varlen(&kernel_hash.encode()), self.proof_leaf];

        MerkleTree::sequential_frugal_root(&block_leafs).unwrap()
    }

    fn guesser_fee_addition_records(&self) -> Vec<AdditionRecord> {
        let block_hash = self.hash();
        self.kernel
            .guesser_fee_addition_records(block_hash)
            .expect("Exported blocks are assumed valid")
    }

    /// Return the mutator set as it looks after the application of this block.
    ///
    /// Includes the guesser-fee UTXOs which are not included by the
    /// `mutator_set_accumulator` field on the block body.
    pub fn mutator_set_accumulator_after(&self) -> MutatorSetAccumulator {
        let guesser_fee_addition_records = self.guesser_fee_addition_records();
        let msa = self
            .kernel
            .body
            .mutator_set_accumulator_after(guesser_fee_addition_records);

        msa
    }

    pub fn mutator_set_update(&self) -> MutatorSetUpdate {
        let inputs =
            RemovalRecordList::try_unpack(self.kernel.body.transaction_kernel.inputs.clone())
                .expect(
                    "Exported blocks are assumed valid, so removal record list unpacking must work",
                );

        let mut mutator_set_update =
            MutatorSetUpdate::new(inputs, self.kernel.body.transaction_kernel.outputs.clone());

        let guesser_addition_records = self.guesser_fee_addition_records();
        mutator_set_update
            .additions
            .extend(guesser_addition_records);

        mutator_set_update
    }

    /// Calculate the block hash without reading the proof, meaning that the
    /// block hash can be calculated without the exported block containing a
    /// valid proof.
    #[inline]
    pub fn hash(&self) -> Digest {
        *self.digest.get_or_init(|| self.mast_hash())
    }
}

pub(crate) async fn run_rpc_server(
    rest_listener: TcpListener,
    rpcstate: NeptuneRPCServer,
) -> Result<(), anyhow::Error> {
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    let router = {
        let routes = axum::Router::new()
            .route(
                "/rpc/block/{*block_selector}",
                axum::routing::get(get_block),
            )
            .route(
                "/rpc/batch_block/{height}/{batch_size}",
                axum::routing::get(get_batch_block),
            )
            .route(
                "/rpc/block_info/{*block_selector}",
                axum::routing::get(get_block_info),
            )
            .route(
                "/rpc/broadcast_tx",
                axum::routing::post(broadcast_transaction),
            )
            .route(
                "/rpc/generate_membership_proof",
                axum::routing::post(generate_restore_membership_proof),
            );

        routes
            // Pass in `Rest` to make things convenient.
            .with_state(rpcstate)
            // Enable tower-http tracing.
            .layer(TraceLayer::new_for_http())
            .layer(DefaultBodyLimit::disable())
            // .layer(RequestBodyLimitLayer::new(200 * 1000 * 1000))
            // Enable CORS.
            .layer(cors)
    };

    axum::serve(
        rest_listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn get_block(
    State(rpcstate): State<NeptuneRPCServer>,
    Path(block_selector): Path<BlockSelectorExtended>,
    Query(params): Query<BlockQuery>,
) -> Result<ErasedJson, RestError> {
    let block_selector = BlockSelector::from(block_selector);
    let state = rpcstate.state.lock_guard().await;
    let Some(digest) = block_selector.as_digest(&state).await else {
        return Ok(ErasedJson::pretty(Option::<BlockKernel>::None));
    };
    let archival_state = state.chain.archival_state();
    let Some(block) = archival_state.get_block(digest).await? else {
        return Ok(ErasedJson::pretty(Option::<BlockKernel>::None));
    };

    let ret = ExportedBlock::from_block(block, params.include_proof);

    Ok(ErasedJson::pretty(ret))
}

async fn get_batch_block(
    State(rpcstate): State<NeptuneRPCServer>,
    Path((height, batch_size)): Path<(u64, u64)>,
    Query(params): Query<BlockQuery>,
) -> Result<Vec<u8>, RestError> {
    let mut blocks = Vec::with_capacity(batch_size as usize);
    for cur_height in height..height + batch_size {
        let block_selector = BlockSelector::Height(cur_height.into());
        let state = rpcstate.state.lock_guard().await;
        let Some(digest) = block_selector.as_digest(&state).await else {
            break;
        };
        let archival_state = state.chain.archival_state();
        let Some(block) = archival_state.get_block(digest).await? else {
            break;
        };

        let block = ExportedBlock::from_block(block, params.include_proof);
        blocks.push(block);
    }

    bincode::serialize(&blocks).map_err(|e| RestError(e.to_string()))
}

async fn get_block_info(
    State(rpcstate): State<NeptuneRPCServer>,
    Path(block_selector): Path<BlockSelectorExtended>,
) -> Result<ErasedJson, RestError> {
    let block_selector = BlockSelector::from(block_selector);
    let state = rpcstate.state.lock_guard().await;
    let Some(digest) = block_selector.as_digest(&state).await else {
        return Ok(ErasedJson::pretty(Option::<BlockInfo>::None));
    };
    let tip_digest = state.chain.light_state().hash();
    let archival_state = state.chain.archival_state();

    let Some(block) = archival_state
        .get_block(digest)
        .await
        .context("Failed to get block")?
    else {
        return Ok(ErasedJson::pretty(Option::<BlockInfo>::None));
    };
    let is_canonical = archival_state
        .block_belongs_to_canonical_chain(digest)
        .await;

    // sibling blocks are those at the same height, with different digest
    let sibling_blocks = archival_state
        .block_height_to_block_digests(block.header().height)
        .await
        .into_iter()
        .filter(|d| *d != digest)
        .collect();

    let block_info = BlockInfo::new(
        &block,
        archival_state.genesis_block().hash(),
        tip_digest,
        sibling_blocks,
        is_canonical,
    );

    Ok(ErasedJson::pretty(block_info))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMsMembershipProofEx {
    pub height: BlockHeight,
    pub block_id: Digest,
    pub proofs: Vec<MsMembershipProofEx>,
}

async fn generate_restore_membership_proof(
    State(rpcstate): State<NeptuneRPCServer>,
    body: axum::body::Bytes,
) -> Result<Vec<u8>, RestError> {
    let r_datas: Vec<RequestMsMembershipProofEx> =
        bincode::deserialize_from(body.reader()).context("deserialize error")?;
    let state = rpcstate.state.lock_guard().await;

    let ams = state.chain.archival_state().archival_mutator_set.ams();

    let mut proofs = Vec::with_capacity(r_datas.len());
    for r_data in r_datas {
        if let Ok(p) = ams.restore_membership_proof_ex(r_data).await {
            proofs.push(p);
        }
    }

    let cur_block = state.chain.archival_state().get_tip().await;

    let height = cur_block.header().height;
    let block_id = cur_block.hash();

    let response = ResponseMsMembershipProofEx {
        height,
        block_id,
        proofs,
    };
    bincode::serialize(&response).map_err(|e| RestError(e.to_string()))
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BroadcastTx {
    pub(crate) transaction: Transaction,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResponseBroadcastTx {
    pub(crate) status: u64,
    pub(crate) message: String,
}
async fn broadcast_transaction(
    State(mut rpcstate): State<NeptuneRPCServer>,
    body: axum::body::Bytes,
) -> Result<ErasedJson, RestError> {
    let tx: BroadcastTx = bincode::deserialize_from(body.reader()).context("deserialize error")?;

    info!(
        "broadcasted insert tx: {}",
        tx.transaction.kernel.txid().to_string()
    );
    let mut state = rpcstate.state.lock_guard_mut().await;

    state
        .mempool_insert(tx.transaction.clone(), UpgradePriority::Critical)
        .await;
    let _ = rpcstate
        .rpc_server_to_main_tx
        .send(RPCServerToMain::BroadcastTx(Arc::new(tx.transaction)))
        .await;
    Ok(ErasedJson::pretty(ResponseBroadcastTx {
        status: 0,
        message: "Transaction broadcasted".to_string(),
    }))
}

// #[derive(Debug, Deserialize, Serialize, Clone)]
// struct SendTx {
//     broadcast_tx: BroadcastTx,
//     amount: String,
//     sender_randomness: String,
//     fee_address: String,
//     block_height: u64,
// }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResponseSendTx {
    pub(crate) status: u64,
    pub(crate) message: String,
}

mod block_selector {
    use std::str::FromStr;

    use height_or_digest::HeightOrDigest;
    use serde::de::Error;
    use serde::Deserialize;
    use serde::Deserializer;

    use crate::protocol::consensus::block::block_selector::BlockSelector;
    use crate::protocol::consensus::block::block_selector::BlockSelectorParseError;

    /// newtype for `BlockSelector` that provides ability to parse `height_or_digest/value`.
    ///
    /// This is useful for HTML form(s) that allow user to enter either height or
    /// digest into the same text input field.
    ///
    /// In particular it is necessary to support javascript-free website with such
    /// an html form.
    #[derive(Debug, Clone, Copy)]
    pub struct BlockSelectorExtended(BlockSelector);

    impl std::fmt::Display for BlockSelectorExtended {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl FromStr for BlockSelectorExtended {
        type Err = BlockSelectorParseError;

        // note: this parses BlockSelector, plus height_or_digest/<value>
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match BlockSelector::from_str(s) {
                Ok(bs) => Ok(Self::from(bs)),
                Err(e) => {
                    let parts: Vec<_> = s.split('/').collect();
                    if parts.len() == 2 && parts[0] == "height_or_digest" {
                        Ok(Self::from(HeightOrDigest::from_str(parts[1])?))
                    } else {
                        Err(e)
                    }
                }
            }
        }
    }

    // note: axum uses serde Deserialize for Path elements.
    impl<'de> Deserialize<'de> for BlockSelectorExtended {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(D::Error::custom)
        }
    }

    impl From<HeightOrDigest> for BlockSelectorExtended {
        fn from(hd: HeightOrDigest) -> Self {
            Self(hd.into())
        }
    }

    impl From<BlockSelector> for BlockSelectorExtended {
        fn from(v: BlockSelector) -> Self {
            Self(v)
        }
    }

    impl From<BlockSelectorExtended> for BlockSelector {
        fn from(v: BlockSelectorExtended) -> Self {
            v.0
        }
    }

    mod height_or_digest {
        use std::str::FromStr;

        use serde::Deserialize;
        use serde::Serialize;

        use crate::prelude::tasm_lib::prelude::Digest;
        use crate::protocol::consensus::block::block_height::BlockHeight;
        use crate::protocol::consensus::block::block_selector::BlockSelector;
        use crate::protocol::consensus::block::block_selector::BlockSelectorParseError;

        /// represents either a block-height or a block digest
        #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
        pub enum HeightOrDigest {
            /// Identifies block by Digest (hash)
            Digest(Digest),
            /// Identifies block by Height (count from genesis)
            Height(BlockHeight),
        }

        impl std::fmt::Display for HeightOrDigest {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Digest(d) => write!(f, "{}", d),
                    Self::Height(h) => write!(f, "{}", h),
                }
            }
        }

        impl FromStr for HeightOrDigest {
            type Err = BlockSelectorParseError;

            // note: this parses the output of impl Display for HeightOrDigest
            // note: this is used by clap parser in neptune-cli for block-info command
            //       and probably future commands as well.
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s.parse::<u64>() {
                    Ok(h) => Self::Height(h.into()),
                    Err(_) => Self::Digest(Digest::try_from_hex(s)?),
                })
            }
        }

        impl From<HeightOrDigest> for BlockSelector {
            fn from(hd: HeightOrDigest) -> Self {
                match hd {
                    HeightOrDigest::Height(h) => Self::Height(h),
                    HeightOrDigest::Digest(d) => Self::Digest(d),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::export::Network;
    use crate::tests::shared::blocks::invalid_empty_block_with_proof_size;

    #[test]
    fn exported_block_hash_calculation_is_consistent() {
        let network = Network::Main;

        // Set proof-size to none-zero to ensure that proof is accounted
        // correctly for in the block hash.
        let proof_size = 533;
        let block =
            invalid_empty_block_with_proof_size(&Block::genesis(network), network, proof_size);
        let as_exported_block_with_proof = ExportedBlock::from_block(block.clone(), true);
        let as_exported_block_without_proof = ExportedBlock::from_block(block.clone(), true);

        assert_eq!(block.hash(), as_exported_block_with_proof.hash());
        assert_eq!(block.hash(), as_exported_block_without_proof.hash());
    }
}
