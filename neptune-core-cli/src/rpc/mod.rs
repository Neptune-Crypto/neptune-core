//! RPC server module for neptune-cli
//!
//! This module provides HTTP JSON-RPC server functionality that exposes
//! neptune-cli methods via a REST API. It follows DRY and KISS principles
//! with clear separation of concerns.

pub mod handlers;
pub mod server;

use anyhow::Result;
use std::path::PathBuf;

/// RPC server configuration
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Port to bind the RPC server to
    pub port: u16,
    /// Data directory for cookie storage
    pub data_dir: PathBuf,
    /// Whether to use shared cookie with neptune-core
    pub _use_shared_cookie: bool,
}

impl RpcConfig {
    /// Create new RPC configuration
    pub fn new(port: u16, data_dir: PathBuf) -> Self {
        Self {
            port,
            data_dir,
            _use_shared_cookie: true, // Default to shared cookie
        }
    }
}

/// Start the RPC server
pub async fn start_rpc_server(config: RpcConfig) -> Result<()> {
    server::start(config).await
}
