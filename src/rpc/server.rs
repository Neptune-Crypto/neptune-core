use crate::models::state::GlobalStateLock;
use crate::rpc::calls;
use axum::{routing::get, Router};

pub(crate) struct Server {
    pub(crate) state: GlobalStateLock,
}

impl Server {
    pub fn new(state: GlobalStateLock) -> Self {
        Self { state }
    }

    pub async fn serve(
        &self,
        listener: tokio::net::TcpListener,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.build_router();
        axum::serve(listener, app).await?;

        Ok(())
    }

    fn build_router(&self) -> Router {
        Router::new()
            .route("/node", get(calls::node_info))
            .route("/network", get(calls::network_info))
            .route("/block/{hash}", get(calls::block_info))
            .with_state(self.state.clone())
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::mock_genesis_global_state;

    use super::Server;

    async fn create_test_server() -> Server {
        let wallet_secret = WalletSecret::new_random();
        let args = cli_args::Args::default();
        let state = mock_genesis_global_state(Network::RegTest, 2, wallet_secret, args).await;

        Server::new(state)
    }

    #[tokio::test]
    async fn test_server_startup() {
        let server = create_test_server().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            server
                .serve(listener)
                .await
                .expect("Server should not panic")
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await; // Give some time for the server to start.

        let is_accessible = tokio::net::TcpStream::connect(addr).await.is_ok();
        assert!(is_accessible, "Server should be accepting connections");

        server_handle.abort();

        let result = server_handle.await;
        assert!(
            matches!(&result, Err(e) if e.is_cancelled()),
            "Server task should be cancelled, but got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_server_routes() {
        let server = create_test_server().await;
        let app = server.build_router();

        let response = app
            .oneshot(Request::builder().uri("/node").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Node info route should return 200"
        );
    }
}
