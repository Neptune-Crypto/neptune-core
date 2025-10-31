# JSON-RPC Client for Neptune Cash

A small async collection of clients for talking to a running **Neptune Cash** node over JSON-RPC.
HTTP client built on top of [`reqwest`](https://docs.rs/reqwest).

--- 

### Example

```rust
use neptune_cash::application::json_rpc::core::api::rpc::RpcApi;
use crate::http::HttpClient;

#[tokio::main]
async fn main() {
    let client = HttpClient::new("http://127.0.0.1:9797");

    // Get current tip (from chain module)
    let tip = client.tip().await.unwrap();
    println!("Current tip: {:?}", tip);
}
```

---

### Tests

The integration test spins up a local Neptune node, connects the HTTP client, and checks real-world RPC behavior.