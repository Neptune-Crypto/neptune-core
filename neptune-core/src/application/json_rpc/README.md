# How to Add a New RPC Method

Let’s say you want to add a new method called `submit_block`.

## Core

1. **Add a new operation**

   * In `json_rpc::core::api::ops::RpcApiOps`, create a new variant (e.g. `SubmitBlock`).

2. **Create request and response types**

   * In `json_rpc::core::model::message`, define a matching pair of structs:
     `SubmitBlockRequest` and `SubmitBlockResponse`.

3. **Update the RPC API**

   * In `json_rpc::core::api::rpc::RpcApi`, add two async functions:

     ```rust
     async fn submit_block(
         &self,
         block: RpcBlock,
     ) -> RpcResult<SubmitBlockResponse>;

     async fn submit_block_call(
         &self,
         request: SubmitBlockRequest
     ) -> RpcResult<SubmitBlockResponse>;
     ```
   * The first function should just call the second one.

---

## Server

1. **Implement the `_call` method**

   * In `json_rpc::server::service::RpcApi`, implement the function with the `_call` suffix.

2. **Write a test**

   * Add a test for your new method using the mock service helpers.
