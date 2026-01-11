# How to Add a New RPC Method

Let’s say you want to add a new method called `submit_block`.

## Core

1. **Add a new operation**

   * In `json_rpc::core::api::ops::RpcMethods`, create a new variant (e.g. `SubmitBlock`).

2. **Create request and response types**

   * In `json_rpc::core::model::message`, define a matching pair of structs:
     `SubmitBlockRequest` and `SubmitBlockResponse`. Note that the `Request` must derive
     `Serialize_tuple, Deserialize_tuple` whereas the `Response` must derive `Serialize, Deserialize`.

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

## Special Case for Accessors

If the method you are implementing is an *accessor*, meaning the request is empty (because all data is contained in the
(static) path) and the server does little more than read state and return it, then simplify the API as follows.

 - Drop the `Get` prefix from the variant in `RpcMethods`.
 - Drop the `Get` prefix from the response an request types.
 - In `RpcApi`, declare a new method right above the one you just declared. The new one drops the suffix `_call` and
   drops the argument. The default implementation of this new method generates a request object (which should be trivial
   because it is an accessor) and calls its `_call` sibling.
