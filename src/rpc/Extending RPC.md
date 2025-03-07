# Add a new method to RPC

## calls.rs

1. Declare a new response type -- remember big numbers that cannot be safely represented by JavaScript etc. must be a String.
2. Implement a function that returns axum-jsonified version of response type.

## server.rs

1. Register new function to router on ``build_router`` function.
2. Implement a call test over router and check for validity over body.
