The **api** module implements a public api layer for neptune-core.

## purpose and goals

This module aims to:

1. simplify and/or enable common tasks.
2. bring the public rust API to parity with the RPC layer.
3. be the layer beneath the RPC layer, so that layer becomes very thin.
4. power integration tests using only `pub` api, in neptune_core/tests
5. be clean and fully documented.
6. be stable and versioned.
7. have complete test coverage.

## for contributors

Please read [these guidelines](README-dev.md).