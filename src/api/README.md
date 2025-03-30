The **api** module implements a public api layer for neptune-core.

## purpose and goals

This module aims to:

1. bring the public rust API to parity with the RPC layer.
2. be the layer beneath the RPC layer, so that layer becomes very thin.
3. power integration tests using only `pub` api, in neptune_core/tests
4. be clean and fully documented.
5. be stable and versioned.
6. have complete test coverage.

It has its own conventions and rules, detailed below.
Please read before making any modifications.

## module owner

this module has a module owner that enforces the rules and oversees things remain in a cohesive state, conventions are followed, etc.

It is intentional that submitting a PR to this module may incur more
rigorous scrutiny than other areas, and that this module will change
more slowly than internal areas of the codebase.

the present module owner is github user: dan-da

## rules:

1. no direct commits to master that touch this layer.

   exception: minor changes that do not modify public interface.

2. all pull-requests must be approved by module owner before merging.

3. no unwrap(), expect(), or panic!() in this layer.

4. make real error types, using thiserror.

5. anyhow not allowed in returned errors.

6. all public types and methods must be documented.
   do not submit PR until this is true.

7. no unit tests. all tests are integration tests instead. this forces usage of public API only. eat your own dog food.

8. each new type or method must have an integration test that
   exercises it.


## conventions and recommendations

1. prefer methods over standalone functions.

2. prefer Result over Option.

3. use a worker type for each public type, so that public types have single statement methods.

4. keep methods as short as possible, even private methods.  If the
method starts getting long, maybe it doesn't belong in this layer.  Or find a way to break it up.

5. provide example usage in doc-comments for public methods and types.

## api versioning and stability

to be written.  suggestions welcome.

# integration test coverage

to be written. suggestions welcome.
