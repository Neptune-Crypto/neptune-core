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

It has its own conventions and rules, detailed below.
Please read before making any modifications.

## module owner

this module has a module owner that enforces the rules and oversees things remain in a cohesive state, conventions are followed, etc.

It is intentional that submitting a PR to this module may incur more
rigorous scrutiny than other areas, and that this module will change
more slowly than internal areas of the codebase.

The module-owner can be changed by a vote of the core team members
or if the module-owner resigns.

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

1. long doc-comments, short methods.

2. prefer methods over standalone functions.

3. prefer Result over Option.

4. consider accepting StateLock if writing multiple types or methods that caller could/should call with a shared lock. eg see the builder types in tx_initiator.

5. use a worker type for each public type, so that public types have single statement methods.

6. keep methods as short as possible, even private methods.  If the
method starts getting long, find a way to break it up, or maybe it doesn't belong in this layer.

7. provide example usage in doc-comments for public methods and types.

## api versioning and stability

to be written.  suggestions welcome.

# integration test coverage

We can use tarpaulin for a code coverage report.

install:

```
cargo install cargo-tarpaulin
```

obtain basic report:

```
cargo tarpaulin --package api crate::tests

```

obtain html report:

```
cargo tarpaulin --package api --out Html crate::tests
```

more to be written. suggestions welcome.
