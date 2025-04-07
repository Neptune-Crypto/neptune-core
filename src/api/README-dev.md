# For developers

This API module has its own conventions and rules, detailed below.
Please read before making any modifications.

## rpc layer integration

goals:

1. provide a method for each rpc endpoint to wrap.
2. provide a path towards adding another rpc mechanism, or switching entirely.

non-goal:  exactly mirror the rpc endpoints.

in particular:

1. we do not need to be a single monolithic type, like the RPCServer type.  we
   should and do group methods into modules by functional area.
2. methods do not need to be exactly the same as the rpc endpoints.  We may have
   additional types, methods, and parameters where it makes sense to do so.

## module owner

this module has a module owner that enforces the rules and oversees things
remain in a cohesive state, conventions are followed, etc.

as a public-facing module, it is intentional that submitting a PR to this module
may incur more rigorous scrutiny than other areas, and that this module will
change more slowly than internal areas of the codebase.

The module-owner can be changed by a vote of the core team members
or if the module-owner resigns.

the present module owner is github user: dan-da

## rules:

1. no direct commits to master that touch this layer.

   exception: minor changes that do not modify public interface.

2. all pull-requests must be approved by module owner before merging.

3. no unwrap(), expect(), or panic!() in this layer.

4. make real error types, using thiserror.

5. anyhow::Error not allowed in returned errors.

6. all public types and methods must be documented.
   please do not submit PR until this is true.

7. no unit tests. all tests are integration tests instead. this forces usage of
public API only. eat your own dog food. it also helps keep the source files
smaller.

8. each new type or method must have an integration test that
   exercises it.


## conventions and recommendations

1. long doc-comments, short methods.

2. prefer methods over standalone functions.

3. prefer Result over Option.

4. consider accepting StateLock if writing multiple types or methods that one
   could/should call with a shared lock. eg see the builder types in
   tx_initiator, and the Wallet type.

5. use a private worker type for each public type, so that public types have
   short, ideally single statement methods.

6. keep methods as short as possible, even private methods.  If the method
starts getting long, find a way to break it up, or maybe it doesn't belong in
this layer.

7. provide example usage in doc-comments for public methods and types.

## api versioning and stability

to be written.  suggestions welcome.

# integration test coverage

to be written. suggestions welcome.

note: I tried tarpaulin but it has problems with the first integration test.
grcov may be our best option but is more complex to use.
