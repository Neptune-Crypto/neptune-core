# RPC
`neptune-core` provides an RPC server and client based on [tarpc](https://docs.rs/crate/tarpc) with [serde_json](https://docs.rs/crate/serde_json) transport. The RPC server provides a set of methods that allow clients to query the state of the node, submit transactions, and interact with the blockchain.

As we use [tarpc](https://docs.rs/crate/tarpc/latest), it is easier to build a client in Rust. However, it is also possible to build a client in other languages that support JSON.

The RPC server listens on the address specified by the `rpc-port` configuration option. The default address is `9799`.

## Authentication 
`neptune-core` currently initially cookie-based authentication. The RPC server provides a `cookie-hint` method that allows clients to locate the data-directory in a zero configuration way. If this method fails, the client should fall-back to the default data-directory location.  

Operators can disable `cookie-hint` API by using `--disable-cookie-hint` flag when starting the node.

## Versioning 
Currently, `neptune-core` RPC server is on version `1.0` of the RPC server. This version is hardcoded in the RPC server and client. The version number will increment if there are breaking changes to the RPC server.

## Security 

The RPC server allows other programs to interact with a `neptune-core` node including submitting transactions and querying the state of the node. This section suggests some best practices for securing the RPC server.

- Securing the executable : Since the RPC server runs on the same executable as `neptune-core` it is important to secure the executable to prevent unauthorized access. This can be done by setting the appropriate permissions on the executable and using a secure operating system.

- Securing local access : By default, the RPC interface is accessible only to clients running on the same machine, and only when they provide a valid authentication cookie. Securing local access to the RPC server is crucial to prevent unauthorized use. Any program on your computer with access to the file system or local network could potentially gain this level of access. Additionally, other programs on your system might attempt to mimic an RPC interface on the same port as the node, potentially tricking you into disclosing your authentication credentials. Therefore, it is essential to use `neptune-core` for security-sensitive operations only on a computer where you trust all other installed programs.

- Securing remote network access: You can choose to let other computers remotely control `neptune-core` by configuring the `listen-addr` and `rpc-port` settings. These options are intended for use within secure private networks or connections that have been properly secured (e.g., via VPN, SSH port forwarding, or stunnel). **Avoid enabling RPC connections over the public Internet**. While `neptune-core`'s RPC interface includes authentication, it lacks encryption, meaning your login credentials are transmitted in plain text and could be intercepted by anyone on your network path. Furthermore, the RPC interface is not designed to handle arbitrary Internet traffic securely. Exposing it to the Internet—even through methods like a Tor onion service—could leave you vulnerable to unforeseen risks.

## RPC Methods

The RPC server provides several methods that allow clients to interact with the node. The list of methods and examples are provided on the [`neptune-cash` crate documentation](https://docs.rs/neptune-cash/latest/neptune_cash/server/trait.RPC.html).

## RPC consistency guarantees
State that can be queried via RPCs is guaranteed to be at least up-to-date with the chain state immediately prior to the call's execution.

## Transaction Pool
The mempool state returned via an RPC is consistent with itself and with the chain state at the time of the call. Thus, the mempool state only encompasses transactions that are considered mine-able by the node at the time of the RPC.

The mempool state returned via an RPC reflects all effects of mempool and chain state related RPCs that returned prior to this call.
