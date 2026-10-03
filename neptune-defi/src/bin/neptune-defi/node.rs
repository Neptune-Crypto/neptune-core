//! The command line of the `neptune-core` process that `neptune-defi` spawns.

use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;

/// The flags `neptune-defi` sets on `neptune-core` itself, so that the user
/// may not.
pub(crate) const FIXED_FLAGS: [&str; 5] = [
    "--block-notify",
    "--tx-notify",
    "--proposal-notify",
    "--rpc-modules",
    "--unsafe-rpc",
];

/// The JSON-RPC namespaces plugins read and write through.
const RPC_MODULES: &str = "node,chain,mempool,mining,wallet,personal";

/// The address `neptune-core` serves JSON-RPC on when `--listen-rpc` is given
/// without one. `neptune-defi` uses it as well when the flag is absent.
const DEFAULT_LISTEN_RPC: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9797);

/// Why `neptune-defi` cannot run with the arguments the user passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArgsError {
    /// A flag that `neptune-defi` sets itself.
    FixedFlag(&'static str),

    /// A `--listen-rpc` value that is not a socket address.
    InvalidListenRpc(String),
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedFlag(flag) => write!(
                f,
                "neptune-defi sets {flag} on neptune-core itself, so it cannot be \
                 passed. Every other neptune-core flag is passed through unchanged."
            ),
            Self::InvalidListenRpc(value) => write!(
                f,
                "--listen-rpc takes a socket address such as {DEFAULT_LISTEN_RPC}, \
                 not {value:?}."
            ),
        }
    }
}

/// How `neptune-defi` runs `neptune-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeCommand {
    /// The arguments `neptune-core` is spawned with.
    pub(crate) args: Vec<String>,

    /// Where `neptune-core` serves JSON-RPC, which is where plugins reach it.
    pub(crate) rpc_address: SocketAddr,
}

/// How to run `neptune-core`, given the arguments the user passed to
/// `neptune-defi`.
///
/// The user's arguments are passed through unchanged. `neptune-defi` parses
/// only the flags whose values it needs, which is `--listen-rpc`, the way
/// `neptune-core` parses them, and `neptune-core` validates the rest. The
/// result is an error if the user passed one of [`FIXED_FLAGS`], in either
/// the `--flag value` or the `--flag=value` form, or an invalid `--listen-rpc`
/// address. Otherwise `neptune-defi` appends `--listen-rpc` unless the user
/// passed it, since plugins reach the node over JSON-RPC, then the RPC flags,
/// and then `notify_flags`, which set the remaining fixed flags.
pub(crate) fn node_command(
    user_args: &[String],
    notify_flags: &[String],
) -> Result<NodeCommand, ArgsError> {
    if let Some(fixed) = user_args
        .iter()
        .find_map(|arg| FIXED_FLAGS.into_iter().find(|f| *f == flag_name(arg)))
    {
        return Err(ArgsError::FixedFlag(fixed));
    }

    let mut args = user_args.to_vec();
    let rpc_address = match listen_rpc(user_args)? {
        Some(address) => address,
        None => {
            args.push(format!("--listen-rpc={DEFAULT_LISTEN_RPC}"));
            DEFAULT_LISTEN_RPC
        }
    };
    args.push(format!("--rpc-modules={RPC_MODULES}"));
    args.push("--unsafe-rpc".to_owned());
    args.extend_from_slice(notify_flags);

    Ok(NodeCommand { args, rpc_address })
}

/// The flag an argument names, without a value joined to it by `=`.
fn flag_name(arg: &str) -> &str {
    arg.split('=').next().unwrap_or(arg)
}

/// The address `--listen-rpc` gives among `user_args`, or `None` if the flag
/// is absent.
///
/// This reads the flag the way `neptune-core` does: `--listen-rpc ADDR` and
/// `--listen-rpc=ADDR` give `ADDR`, and the flag followed by nothing or by
/// another flag gives [`DEFAULT_LISTEN_RPC`].
fn listen_rpc(user_args: &[String]) -> Result<Option<SocketAddr>, ArgsError> {
    const FLAG: &str = "--listen-rpc";
    let Some(position) = user_args.iter().position(|arg| flag_name(arg) == FLAG) else {
        return Ok(None);
    };

    let value = match user_args[position].strip_prefix(&format!("{FLAG}=")) {
        Some(joined) => Some(joined),
        None => user_args
            .get(position + 1)
            .map(String::as_str)
            .filter(|next| !next.starts_with('-')),
    };
    let Some(value) = value else {
        return Ok(Some(DEFAULT_LISTEN_RPC));
    };

    value
        .parse()
        .map(Some)
        .map_err(|_| ArgsError::InvalidListenRpc(value.to_owned()))
}

/// The `neptune-core` executable: the one next to `neptune-defi` if there is
/// one, and otherwise the first on `PATH`.
pub(crate) fn find_executable() -> Option<PathBuf> {
    let name = format!("neptune-core{}", std::env::consts::EXE_SUFFIX);
    let beside_self = std::env::current_exe()
        .ok()
        .map(|exe| exe.with_file_name(&name));
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(&name));

    beside_self
        .into_iter()
        .chain(on_path)
        .find(|path| path.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn notify() -> Vec<String> {
        args(&["--block-notify=notify-command %s"])
    }

    /// The fixed flags `neptune-defi` appends, after the user's arguments.
    fn appended(listen_rpc: bool) -> Vec<String> {
        let mut appended = vec![];
        if listen_rpc {
            appended.push("--listen-rpc=127.0.0.1:9797".to_owned());
        }
        appended.push("--rpc-modules=node,chain,mempool,mining,wallet,personal".to_owned());
        appended.push("--unsafe-rpc".to_owned());
        appended.extend(notify());
        appended
    }

    /// `neptune-core` has no short form and no alias for any fixed flag, so
    /// a fixed flag is passed by its long name, and in one of four shapes:
    /// alone, followed by a value, joined to a value, or joined to an empty
    /// value. Each is refused wherever it stands among other arguments.
    #[test]
    fn every_fixed_flag_is_refused_in_every_shape_and_position() {
        for flag in FIXED_FLAGS {
            let shapes = [
                vec![flag.to_owned()],
                vec![flag.to_owned(), "value".to_owned()],
                vec![format!("{flag}=value")],
                vec![format!("{flag}=")],
            ];
            for shape in shapes {
                let others = args(&["--network", "regtest"]);
                for position in [0, 1, 2] {
                    let mut user = others.clone();
                    for (offset, arg) in shape.iter().enumerate() {
                        user.insert(position + offset, arg.clone());
                    }
                    assert_eq!(
                        Err(ArgsError::FixedFlag(flag)),
                        node_command(&user, &notify()),
                        "{user:?}"
                    );
                }
            }
        }
    }

    /// A fixed flag where `neptune-core` expects a value is still a flag to
    /// `neptune-core`, which reads a token starting with `--` as a flag, so it
    /// is refused there too.
    #[test]
    fn a_fixed_flag_in_the_place_of_a_value_is_refused() {
        let user = args(&["--peers", "--unsafe-rpc"]);
        assert_eq!(
            Err(ArgsError::FixedFlag("--unsafe-rpc")),
            node_command(&user, &notify())
        );
    }

    /// Only a flag's name decides whether it is fixed. A different flag that
    /// begins like a fixed one, and a value that contains one, pass through.
    #[test]
    fn names_that_only_resemble_a_fixed_flag_pass_through() {
        for user in [
            args(&["--unsafe-rpc-extra"]),
            args(&["--block-notify-extra", "value"]),
            args(&["--rpc-modules2=chain"]),
            args(&["--data-dir=/tmp/--unsafe-rpc"]),
            args(&["--data-dir", "/tmp/--rpc-modules=chain"]),
            args(&["-unsafe-rpc"]),
        ] {
            let node = node_command(&user, &notify()).unwrap();
            assert_eq!([user, appended(true)].concat(), node.args);
        }
    }

    #[test]
    fn no_arguments_give_only_the_fixed_flags() {
        let node = node_command(&[], &notify()).unwrap();
        assert_eq!(appended(true), node.args);
        assert_eq!(DEFAULT_LISTEN_RPC, node.rpc_address);
    }

    /// Flags, values, short flags and aliases all pass through in their
    /// original order, ahead of the fixed flags, whether or not
    /// `neptune-core` accepts them: validating them is `neptune-core`'s job.
    #[test]
    fn other_arguments_pass_through_unchanged_and_in_order() {
        for user in [
            args(&["--network", "regtest", "--peers", "1.2.3.4:9798"]),
            args(&["-n", "regtest", "--notx", "--max-num-peers=3"]),
            args(&["--no-such-flag", "positional", "--", "--anything"]),
            args(&["--data-dir", "/path with spaces/", "--peers="]),
        ] {
            let node = node_command(&user, &notify()).unwrap();
            assert_eq!([user, appended(true)].concat(), node.args);
            assert_eq!(DEFAULT_LISTEN_RPC, node.rpc_address);
        }
    }

    #[test]
    fn listen_rpc_is_read_as_neptune_core_reads_it() {
        let v4: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let v6: SocketAddr = "[::1]:1234".parse().unwrap();
        for (user, address) in [
            (args(&["--listen-rpc", "127.0.0.1:1234"]), v4),
            (args(&["--listen-rpc=127.0.0.1:1234"]), v4),
            (args(&["--listen-rpc", "[::1]:1234"]), v6),
            (args(&["--listen-rpc=[::1]:1234"]), v6),
            (args(&["--listen-rpc"]), DEFAULT_LISTEN_RPC),
            (
                args(&["--listen-rpc", "--network", "regtest"]),
                DEFAULT_LISTEN_RPC,
            ),
            (
                args(&["--network", "regtest", "--listen-rpc", "127.0.0.1:1234"]),
                v4,
            ),
        ] {
            let node = node_command(&user, &notify()).unwrap();
            assert_eq!(address, node.rpc_address, "{user:?}");
            assert_eq!([user, appended(false)].concat(), node.args);
        }
    }

    /// `neptune-core` refuses a repeated `--listen-rpc`, so `neptune-defi`
    /// passes the repetition through for it to refuse, and adds no third.
    #[test]
    fn a_repeated_listen_rpc_is_passed_through() {
        let user = args(&["--listen-rpc=127.0.0.1:1", "--listen-rpc=127.0.0.1:2"]);
        let node = node_command(&user, &notify()).unwrap();
        assert_eq!([user, appended(false)].concat(), node.args);
    }

    /// Only a socket address is a valid value: no host name, no bare port or
    /// address, no out-of-range port, and not the empty string.
    #[test]
    fn an_invalid_listen_rpc_address_is_refused() {
        for (user, value) in [
            (args(&["--listen-rpc", "localhost:9797"]), "localhost:9797"),
            (args(&["--listen-rpc=9797"]), "9797"),
            (args(&["--listen-rpc", "127.0.0.1"]), "127.0.0.1"),
            (args(&["--listen-rpc=127.0.0.1:65536"]), "127.0.0.1:65536"),
            (args(&["--listen-rpc="]), ""),
            (args(&["--listen-rpc", "nonsense"]), "nonsense"),
        ] {
            assert_eq!(
                Err(ArgsError::InvalidListenRpc(value.to_owned())),
                node_command(&user, &notify()),
                "{user:?}"
            );
        }
    }

    /// A refused fixed flag is reported before an invalid address, so the
    /// user learns of the flag they cannot pass at all first.
    #[test]
    fn a_fixed_flag_is_reported_before_an_invalid_address() {
        let user = args(&["--listen-rpc=nonsense", "--unsafe-rpc"]);
        assert_eq!(
            Err(ArgsError::FixedFlag("--unsafe-rpc")),
            node_command(&user, &notify())
        );
    }
}
