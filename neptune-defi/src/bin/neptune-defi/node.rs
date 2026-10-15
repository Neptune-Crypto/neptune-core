//! The command line of the `neptune-core` process that `neptune-defi` spawns.

use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;

use neptune_primitives::data_directory::DataDirectory;
use neptune_primitives::network::Network;

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
const RPC_MODULES: &str = "node,chain,archival,mempool,mining,wallet,personal";

/// The address `neptune-core` serves JSON-RPC on when `--listen-rpc` is given
/// without one. `neptune-defi` uses it as well when the flag is absent.
const DEFAULT_LISTEN_RPC: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9797);

/// The flag of `neptune-defi`'s own that says where it listens for plugins. It
/// is not passed on to `neptune-core`.
pub(crate) const PLUGIN_LISTEN: &str = "--plugin-listen";

/// Why `neptune-defi` cannot run with the arguments the user passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArgsError {
    /// A flag that `neptune-defi` sets itself.
    FixedFlag(&'static str),

    /// A value that a flag `neptune-defi` reads does not take.
    InvalidValue {
        flag: &'static str,
        value: String,
        expected: &'static str,
    },

    /// A flag that takes a value, given without one.
    MissingValue {
        flag: &'static str,
        expected: &'static str,
    },

    /// A flag of `neptune-defi`'s own, given more than once.
    Repeated(&'static str),

    /// The data directory cannot be determined.
    NoDataDirectory(String),
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedFlag(flag) => write!(
                f,
                "neptune-defi sets {flag} on neptune-core itself, so it cannot be \
                 passed. Every other neptune-core flag is passed through unchanged."
            ),
            Self::InvalidValue {
                flag,
                value,
                expected,
            } => write!(f, "{flag} takes {expected}, not {value:?}."),
            Self::MissingValue { flag, expected } => write!(f, "{flag} takes {expected}."),
            Self::Repeated(flag) => write!(f, "{flag} may be given only once."),
            Self::NoDataDirectory(error) => {
                write!(f, "Cannot determine neptune-core's data directory: {error}")
            }
        }
    }
}

/// How `neptune-defi` runs `neptune-core`, and what it needs to know about the
/// run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeCommand {
    /// The arguments `neptune-core` is spawned with.
    pub(crate) args: Vec<String>,

    /// Where `neptune-core` serves JSON-RPC, which is where plugins reach it.
    pub(crate) rpc_address: SocketAddr,

    /// The plugin cookie's file, next to `neptune-core`'s own RPC cookie in
    /// its data directory.
    pub(crate) cookie_path: PathBuf,

    /// Where `neptune-defi` listens for plugins.
    pub(crate) plugin_address: SocketAddr,
}

/// How to run `neptune-core`, given the arguments the user passed to
/// `neptune-defi`.
///
/// The user's arguments are passed through unchanged, except for
/// [`PLUGIN_LISTEN`], which is `neptune-defi`'s own. `neptune-defi` reads the
/// flags whose values it needs, which are `--listen-rpc`, `--network` and
/// `--data-dir`, the way `neptune-core` reads them, and `neptune-core`
/// validates the rest. The result is an error if the user passed one of
/// [`FIXED_FLAGS`], in either the `--flag value` or the `--flag=value` form, or
/// an invalid or missing value for a flag `neptune-defi` reads, or
/// [`PLUGIN_LISTEN`] more than once. Otherwise
/// `neptune-defi` appends `--listen-rpc` unless the user passed it, since
/// plugins reach the node over JSON-RPC, then the RPC flags, and then
/// `notify_flags`, which set the remaining fixed flags.
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
    let plugin_address = match find(&args, PLUGIN_LISTEN, None) {
        Some(occurrence) => {
            let address = required(PLUGIN_LISTEN, &occurrence, SOCKET_ADDRESS)?;
            args.drain(occurrence.position..occurrence.position + occurrence.len);
            if find(&args, PLUGIN_LISTEN, None).is_some() {
                return Err(ArgsError::Repeated(PLUGIN_LISTEN));
            }
            address
        }
        None => neptune_defi::plugin::DEFAULT_ADDRESS,
    };

    let network = match find(&args, "--network", Some('n')) {
        Some(occurrence) => required("--network", &occurrence, NETWORK)?,
        None => Network::Main,
    };
    let data_dir = find(&args, "--data-dir", None)
        .map(|occurrence| required::<PathBuf>("--data-dir", &occurrence, DIRECTORY))
        .transpose()?;
    let data_directory = DataDirectory::get(data_dir, network)
        .map_err(|error| ArgsError::NoDataDirectory(error.to_string()))?;
    let cookie_path = neptune_defi::plugin::cookie_path(&data_directory);

    let rpc_address = match find(&args, "--listen-rpc", None) {
        Some(Occurrence {
            value: Some(value), ..
        }) => value.parse().map_err(|_| ArgsError::InvalidValue {
            flag: "--listen-rpc",
            value: value.to_owned(),
            expected: SOCKET_ADDRESS,
        })?,
        Some(Occurrence { value: None, .. }) => DEFAULT_LISTEN_RPC,
        None => {
            args.push(format!("--listen-rpc={DEFAULT_LISTEN_RPC}"));
            DEFAULT_LISTEN_RPC
        }
    };
    args.push(format!("--rpc-modules={RPC_MODULES}"));
    args.push("--unsafe-rpc".to_owned());
    args.extend_from_slice(notify_flags);

    Ok(NodeCommand {
        args,
        rpc_address,
        cookie_path,
        plugin_address,
    })
}

const SOCKET_ADDRESS: &str = "a socket address such as 127.0.0.1:9797";
const NETWORK: &str = "a network such as main, testnet or regtest";
const DIRECTORY: &str = "a directory";

/// The flag an argument names, without a value joined to it by `=`.
fn flag_name(arg: &str) -> &str {
    arg.split('=').next().unwrap_or(arg)
}

/// Where a flag occurs among the arguments, and its value.
struct Occurrence {
    /// The index of the argument that names the flag.
    position: usize,

    /// The number of arguments the flag and its value take up: two if the
    /// value is the next argument, and one otherwise.
    len: usize,

    /// The flag's value, if it has one.
    value: Option<String>,
}

/// The first occurrence of the flag `long`, or of its short form `short`,
/// among `args`, read the way `neptune-core`'s argument parser reads it.
///
/// `--long=VALUE`, `-sVALUE` and `-s=VALUE` carry their value in the same
/// argument. `--long VALUE` and `-s VALUE` take the next argument as the value
/// unless it starts with `-`, in which case the flag has no value.
fn find(args: &[String], long: &str, short: Option<char>) -> Option<Occurrence> {
    let short = short.map(|short| format!("-{short}"));
    args.iter().enumerate().find_map(|(position, arg)| {
        let joined = if flag_name(arg) == long {
            arg.strip_prefix(long).map(|rest| rest.strip_prefix('='))?
        } else {
            let short = short.as_deref().filter(|short| arg.starts_with(short))?;
            let rest = &arg[short.len()..];
            if rest.is_empty() {
                None
            } else {
                Some(rest.strip_prefix('=').unwrap_or(rest))
            }
        };

        if let Some(joined) = joined {
            return Some(Occurrence {
                position,
                len: 1,
                value: Some(joined.to_owned()),
            });
        }
        let next = args.get(position + 1).filter(|next| !next.starts_with('-'));
        Some(Occurrence {
            position,
            len: 1 + usize::from(next.is_some()),
            value: next.cloned(),
        })
    })
}

/// The value of a flag that requires one, parsed.
fn required<T: std::str::FromStr>(
    flag: &'static str,
    occurrence: &Occurrence,
    expected: &'static str,
) -> Result<T, ArgsError> {
    let value = occurrence
        .value
        .as_deref()
        .ok_or(ArgsError::MissingValue { flag, expected })?;
    value.parse().map_err(|_| ArgsError::InvalidValue {
        flag,
        value: value.to_owned(),
        expected,
    })
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
        appended
            .push("--rpc-modules=node,chain,archival,mempool,mining,wallet,personal".to_owned());
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
                Err(ArgsError::InvalidValue {
                    flag: "--listen-rpc",
                    value: value.to_owned(),
                    expected: SOCKET_ADDRESS,
                }),
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

    fn cookie_path(data_dir: Option<&str>, network: Network) -> PathBuf {
        neptune_defi::plugin::cookie_path(
            &DataDirectory::get(data_dir.map(PathBuf::from), network).unwrap(),
        )
    }

    /// `--network` and its short form `-n` are read in every shape the
    /// argument parser of `neptune-core` accepts, and pass through unchanged.
    #[test]
    fn the_network_is_read_as_neptune_core_reads_it() {
        for user in [
            args(&["--network", "regtest"]),
            args(&["--network=regtest"]),
            args(&["-n", "regtest"]),
            args(&["-nregtest"]),
            args(&["-n=regtest"]),
            args(&["--peers", "1.2.3.4:5", "-n", "regtest", "--notx"]),
        ] {
            let node = node_command(&user, &notify()).unwrap();
            assert_eq!(
                cookie_path(None, Network::RegTest),
                node.cookie_path,
                "{user:?}"
            );
            assert_eq!([user, appended(true)].concat(), node.args);
        }

        let node = node_command(&args(&["--network", "testnet-3"]), &notify()).unwrap();
        assert_eq!(cookie_path(None, Network::Testnet(3)), node.cookie_path);

        let node = node_command(&[], &notify()).unwrap();
        assert_eq!(cookie_path(None, Network::Main), node.cookie_path);
    }

    /// The plugin cookie lies in `neptune-core`'s data directory for the
    /// network, wherever `--data-dir` puts it.
    ///
    /// The data directory is absolute on every platform. On Windows, a path
    /// such as `/srv/neptune data` is not, since it names no drive, and
    /// `neptune-core` puts it on the drive of the user's application data.
    #[test]
    fn the_cookie_lies_in_the_data_directory() {
        let data_dir = std::env::temp_dir().join("neptune data");
        let data_dir = data_dir.to_str().unwrap();
        for user in [
            args(&["--data-dir", data_dir, "-n", "regtest"]),
            args(&[&format!("--data-dir={data_dir}"), "--network=regtest"]),
        ] {
            let node = node_command(&user, &notify()).unwrap();
            assert_eq!(
                cookie_path(Some(data_dir), Network::RegTest),
                node.cookie_path
            );
            assert!(node.cookie_path.starts_with(data_dir));
        }
    }

    #[test]
    fn a_missing_or_invalid_network_or_data_directory_is_refused() {
        for (user, error) in [
            (
                args(&["--network", "nonsense"]),
                ArgsError::InvalidValue {
                    flag: "--network",
                    value: "nonsense".to_owned(),
                    expected: NETWORK,
                },
            ),
            (
                args(&["-ntestnet-x"]),
                ArgsError::InvalidValue {
                    flag: "--network",
                    value: "testnet-x".to_owned(),
                    expected: NETWORK,
                },
            ),
            (
                args(&["--network"]),
                ArgsError::MissingValue {
                    flag: "--network",
                    expected: NETWORK,
                },
            ),
            (
                args(&["-n", "--notx"]),
                ArgsError::MissingValue {
                    flag: "--network",
                    expected: NETWORK,
                },
            ),
            (
                args(&["--data-dir"]),
                ArgsError::MissingValue {
                    flag: "--data-dir",
                    expected: DIRECTORY,
                },
            ),
        ] {
            assert_eq!(Err(error), node_command(&user, &notify()), "{user:?}");
        }
    }

    /// `--plugin-listen` is `neptune-defi`'s own, so it is read and then
    /// removed, value and all, from what `neptune-core` receives.
    #[test]
    fn the_plugin_address_is_read_and_not_passed_on() {
        let given: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        for (user, rest) in [
            (
                args(&["--plugin-listen", "127.0.0.1:4000", "-n", "regtest"]),
                args(&["-n", "regtest"]),
            ),
            (
                args(&["-n", "regtest", "--plugin-listen=127.0.0.1:4000"]),
                args(&["-n", "regtest"]),
            ),
        ] {
            let node = node_command(&user, &notify()).unwrap();
            assert_eq!(given, node.plugin_address);
            assert_eq!([rest, appended(true)].concat(), node.args);
        }

        let node = node_command(&[], &notify()).unwrap();
        assert_eq!(neptune_defi::plugin::DEFAULT_ADDRESS, node.plugin_address);
    }

    #[test]
    fn a_missing_or_invalid_plugin_address_is_refused() {
        for (user, error) in [
            (
                args(&["--plugin-listen"]),
                ArgsError::MissingValue {
                    flag: PLUGIN_LISTEN,
                    expected: SOCKET_ADDRESS,
                },
            ),
            (
                args(&["--plugin-listen", "--notx"]),
                ArgsError::MissingValue {
                    flag: PLUGIN_LISTEN,
                    expected: SOCKET_ADDRESS,
                },
            ),
            (
                args(&["--plugin-listen=localhost:4000"]),
                ArgsError::InvalidValue {
                    flag: PLUGIN_LISTEN,
                    value: "localhost:4000".to_owned(),
                    expected: SOCKET_ADDRESS,
                },
            ),
        ] {
            assert_eq!(Err(error), node_command(&user, &notify()), "{user:?}");
        }
    }

    /// `--plugin-listen` is neptune-defi's own, so neptune-core never sees it.
    /// A second one is refused, as neptune-core refuses a second of its own
    /// options, in whatever shape and wherever it stands.
    #[test]
    fn a_repeated_plugin_address_is_refused() {
        for user in [
            args(&[
                "--plugin-listen=127.0.0.1:4000",
                "--plugin-listen=127.0.0.1:4001",
            ]),
            args(&[
                "--plugin-listen",
                "127.0.0.1:4000",
                "-n",
                "regtest",
                "--plugin-listen=127.0.0.1:4000",
            ]),
            args(&["--plugin-listen=127.0.0.1:4000", "--plugin-listen"]),
        ] {
            assert_eq!(
                Err(ArgsError::Repeated(PLUGIN_LISTEN)),
                node_command(&user, &notify()),
                "{user:?}"
            );
        }
    }
}
