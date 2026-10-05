//! The `neptune-defi` binary, run against a stand-in for `neptune-core`.
//!
//! The stand-in, `neptune-core-stand-in`, records the arguments it receives,
//! can run the notify commands among them, and exits with a code the test
//! chooses, so these tests check what `neptune-defi` hands `neptune-core` and
//! what it makes of the result, without starting a node.

use std::env::consts::EXE_SUFFIX;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::Mutex;
use std::sync::MutexGuard;

const FIXED_FLAGS: [&str; 5] = [
    "--block-notify",
    "--tx-notify",
    "--proposal-notify",
    "--rpc-modules",
    "--unsafe-rpc",
];

const APPENDED: [&str; 3] = [
    "--listen-rpc=127.0.0.1:9797",
    "--rpc-modules=node,chain,archival,mempool,mining,wallet,personal",
    "--unsafe-rpc",
];

/// Held while a test writes an executable or runs one.
///
/// A file open for writing cannot be executed, and on Unix a process forked by
/// another test thread inherits every open file until it executes its own
/// program. So without this lock, one test's executable may still be open
/// in another test's child when it is run, and running it fails with "text
/// file busy".
static EXECUTABLES: Mutex<()> = Mutex::new(());

fn executables() -> MutexGuard<'static, ()> {
    EXECUTABLES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A directory of its own for one test, holding a copy of `neptune-defi`, so
/// that what lies next to the executable is up to the test.
struct Sandbox {
    dir: PathBuf,

    /// The directory within `dir` that holds `neptune-defi`.
    bin: &'static str,
}

impl Sandbox {
    fn new() -> Self {
        Self::with_bin("bin")
    }

    /// A sandbox whose `neptune-defi` lives in `dir/bin`.
    fn with_bin(bin: &'static str) -> Self {
        let dir = std::env::temp_dir()
            .join("neptune-defi-cli-tests")
            .join(format!("{:016x}", rand::random::<u64>()));
        fs::create_dir_all(dir.join(bin)).unwrap();
        let sandbox = Self { dir, bin };
        let _executables = executables();
        fs::copy(env!("CARGO_BIN_EXE_neptune-defi"), sandbox.exe()).unwrap();
        sandbox
    }

    fn exe(&self) -> PathBuf {
        self.dir
            .join(self.bin)
            .join(format!("neptune-defi{EXE_SUFFIX}"))
    }

    /// Put the stand-in, named `neptune-core`, in `dir`, and return `dir`.
    fn neptune_core(&self, dir: &str) -> PathBuf {
        let dir = self.dir.join(dir);
        fs::create_dir_all(&dir).unwrap();
        let _executables = executables();
        fs::copy(
            env!("CARGO_BIN_EXE_neptune-core-stand-in"),
            dir.join(format!("neptune-core{EXE_SUFFIX}")),
        )
        .unwrap();
        dir
    }

    /// The arguments every run starts with: a data directory in the sandbox,
    /// which holds the plugin cookie, and a plugin port the operating system
    /// chooses, so that runs in parallel do not collide.
    fn base_args(&self) -> Vec<String> {
        vec![
            "--data-dir".to_owned(),
            self.dir.join("data").display().to_string(),
            "--plugin-listen=127.0.0.1:0".to_owned(),
        ]
    }

    /// Run `neptune-defi` with [`Self::base_args`] and `args`, with `PATH` set
    /// to `path`, and with the stand-in's environment variables set as
    /// `stand_in` says.
    fn run_with(&self, args: &[&str], path: &[&Path], stand_in: &[(&str, &str)]) -> Output {
        let path = std::env::join_paths(path).unwrap();
        let _executables = executables();
        Command::new(self.exe())
            .args(self.base_args())
            .args(args)
            .env("PATH", path)
            .envs(stand_in.iter().copied())
            .output()
            .unwrap()
    }

    fn run(&self, args: &[&str], path: &[&Path]) -> Output {
        self.run_with(args, path, &[])
    }

    /// Run `neptune-defi notify` with `args`, as `neptune-core` does: with
    /// nothing before the subcommand.
    fn run_notify(&self, args: &[&str]) -> Output {
        let _executables = executables();
        Command::new(self.exe())
            .arg("notify")
            .args(args)
            .output()
            .unwrap()
    }

    /// The arguments the stand-in in `dir` received after the data
    /// directory and before the notify flags, or `None` if it did not run.
    ///
    /// The data directory comes first, from [`Self::base_args`], whose plugin
    /// port `neptune-defi` keeps to itself. The notify flags come last, and
    /// name this sandbox's `neptune-defi` and a port the operating system
    /// chose, so they are checked here by shape and left out of the result.
    fn received(&self, dir: &str) -> Option<Vec<String>> {
        let args = fs::read_to_string(self.dir.join(dir).join("args")).ok()?;
        let args = args.lines().map(str::to_owned).collect::<Vec<_>>();
        let (data_dir, args) = args.split_at(2);
        assert_eq!(self.base_args()[..2], *data_dir);
        let (args, notify_flags) = args.split_at(args.len() - 3);

        let exe = self.exe().display().to_string();
        let program = if exe.contains(' ') {
            format!("\"{exe}\"")
        } else {
            exe
        };
        for (flag, kind) in notify_flags.iter().zip(["block", "tx", "proposal"]) {
            let prefix = format!("--{kind}-notify={program} notify ");
            let port = flag
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(&format!(" {kind} %s")))
                .unwrap_or_else(|| panic!("not a {kind} notify flag: {flag}"));
            port.parse::<u16>().unwrap();
        }

        Some(args.to_vec())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

#[test]
fn the_users_arguments_reach_neptune_core_followed_by_the_fixed_flags() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");
    let user = ["--network", "regtest", "--data-dir", "/a path/with spaces"];

    let output = sandbox.run(&user, &[]);

    assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
    assert_eq!(
        Some([strings(&user), strings(&APPENDED)].concat()),
        sandbox.received("bin")
    );
    assert!(stderr(&output).contains("serves JSON-RPC on 127.0.0.1:9797"));
}

#[test]
fn a_listen_rpc_address_of_the_users_reaches_neptune_core_once() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");
    let user = ["--listen-rpc", "[::1]:1234"];

    let output = sandbox.run(&user, &[]);

    assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
    assert_eq!(
        Some([strings(&user), strings(&APPENDED[1..])].concat()),
        sandbox.received("bin")
    );
    assert!(stderr(&output).contains("serves JSON-RPC on [::1]:1234"));
}

#[test]
fn neptune_cores_exit_code_is_neptune_defis() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");
    for code in [0, 1, 2, 3, 101] {
        let output = sandbox.run_with(&[], &[], &[("STAND_IN_EXIT", &code.to_string())]);
        assert_eq!(Some(code), output.status.code());
    }
}

/// Only Unix ends a process with a signal, and so without an exit code.
#[cfg(unix)]
#[test]
fn neptune_core_killed_by_a_signal_is_a_failure() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");
    let output = sandbox.run_with(&[], &[], &[("STAND_IN_ABORT", "1")]);
    assert_eq!(Some(1), output.status.code());
}

#[test]
fn a_fixed_flag_is_refused_without_starting_neptune_core() {
    for flag in FIXED_FLAGS {
        for args in [vec![flag.to_owned()], vec![format!("{flag}=value")]] {
            let sandbox = Sandbox::new();
            sandbox.neptune_core("bin");
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();

            let output = sandbox.run(&args, &[]);

            assert_eq!(Some(2), output.status.code());
            assert!(stderr(&output).contains(&format!("neptune-defi sets {flag}")));
            assert_eq!(None, sandbox.received("bin"));
        }
    }
}

#[test]
fn an_invalid_listen_rpc_address_is_refused_without_starting_neptune_core() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");

    let output = sandbox.run(&["--listen-rpc", "localhost:9797"], &[]);

    assert_eq!(Some(2), output.status.code());
    assert!(stderr(&output).contains("--listen-rpc takes a socket address"));
    assert_eq!(None, sandbox.received("bin"));
}

#[test]
fn without_neptune_core_the_user_is_asked_to_install_it() {
    let sandbox = Sandbox::new();
    let empty = sandbox.dir.join("empty");
    fs::create_dir_all(&empty).unwrap();

    let output = sandbox.run(&["--network", "regtest"], &[&empty]);

    assert_eq!(Some(1), output.status.code());
    let message = stderr(&output);
    assert!(message.contains("Please install neptune-core"));
    assert!(message.contains("https://github.com/Neptune-Crypto/neptune-core#installing"));
}

#[test]
fn neptune_core_is_found_on_path_when_not_next_to_neptune_defi() {
    let sandbox = Sandbox::new();
    let on_path = sandbox.neptune_core("elsewhere");

    let output = sandbox.run(&[], &[&on_path]);

    assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
    assert_eq!(Some(strings(&APPENDED)), sandbox.received("elsewhere"));
}

#[test]
fn neptune_core_next_to_neptune_defi_is_preferred_to_one_on_path() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");
    let on_path = sandbox.neptune_core("elsewhere");

    let output = sandbox.run(&[], &[&on_path]);

    assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
    assert!(sandbox.received("bin").is_some());
    assert_eq!(None, sandbox.received("elsewhere"));
}

/// Only Unix has a permission to execute a file.
#[cfg(unix)]
#[test]
fn a_neptune_core_that_cannot_be_executed_is_reported() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    let exe = sandbox.neptune_core("bin").join("neptune-core");
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o644)).unwrap();

    let output = sandbox.run(&[], &[]);

    assert_eq!(Some(1), output.status.code());
    assert!(stderr(&output).contains("Could not start"));
}

/// `neptune-defi` takes in each notification its `neptune-core` sends,
/// whether or not the path to `neptune-defi` contains a space.
#[test]
fn notifications_from_neptune_core_reach_neptune_defi() {
    for bin in ["bin", "with space"] {
        let sandbox = Sandbox::with_bin(bin);
        let id = "0".repeat(80);
        sandbox.neptune_core(bin);

        let output = sandbox.run_with(&[], &[], &[("STAND_IN_NOTIFY", &id)]);

        assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
        for kind in ["block", "tx", "proposal"] {
            assert!(
                stderr(&output).contains(&format!("neptune-defi: {kind} {id}")),
                "{bin}: {}",
                stderr(&output)
            );
        }
        assert!(sandbox.received(bin).is_some());
    }
}

/// Windows forbids a double quote in a path, so the case arises only on Unix.
#[cfg(unix)]
#[test]
fn a_path_to_neptune_defi_with_a_double_quote_is_refused() {
    let sandbox = Sandbox::with_bin("with \"quote\"");
    sandbox.neptune_core("with \"quote\"");

    let output = sandbox.run(&[], &[]);

    assert_eq!(Some(1), output.status.code());
    assert!(stderr(&output).contains("contains a double quote"));
    assert_eq!(None, sandbox.received("with \"quote\""));
}

/// The `notify` subcommand on its own, without a `neptune-defi` listening:
/// malformed arguments and an unreachable port are failures, and neither
/// starts `neptune-core`.
#[test]
fn the_notify_subcommand_fails_on_malformed_arguments_or_no_listener() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");
    let id = "0".repeat(80);
    let unused_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    for args in [
        vec![],
        vec!["1".to_owned(), "block".to_owned()],
        vec!["1".to_owned(), "nonsense".to_owned(), id.clone()],
        vec!["1".to_owned(), "block".to_owned(), "beef".to_owned()],
        vec![unused_port.to_string(), "block".to_owned(), id.clone()],
    ] {
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = sandbox.run_notify(&args);
        assert_eq!(Some(1), output.status.code(), "{args:?}");
        assert_eq!(None, sandbox.received("bin"));
    }
}

/// A plugin that connects with [`neptune_defi::plugin::connect`] is welcomed,
/// told where `neptune-core` serves JSON-RPC, sent the notifications it
/// subscribed to and no others, and disconnected when `neptune-core` exits.
#[test]
fn a_plugin_receives_the_notifications_it_subscribed_to() {
    use std::io::BufRead;
    use std::io::BufReader;

    use neptune_defi::plugin::connect;
    use neptune_defi::plugin::cookie_path;
    use neptune_defi::plugin::Event;
    use neptune_defi::plugin::Kind;

    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin");
    let id = "0".repeat(80);
    let mut defi = {
        let _executables = executables();
        Command::new(sandbox.exe())
            .args(sandbox.base_args())
            .args(["--network", "regtest"])
            .env("STAND_IN_NOTIFY", &id)
            .env("STAND_IN_DELAY", "2000")
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };

    // neptune-defi says where it listens for plugins, and where the cookie
    // is, before neptune-core sends its first notification.
    let mut stderr = BufReader::new(defi.stderr.take().unwrap()).lines();
    let listening = stderr
        .by_ref()
        .map(Result::unwrap)
        .find(|line| line.contains("listening for plugins on "))
        .unwrap();
    let address = listening
        .split("listening for plugins on ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .unwrap()
        .to_owned();
    // The cookie lies next to neptune-core's own, in its data directory for
    // the network, which is where a plugin looks for it.
    let cookie_path = cookie_path(
        &neptune_primitives::data_directory::DataDirectory::get(
            Some(sandbox.dir.join("data")),
            neptune_primitives::network::Network::RegTest,
        )
        .unwrap(),
    );

    // The stand-in sends one notification of each kind, and then exits,
    // which makes neptune-defi exit and close the connection.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let received = runtime.block_on(async {
        let address = address.parse().unwrap();
        let mut connection = connect(address, &cookie_path, "test", vec![Kind::Proposal])
            .await
            .unwrap();
        assert_eq!(
            "127.0.0.1:9797".parse::<std::net::SocketAddr>().unwrap(),
            connection.rpc()
        );

        let mut received = vec![];
        while let Some(event) = connection.next().await.unwrap() {
            received.push(event);
        }
        received
    });

    let [Event::Notification(notification)] = received[..] else {
        panic!("not one notification: {received:?}");
    };
    assert_eq!(Kind::Proposal, notification.kind);
    assert_eq!(id, notification.id.to_hex());
    assert_eq!(Some(0), defi.wait().unwrap().code());
}
