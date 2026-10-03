//! The `neptune-defi` binary, run against a stand-in for `neptune-core`.
//!
//! The stand-in is a shell script that records the arguments it receives and
//! exits with a code the test chooses, so these tests check what
//! `neptune-defi` hands `neptune-core` and what it makes of the result,
//! without starting a node.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
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
    "--rpc-modules=node,chain,mempool,mining,wallet,personal",
    "--unsafe-rpc",
];

/// Held while a test writes an executable or runs one.
///
/// A file open for writing cannot be executed, and a process forked by
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
}

impl Sandbox {
    fn new() -> Self {
        let dir = std::env::temp_dir()
            .join("neptune-defi-cli-tests")
            .join(format!("{:016x}", rand::random::<u64>()));
        fs::create_dir_all(dir.join("bin")).unwrap();
        let _executables = executables();
        fs::copy(
            env!("CARGO_BIN_EXE_neptune-defi"),
            dir.join("bin/neptune-defi"),
        )
        .unwrap();
        Self { dir }
    }

    /// Put a stand-in `neptune-core` in `dir`. It writes its arguments, one
    /// per line, to `<dir>/args`, and exits with `exit`.
    fn neptune_core(&self, dir: &str, exit: &str) -> PathBuf {
        let dir = self.dir.join(dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("neptune-core");
        let args_file = dir.join("args");
        let _executables = executables();
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n{exit}\n",
                args_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    /// Run `neptune-defi` with `args`, and with `PATH` set to `path`.
    fn run(&self, args: &[&str], path: &[&Path]) -> Output {
        let path = std::env::join_paths(path).unwrap();
        let _executables = executables();
        Command::new(self.dir.join("bin/neptune-defi"))
            .args(args)
            .env("PATH", path)
            .output()
            .unwrap()
    }

    /// The arguments the stand-in in `dir` received, up to the notify flags,
    /// or `None` if it did not run.
    ///
    /// The notify flags come last, and name this sandbox's `neptune-defi` and
    /// a port the operating system chose, so they are checked here by shape
    /// and left out of the result.
    fn received(&self, dir: &str) -> Option<Vec<String>> {
        let args = fs::read_to_string(self.dir.join(dir).join("args")).ok()?;
        let args = args.lines().map(str::to_owned).collect::<Vec<_>>();
        let (args, notify_flags) = args.split_at(args.len() - 3);

        let exe = self.dir.join("bin/neptune-defi");
        for (flag, kind) in notify_flags.iter().zip(["block", "tx", "proposal"]) {
            let prefix = format!("--{kind}-notify={} notify ", exe.display());
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
    sandbox.neptune_core("bin", "exit 0");
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
    sandbox.neptune_core("bin", "exit 0");
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
    for code in [0, 1, 2, 3, 101] {
        let sandbox = Sandbox::new();
        sandbox.neptune_core("bin", &format!("exit {code}"));
        let output = sandbox.run(&[], &[]);
        assert_eq!(Some(code), output.status.code());
    }
}

#[test]
fn neptune_core_killed_by_a_signal_is_a_failure() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin", "kill -9 $$");
    let output = sandbox.run(&[], &[]);
    assert_eq!(Some(1), output.status.code());
}

#[test]
fn a_fixed_flag_is_refused_without_starting_neptune_core() {
    for flag in FIXED_FLAGS {
        for args in [vec![flag.to_owned()], vec![format!("{flag}=value")]] {
            let sandbox = Sandbox::new();
            sandbox.neptune_core("bin", "exit 0");
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
    sandbox.neptune_core("bin", "exit 0");

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
    let on_path = sandbox.neptune_core("elsewhere", "exit 0");

    let output = sandbox.run(&[], &[&on_path]);

    assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
    assert_eq!(Some(strings(&APPENDED)), sandbox.received("elsewhere"));
}

#[test]
fn neptune_core_next_to_neptune_defi_is_preferred_to_one_on_path() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin", "exit 0");
    let on_path = sandbox.neptune_core("elsewhere", "exit 0");

    let output = sandbox.run(&[], &[&on_path]);

    assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
    assert!(sandbox.received("bin").is_some());
    assert_eq!(None, sandbox.received("elsewhere"));
}

#[test]
fn a_neptune_core_that_cannot_be_executed_is_reported() {
    let sandbox = Sandbox::new();
    let script = sandbox.neptune_core("bin", "exit 0").join("neptune-core");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();

    let output = sandbox.run(&[], &[]);

    assert_eq!(Some(1), output.status.code());
    assert!(stderr(&output).contains("Could not start"));
}

/// The stand-in runs every notify command it was given, the way
/// `neptune-core` does on an event, and `neptune-defi` takes in each
/// notification.
#[test]
fn notifications_from_neptune_core_reach_neptune_defi() {
    let sandbox = Sandbox::new();
    let id = "0".repeat(80);
    sandbox.neptune_core(
        "bin",
        &format!(
            "for arg in \"$@\"; do\n\
             \x20 case \"$arg\" in\n\
             \x20   --*-notify=*) $(printf '%s' \"${{arg#*=}}\" | sed 's/%s/{id}/') ;;\n\
             \x20 esac\n\
             done\n\
             sleep 1\n\
             exit 0"
        ),
    );

    let output = sandbox.run(&[], &[Path::new("/bin"), Path::new("/usr/bin")]);

    assert_eq!(Some(0), output.status.code(), "{}", stderr(&output));
    for kind in ["block", "tx", "proposal"] {
        assert!(
            stderr(&output).contains(&format!("neptune-defi: {kind} {id}")),
            "{}",
            stderr(&output)
        );
    }
}

#[test]
fn a_path_to_neptune_defi_with_a_space_is_refused() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("with space", "exit 0");
    let exe = sandbox.dir.join("with space/neptune-defi");
    {
        let _executables = executables();
        fs::copy(env!("CARGO_BIN_EXE_neptune-defi"), &exe).unwrap();
    }

    let output = {
        let _executables = executables();
        Command::new(&exe).env("PATH", "").output().unwrap()
    };

    assert_eq!(Some(1), output.status.code());
    assert!(stderr(&output).contains("may not contain one"));
    assert!(!sandbox.dir.join("with space/args").exists());
}

/// The `notify` subcommand on its own, without a `neptune-defi` listening:
/// malformed arguments and an unreachable port are failures, and neither
/// starts `neptune-core`.
#[test]
fn the_notify_subcommand_fails_on_malformed_arguments_or_no_listener() {
    let sandbox = Sandbox::new();
    sandbox.neptune_core("bin", "exit 0");
    let id = "0".repeat(80);
    let unused_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    for args in [
        vec!["notify".to_owned()],
        vec!["notify".to_owned(), "1".to_owned(), "block".to_owned()],
        vec![
            "notify".to_owned(),
            "1".to_owned(),
            "nonsense".to_owned(),
            id.clone(),
        ],
        vec![
            "notify".to_owned(),
            "1".to_owned(),
            "block".to_owned(),
            "beef".to_owned(),
        ],
        vec![
            "notify".to_owned(),
            unused_port.to_string(),
            "block".to_owned(),
            id.clone(),
        ],
    ] {
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = sandbox.run(&args, &[]);
        assert_eq!(Some(1), output.status.code(), "{args:?}");
        assert_eq!(None, sandbox.received("bin"));
    }
}
