//! The external programs a node runs when something happens: `--block-notify`
//! and `--tx-notify`.

use std::process::Command;
use std::process::Stdio;

use itertools::Itertools;
use tracing::debug;
use tracing::error;
use tracing::trace;

/// Run `command`, if set, with every `%s` replaced by `argument`.
///
/// The first space separates the program from its arguments, and every later
/// space separates two arguments. The program runs in a process of its own,
/// which nothing waits on, so its exit code is never checked. Halts the node if
/// the program cannot be started.
pub(crate) fn spawn_notify_command(command: &Option<String>, argument: &str) {
    let Some(command) = command else {
        return;
    };
    let cmd = command.replace("%s", argument);

    debug!("Invoking notify cmd:\"{cmd}\"");
    let args = cmd.split(' ').collect_vec();
    trace!("args[0]=\"{}\"", args[0]);
    trace!("args[1..]=[{}]", args[1..].iter().join(","));
    let child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::null()) // detach from our stdin
        .stdout(Stdio::null()) // discard output
        .stderr(Stdio::null()) // discard errors
        .spawn()
        .unwrap_or_else(|e| {
            error!("Failed to start external program \"{cmd}\": {e}");
            std::process::exit(1);
        });

    // Don't wait on `child`, just drop it:
    drop(child);
}
