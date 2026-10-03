//! The external programs a node runs when something happens: `--block-notify`,
//! `--tx-notify` and `--proposal-notify`.

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
/// and the node does not wait for it to finish, nor check its exit code. A
/// thread of its own waits for it instead, because on Unix a process that
/// exits stays in the process table until its parent waits for it; were no
/// one to wait, every notification would leave one behind until the node
/// exits. Halts the node if the program cannot be started.
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

    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    /// This process's children that exited and have not been waited for,
    /// running `program`.
    fn exited_children_running(program: &str) -> usize {
        let parent = std::process::id().to_string();
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|entry| std::fs::read_to_string(entry.ok()?.path().join("stat")).ok())
            .filter(|stat| {
                // The fields after the parenthesized program name are the state
                // and then the parent's process id.
                let Some((name, rest)) = stat.split_once(") ") else {
                    return false;
                };
                let mut fields = rest.split(' ');
                name.ends_with(&format!("({program}"))
                    && fields.next() == Some("Z")
                    && fields.next() == Some(parent.as_str())
            })
            .count()
    }

    #[test]
    fn notify_commands_leave_no_exited_process_behind() {
        let command = Some("true %s".to_owned());
        for _ in 0..10 {
            spawn_notify_command(&command, "argument");
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while exited_children_running("true") > 0 {
            assert!(
                Instant::now() < deadline,
                "notify commands that exited were never waited for"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
