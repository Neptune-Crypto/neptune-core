//! `neptune-defi` runs `neptune-core` for overlay protocols.
//!
//! It takes `neptune-core`'s command line, passes it through, and sets the
//! flags in [`node::FIXED_FLAGS`] itself. The notify flags among them make
//! `neptune-core` run `neptune-defi notify`, which hands the running
//! `neptune-defi` each notification.

mod node;
mod notify;

use std::process::ExitCode;

use tokio::sync::mpsc;

const INSTALL_URL: &str = "https://github.com/Neptune-Crypto/neptune-core#installing";

fn main() -> ExitCode {
    let user_args = std::env::args().skip(1).collect::<Vec<_>>();

    // neptune-core runs this once per notification, so it does no more than
    // send it. neptune-core takes no positional arguments, so a first argument
    // equal to the subcommand's name is never one of neptune-core's.
    if user_args.first().map(String::as_str) == Some(notify::SUBCOMMAND) {
        return match notify::send(&user_args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }

    tokio::runtime::Runtime::new()
        .expect("a tokio runtime must start")
        .block_on(run(user_args))
}

/// Run `neptune-core` with `user_args`, and take its notifications until it
/// exits.
async fn run(user_args: Vec<String>) -> ExitCode {
    let listener = match notify::bind().await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("Could not listen for notifications from neptune-core: {error}");
            return ExitCode::FAILURE;
        }
    };
    let port = listener
        .local_addr()
        .expect("a bound listener has an address")
        .port();
    let notify_flags = match std::env::current_exe()
        .map_err(|error| error.to_string())
        .and_then(|exe| notify::notify_flags(&exe, port).map_err(|error| error.to_string()))
    {
        Ok(notify_flags) => notify_flags,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    let node_command = match node::node_command(&user_args, &notify_flags) {
        Ok(node_command) => node_command,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };

    let Some(executable) = node::find_executable() else {
        eprintln!(
            "neptune-defi runs neptune-core, which was found neither next to \
             neptune-defi nor on PATH. Please install neptune-core: {INSTALL_URL}"
        );
        return ExitCode::FAILURE;
    };

    eprintln!(
        "neptune-defi: starting {}, which serves JSON-RPC on {}",
        executable.display(),
        node_command.rpc_address
    );
    let mut node = match tokio::process::Command::new(&executable)
        .args(&node_command.args)
        .spawn()
    {
        Ok(node) => node,
        Err(error) => {
            eprintln!("Could not start {}: {error}", executable.display());
            return ExitCode::FAILURE;
        }
    };

    let (sender, mut notifications) = mpsc::unbounded_channel();
    tokio::spawn(notify::listen(listener, sender));

    // An interrupt from the terminal reaches neptune-core as well, which
    // shuts down on it. So neptune-defi waits for that, rather than exiting
    // first and leaving neptune-core behind.
    //
    // ponytail: a signal sent to neptune-defi alone, rather than to its process
    // group, does not reach neptune-core. Forward SIGINT and SIGTERM when a
    // supervisor that signals only the parent needs it.
    let status = loop {
        tokio::select! {
            status = node.wait() => break status,
            _ = tokio::signal::ctrl_c() => {}
            Some(notification) = notifications.recv() => {
                eprintln!("neptune-defi: {notification}");
            }
        }
    };

    match status.ok().and_then(|status| status.code()) {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    }
}
