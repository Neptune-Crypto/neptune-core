//! `neptune-defi` runs `neptune-core` for overlay protocols.
//!
//! It takes `neptune-core`'s command line, passes it through, and sets the
//! flags in [`node::FIXED_FLAGS`] itself.

mod node;

use std::process::ExitCode;

const INSTALL_URL: &str = "https://github.com/Neptune-Crypto/neptune-core#installing";

#[tokio::main]
async fn main() -> ExitCode {
    let user_args = std::env::args().skip(1).collect::<Vec<_>>();
    let node_command = match node::node_command(&user_args) {
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
        }
    };

    match status.ok().and_then(|status| status.code()) {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::FAILURE,
    }
}
