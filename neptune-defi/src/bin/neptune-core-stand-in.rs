//! A stand-in for `neptune-core`, which `neptune-defi`'s integration tests run
//! in its place. It is built only with the `test-stand-in` feature.
//!
//! It writes the arguments it receives, one per line, to a file named `args`
//! next to its own executable. If `STAND_IN_NOTIFY` is set, it then waits the
//! number of milliseconds in `STAND_IN_DELAY`, if that is set, runs every
//! notify command among its arguments, as `neptune-core` does on an event,
//! with the variable's value in place of `%s`, and waits a second for the
//! notifications to be taken in. It exits with the code in `STAND_IN_EXIT`,
//! or 0 if that is not set, unless `STAND_IN_ABORT` is set, in which case it
//! aborts.

use std::process::Command;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let exe = std::env::current_exe().expect("the stand-in knows its own path");
    let lines = args
        .iter()
        .map(|arg| format!("{arg}\n"))
        .collect::<String>();
    std::fs::write(exe.with_file_name("args"), lines)
        .expect("the stand-in can record its arguments");

    if let Ok(id) = std::env::var("STAND_IN_NOTIFY") {
        let delay = std::env::var("STAND_IN_DELAY").map_or(0, |ms| ms.parse().expect("a delay"));
        std::thread::sleep(Duration::from_millis(delay));
        let commands = args
            .iter()
            .filter_map(|arg| arg.split_once('='))
            .filter(|(flag, _)| flag.ends_with("-notify"))
            .map(|(_, command)| command.replace("%s", &id));
        for command in commands {
            let words = words(&command);
            let (program, args) = words
                .split_first()
                .expect("a notify command names a program");
            let _ = Command::new(program).args(args).status();
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    if std::env::var_os("STAND_IN_ABORT").is_some() {
        std::process::abort();
    }

    let code = std::env::var("STAND_IN_EXIT").map_or(0, |code| code.parse().expect("an exit code"));
    ExitCode::from(code)
}

/// The words of a notify command, as `neptune-core` splits it: at spaces
/// outside double quotes, which group what they enclose and are dropped.
fn words(command: &str) -> Vec<String> {
    let mut words = vec![];
    let mut word: Option<String> = None;
    let mut quoted = false;
    for c in command.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                word.get_or_insert_with(String::new);
            }
            ' ' if !quoted => words.extend(word.take()),
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    words.extend(word);

    words
}
