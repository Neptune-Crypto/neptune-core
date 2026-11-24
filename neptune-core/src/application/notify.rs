//! The external programs a node runs when something happens: `--block-notify`,
//! `--tx-notify` and `--proposal-notify`.

use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::sync::mpsc::SendError;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use itertools::Itertools;
use tracing::debug;
use tracing::error;
use tracing::trace;

/// Run `command`, if set, with every `%s` replaced by `argument`.
///
/// The command's first word, as [`words`] splits it, is the program, and the
/// rest are its arguments. The program runs in a process of its own,
/// and the node does not wait for it to finish, nor check its exit code. A
/// thread of its own waits for it instead, because on Unix a process that
/// exits stays in the process table until its parent waits for it; were no
/// one to wait, every notification would leave one behind until the node
/// exits.
///
/// If the program cannot be started, logs an error and carries on: once the
/// node runs, a notification it cannot deliver is no reason to stop it. If the
/// thread that waits for it cannot be started, logs an error, and the next
/// notification waits for the process instead, if it has exited by then.
/// [`check_notify_command`] refuses a command whose program is missing at
/// startup, so this happens only if the program disappears later, or the
/// system cannot start another process or thread.
pub(crate) fn spawn_notify_command(command: &Option<String>, argument: &str) {
    let Some(command) = command else {
        return;
    };
    reap_unwaited();
    let cmd = command.replace("%s", argument);

    debug!("Invoking notify cmd:\"{cmd}\"");
    let args = words(&cmd);
    let Some((program, args)) = args.split_first() else {
        error!("Notify command \"{command}\" names no program");
        return;
    };
    trace!("program=\"{program}\"");
    trace!("args=[{}]", args.iter().join(","));
    let child = match Command::new(program)
        .args(args)
        .stdin(Stdio::null()) // detach from our stdin
        .stdout(Stdio::null()) // discard output
        .stderr(Stdio::null()) // discard errors
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            error!("Failed to start external program \"{cmd}\": {e}");
            return;
        }
    };

    // The child goes to the waiting thread only once that thread runs, so
    // that the child stays here if the thread cannot be started.
    let (to_waiter, from_spawner) = mpsc::channel::<Child>();
    let waiter = std::thread::Builder::new().spawn(move || {
        if let Ok(mut waited_for) = from_spawner.recv() {
            let _ = waited_for.wait();
        }
    });
    let unwaited = match waiter {
        Ok(_) => to_waiter.send(child).err().map(|SendError(unsent)| unsent),
        Err(e) => {
            error!("Failed to start a thread to wait for \"{cmd}\": {e}");
            Some(child)
        }
    };
    if let Some(unwaited) = unwaited {
        lock_unwaited().push(unwaited);
    }
}

/// The children whose waiting thread could not be started. Each call to
/// [`spawn_notify_command`] waits for those that have exited, so none stays in
/// the process table for longer than until the next notification.
static UNWAITED: Mutex<Vec<Child>> = Mutex::new(Vec::new());

fn lock_unwaited() -> MutexGuard<'static, Vec<Child>> {
    UNWAITED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Wait for every child in [`UNWAITED`] that has exited, without blocking, and
/// forget it. A child that cannot be waited for is forgotten too.
fn reap_unwaited() {
    lock_unwaited().retain_mut(|child| matches!(child.try_wait(), Ok(None)));
}

/// Why `command` cannot run, if it cannot: it names no program, or its
/// program is neither a file at the path given nor a file in a directory on
/// `PATH`.
///
/// A program named by a path, that is, by more than one component, is looked
/// up at that path, and a bare name is looked up on `PATH`, as
/// [`Command::new`] does. On Windows a bare name also matches the name with
/// `.exe` appended.
// ponytail: on Windows, `Command::new` also searches the node's own directory
// and the system directories, which this does not; a program found only there
// is refused. Mirror that search if anyone relies on it.
pub(crate) fn check_notify_command(command: &str) -> Result<(), String> {
    let words = words(command);
    let Some(program) = words.first() else {
        return Err("it names no program".to_owned());
    };

    let path = Path::new(program);
    let exists = if path.components().count() > 1 {
        path.is_file()
    } else {
        std::env::var_os("PATH").is_some_and(|dirs| {
            std::env::split_paths(&dirs).any(|dir| {
                let candidate = dir.join(program);
                candidate.is_file() || (cfg!(windows) && candidate.with_extension("exe").is_file())
            })
        })
    };

    if exists {
        Ok(())
    } else {
        Err(format!("program \"{program}\" not found"))
    }
}

/// The words of `command`.
///
/// Spaces separate words. A double quote starts a quoted run, which ends at the
/// next double quote, or at the end of the command if there is none. Inside a
/// quoted run a space belongs to the word, and the quotes themselves belong to
/// no word. Nothing escapes anything, so a backslash is an ordinary character,
/// as Windows paths need, and so is a single quote, which a Windows path may
/// contain. A word may consist of quoted and unquoted runs side by side, and
/// `""` is an empty word. Consecutive spaces outside quotes separate two words
/// just as one space does.
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

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    /// This process's children that exited and have not been waited for,
    /// running `program`.
    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    /// A child whose waiting thread could not be started is waited for once
    /// it has exited, at the next notification.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unwaited_child_is_reaped_at_the_next_notification() {
        let child = Command::new("sleep").arg("0").spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while exited_children_running("sleep") == 0 {
            assert!(Instant::now() < deadline, "the child never exited");
            std::thread::sleep(Duration::from_millis(10));
        }
        let id = child.id();
        lock_unwaited().push(child);

        spawn_notify_command(&Some("true %s".to_owned()), "argument");
        assert!(!lock_unwaited().iter().any(|unwaited| unwaited.id() == id));
        assert_eq!(0, exited_children_running("sleep"));
    }

    /// A program that cannot be started leaves the node running. Were it to
    /// halt the node, it would end this test process, and the test with it.
    #[test]
    fn a_missing_program_leaves_the_node_running() {
        spawn_notify_command(&Some("/no/such/program %s".to_owned()), "argument");
        spawn_notify_command(&Some("   ".to_owned()), "argument");
    }

    #[test]
    fn a_command_whose_program_exists_passes_the_check() {
        let this_program = std::env::current_exe().unwrap();
        let command = format!("\"{}\" %s", this_program.to_string_lossy());
        assert_eq!(Ok(()), check_notify_command(&command));

        #[cfg(unix)]
        assert_eq!(Ok(()), check_notify_command("sh -c true"));
        #[cfg(windows)]
        assert_eq!(Ok(()), check_notify_command("cmd /c rem"));
    }

    #[test]
    fn a_command_whose_program_is_missing_fails_the_check() {
        assert!(check_notify_command("").is_err());
        assert!(check_notify_command("   ").is_err());
        assert!(check_notify_command("/no/such/program %s").is_err());
        assert!(check_notify_command("no-such-program-on-path %s").is_err());

        // A directory is not a program.
        let dir = std::env::temp_dir();
        let command = format!("\"{}\" %s", dir.to_string_lossy());
        assert!(check_notify_command(&command).is_err());
    }

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn unquoted_words_are_separated_by_spaces() {
        assert_eq!(strings(&["a", "b", "c"]), words("a b c"));
        assert_eq!(strings(&["a", "b"]), words("  a   b  "));
        assert_eq!(Vec::<String>::new(), words(""));
        assert_eq!(Vec::<String>::new(), words("   "));
    }

    #[test]
    fn a_quoted_run_keeps_its_spaces_and_loses_its_quotes() {
        assert_eq!(
            strings(&["/opt/neptune defi/neptune-defi", "notify", "1"]),
            words(r#""/opt/neptune defi/neptune-defi" notify 1"#)
        );
        assert_eq!(
            strings(&[r"C:\Program Files\neptune-defi.exe", "x"]),
            words(r#""C:\Program Files\neptune-defi.exe" x"#)
        );
        assert_eq!(strings(&["a b c"]), words(r#"a" b "c"#));
        assert_eq!(strings(&["", "a", ""]), words(r#""" a """#));
        assert_eq!(strings(&["a", "b c "]), words(r#"a "b c "#));
    }

    /// Backslashes and single quotes are ordinary characters, so the
    /// unquoted commands that split at spaces before quoting existed still
    /// split the same way.
    #[test]
    fn backslashes_and_single_quotes_are_ordinary_characters() {
        assert_eq!(
            strings(&[r"C:\neptune\notify.exe", r"a\b", "%s"]),
            words(r"C:\neptune\notify.exe a\b %s")
        );
        assert_eq!(
            strings(&[r"C:\Users\O'Brien\notify.exe", "'a", "b'"]),
            words(r"C:\Users\O'Brien\notify.exe 'a b'")
        );
        assert_eq!(strings(&[r"a\ b"]), words(r#"a\" b"#));
    }

    /// A program whose path contains a space runs if the path is quoted, and
    /// so does an argument containing one. The program is the dummy notify
    /// script, which creates `<first argument>.block` in the directory its
    /// second argument names.
    #[test]
    fn a_quoted_path_may_contain_a_space() {
        use neptune_consensus::proof_abstractions::test_helpers::test_helper_data_dir;

        #[cfg(not(windows))]
        const SCRIPT: &str = "block_notify_dummy.py";
        #[cfg(windows)]
        const SCRIPT: &str = "block_notify_dummy.bat";

        let root = std::env::temp_dir()
            .join("neptune-notify-tests")
            .join(format!("{:016x}", rand::random::<u64>()));
        let program_dir = root.join("with space");
        std::fs::create_dir_all(&program_dir).unwrap();
        let test_data = std::fs::canonicalize(test_helper_data_dir()).unwrap();

        // A link rather than a copy: a file just written may still be open in
        // a process another test thread forked, and cannot be executed then.
        #[cfg(unix)]
        std::os::unix::fs::symlink(test_data.join(SCRIPT), program_dir.join(SCRIPT)).unwrap();
        #[cfg(windows)]
        for file in ["block_notify_dummy.bat", "block_notify_dummy.py"] {
            std::fs::copy(test_data.join(file), program_dir.join(file)).unwrap();
        }

        let output_dir = root.join("out put");
        let command = format!(
            r#""{}" %s "{}""#,
            program_dir.join(SCRIPT).display(),
            output_dir.display()
        );
        spawn_notify_command(&Some(command), "notified");

        let deadline = Instant::now() + Duration::from_secs(30);
        while !output_dir.join("notified.block").exists() {
            assert!(Instant::now() < deadline, "the notify command did not run");
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
