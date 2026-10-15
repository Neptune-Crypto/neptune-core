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
/// The command's first word, as [`words`] splits it, is the program, and the
/// rest are its arguments. The program runs in a process of its own,
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
    let args = words(&cmd);
    let Some((program, args)) = args.split_first() else {
        error!("Notify command \"{command}\" names no program");
        std::process::exit(1);
    };
    trace!("program=\"{program}\"");
    trace!("args=[{}]", args.iter().join(","));
    let child = Command::new(program)
        .args(args)
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
