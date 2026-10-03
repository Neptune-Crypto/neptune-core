//! The plugin cookie: a secret only the user who started `neptune-defi` can
//! read, which a plugin sends to prove it runs as that user.

use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;

use neptune_defi::plugin::COOKIE_LENGTH;

/// A plugin cookie.
pub(crate) type Cookie = [u8; COOKIE_LENGTH];

/// Write a new random cookie to `path`, and return it.
///
/// This follows `neptune-core`'s RPC cookie. On Unix the file can be read and
/// written by its owner alone, and a directory the call creates can be entered
/// by its owner alone; elsewhere both get the permissions of the user's data
/// directory. The file is replaced by a rename, so a plugin never reads a
/// partly written cookie.
pub(crate) fn write(path: &Path) -> io::Result<Cookie> {
    let cookie: Cookie = rand::random();

    if let Some(parent) = path.parent() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(parent)?;
    }

    let temporary = path.with_extension(format!("{:016x}", rand::random::<u64>()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&temporary)?;
    file.write_all(&cookie)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;

    Ok(cookie)
}

/// `cookie` in lowercase hex, as a plugin sends it.
pub(crate) fn hex(cookie: &Cookie) -> String {
    cookie.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> std::path::PathBuf {
        std::env::temp_dir()
            .join("neptune-defi-cookie-tests")
            .join(format!("{:016x}", rand::random::<u64>()))
    }

    #[test]
    fn the_cookie_written_is_the_cookie_returned_and_is_new_every_time() {
        let path = scratch().join("data dir").join(".cookie");
        let first = write(&path).unwrap();
        assert_eq!(first.to_vec(), fs::read(&path).unwrap());

        let second = write(&path).unwrap();
        assert_ne!(first, second);
        assert_eq!(second.to_vec(), fs::read(&path).unwrap());
        assert_eq!(1, fs::read_dir(path.parent().unwrap()).unwrap().count());
        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_the_cookie() {
        use std::os::unix::fs::PermissionsExt;

        let root = scratch();
        let path = root.join("data dir").join(".cookie");
        write(&path).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(0o600, mode(&path));
        assert_eq!(0o700, mode(path.parent().unwrap()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hex_is_lowercase_and_two_digits_per_byte() {
        let mut cookie = [0; COOKIE_LENGTH];
        cookie[0] = 0x0a;
        cookie[1] = 0xff;
        let hex = hex(&cookie);
        assert_eq!(2 * COOKIE_LENGTH, hex.len());
        assert!(hex.starts_with("0aff00"));
    }
}
