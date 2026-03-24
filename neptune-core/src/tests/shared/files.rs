use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clienter::HttpHeaders;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use rand::seq::SliceRandom;
use tokio::time::sleep;
use tokio::time::timeout;
use tracing::debug;
use tracing::Span;

use crate::application::config::data_directory::DataDirectory;

/// Create a randomly named `DataDirectory` so filesystem-bound tests can run
/// in parallel. If this is not done, parallel execution of unit tests will
/// fail as they each hold a lock on the database.
///
/// For now we use databases on disk. In-memory databases would be nicer.
pub(crate) fn unit_test_data_directory(
    network: crate::api::export::Network,
) -> Result<DataDirectory> {
    let mut rng = rand::rng();
    let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
    let pid = std::process::id();

    let tmp_root: PathBuf = env::temp_dir()
        .join(format!("neptune-unit-tests-{user}-{pid}"))
        .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));

    DataDirectory::get(Some(tmp_root), network)
}

/// Waits until the file at `path` exists, or returns `Err` after 30 seconds.
pub(crate) async fn wait_for_file_to_exist(path: impl AsRef<Path>) -> Result<(), &'static str> {
    let path = path.as_ref().to_path_buf();

    // Wrap in timeout: returns error if 30s pass without success
    let res = timeout(Duration::from_secs(30), async {
        loop {
            if path.exists() {
                return Ok(());
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await;

    match res {
        Ok(inner) => inner,
        Err(_) => Err("Timed out"), // timeout triggered
    }
}

/// Return path for the directory containing test data, like proofs and block
/// data.
pub(crate) fn test_helper_data_dir() -> PathBuf {
    const TEST_DATA_DIR_NAME: &str = "test_data/";
    let mut path = PathBuf::new();
    path.push(TEST_DATA_DIR_NAME);
    path
}

/// Load a list of proof-servers from test data directory. These servers are
/// expected to server data required for tests. That data is mainly proofs but
/// may also be blocks.
pub(crate) fn load_test_proof_servers() -> Vec<String> {
    let mut server_list_path = test_helper_data_dir();
    server_list_path.push(Path::new("proof_servers").with_extension("txt"));
    let Ok(mut input_file) = File::open(server_list_path.clone()) else {
        debug!(
            "cannot proof-server list '{}' -- file might not exist",
            server_list_path.display()
        );
        return vec![];
    };
    let mut file_contents = vec![];
    if input_file.read_to_end(&mut file_contents).is_err() {
        debug!("cannot read file '{}'", server_list_path.display());
        return vec![];
    }
    let Ok(file_as_string) = String::from_utf8(file_contents) else {
        debug!(
            "cannot parse file '{}' -- is it valid utf8?",
            server_list_path.display()
        );
        return vec![];
    };
    file_as_string.lines().map(|s| s.to_string()).collect()
}

/// Tries to load a file from disk, returns the bytes if successful.
pub(crate) fn try_load_file_from_disk(path: &Path) -> Option<Vec<u8>> {
    let Ok(mut input_file) = File::open(path) else {
        debug!("cannot open file '{}' -- might not exist", path.display());
        return None;
    };

    let mut file_contents = vec![];
    if input_file.read_to_end(&mut file_contents).is_err() {
        debug!("cannot read file '{}'", path.display());
        return None;
    }

    Some(file_contents)
}

pub(crate) fn try_fetch_from_server(
    filename: String,
    server: String,
    headers: HttpHeaders,
) -> Option<Vec<u8>> {
    let filename_ = filename.clone();
    let server_ = server.clone();
    let handle = std::thread::spawn(move || {
        let server__ = &server_;
        let filename__ = &filename_;
        let url = format!("{server__}{filename__}");

        debug!("requesting: <{url}>");

        let uri: clienter::Uri = url.into();

        let mut http_client = clienter::HttpClient::new();
        http_client.timeout = Some(Duration::from_millis(1600));
        http_client.headers = headers;
        let request = http_client.request(clienter::HttpMethod::GET, uri);

        // note: send() blocks
        let Ok(mut response) = http_client.send(&request) else {
            println!("server '{server__}' failed for file '{filename__}'; trying next ...",);

            return None;
        };

        // only retrieve body if we got a 2xx code.
        // addresses #477
        // https://github.com/Neptune-Crypto/neptune-core/issues/477
        let body = if response.status.is_success() {
            response.body()
        } else {
            Ok(vec![])
        };

        Some((response.status, body))
    });

    let Some((status_code, body)) = handle.join().unwrap() else {
        eprintln!("Could not connect to server {server}.");
        return None;
    };

    if !status_code.is_success() {
        eprintln!("{server} responded with {status_code}");
        return None;
    }

    println!("{server} responded with successful HTTP status code");

    let Ok(file_contents) = body else {
        eprintln!("error reading file '{filename}' from server '{server}'");

        return None;
    };

    Some(file_contents)
}

/// Build headers expected by proof server. Allows proof server to see which
/// test is requesting the data.
pub(crate) fn headers_for_proof_server_request() -> clienter::HttpHeaders {
    const TEST_NAME_HTTP_HEADER_KEY: &str = "Test-Name";

    fn get_test_name_from_tracing() -> String {
        match Span::current().metadata().map(|x| x.name()) {
            Some(test_name) => test_name.to_owned(),
            None => "unknown".to_owned(),
        }
    }

    fn attempt_to_get_test_name() -> String {
        let thread = std::thread::current();
        match thread.name() {
            Some(test_name) => {
                if test_name.eq("tokio-runtime-worker") {
                    get_test_name_from_tracing()
                } else {
                    test_name.to_owned()
                }
            }
            None => get_test_name_from_tracing(),
        }
    }

    // Add test name to request to allow server to see which test requires this
    // file.
    let mut headers = clienter::HttpHeaders::default();
    headers.insert(
        TEST_NAME_HTTP_HEADER_KEY.to_string(),
        attempt_to_get_test_name(),
    );

    headers
}

/// Return the specified file from a server, along with the name of the server
/// providing the result.
pub(crate) fn try_fetch_file(filename: String) -> Option<(Vec<u8>, String)> {
    let headers = headers_for_proof_server_request();

    let mut servers = load_test_proof_servers();
    servers.shuffle(&mut rand::rng());

    for server in servers {
        let body = try_fetch_from_server(filename.clone(), server.clone(), headers.clone());
        if let Some(body) = body {
            return Some((body, server));
        }
    }

    println!("No known servers serve file `{}`", filename);

    None
}

// recursively copy source dir to destination
pub fn copy_dir_recursive(source: &PathBuf, destination: &PathBuf) -> std::io::Result<()> {
    if !source.is_dir() {
        return Err(std::io::Error::other("Source is not a directory"));
    }
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let dest_path = &destination.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir_recursive(&entry.path(), dest_path)?;
        } else {
            std::fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

mod tests {
    use super::*;

    #[test]
    fn test_load_servers() {
        let servers = load_test_proof_servers();
        for server in servers {
            println!("read server: {}", server);
        }
    }
}
