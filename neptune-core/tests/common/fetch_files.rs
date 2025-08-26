use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use rand::seq::SliceRandom;
use tracing::debug;
use tracing::Span;

// Copied from elsewhere because it's under the test flag the other place.
#[allow(dead_code)]
pub fn test_helper_data_dir() -> PathBuf {
    const TEST_DATA_DIR_NAME: &str = "test_data/";
    let mut path = PathBuf::new();
    path.push(TEST_DATA_DIR_NAME);
    path
}

// Copied from elsewhere because it's under the test flag the other place.
#[allow(dead_code)]
pub fn try_fetch_file_from_server(filename: String) -> Option<(Vec<u8>, String)> {
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

    fn load_servers() -> Vec<String> {
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

    let mut servers = load_servers();
    servers.shuffle(&mut rand::rng());

    // Add test name to request to allow server to see which test requires this
    // file.
    let mut headers = clienter::HttpHeaders::default();
    headers.insert(
        TEST_NAME_HTTP_HEADER_KEY.to_string(),
        attempt_to_get_test_name(),
    );

    for server in servers {
        let server_ = server.clone();
        let filename_ = filename.clone();
        let headers_ = headers.clone();
        let handle = std::thread::spawn(move || {
            let url = format!("{}{}", server_, filename_);

            debug!("requesting: <{url}>");

            let uri: clienter::Uri = url.into();

            let mut http_client = clienter::HttpClient::new();
            http_client.timeout = Some(Duration::from_secs(10));
            http_client.headers = headers_;
            let request = http_client.request(clienter::HttpMethod::GET, uri);

            // note: send() blocks
            let Ok(mut response) = http_client.send(&request) else {
                println!(
                    "server '{}' failed for file '{}'; trying next ...",
                    server_.clone(),
                    filename_
                );

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
            continue;
        };

        if !status_code.is_success() {
            eprintln!("{server} responded with {status_code}");
            continue;
        }

        let Ok(file_contents) = body else {
            eprintln!(
                "error reading file '{}' from server '{}'; trying next ...",
                filename, server
            );

            continue;
        };

        return Some((file_contents, server));
    }

    println!("No known servers serve file `{}`", filename);

    None
}
