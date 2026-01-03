use anyhow::Context;
use anyhow::Result;
use libp2p::identity::Keypair;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

const IDENTITY_WARNING_HEADER: &str = r#"# =============================================================================
# LIBP2P NODE IDENTITY KEY
# =============================================================================
# This file contains the private key for your P2P node identity.
#
# WHAT IT DOES:
# - Manages your node's PeerId and network identity.
# - Allows other peers to recognize you across restarts.
#
# WHAT IT DOES NOT DO:
# - It DOES NOT manage, store, or protect any cryptocurrency funds.
# =============================================================================
"#;

/// Read the node's cryptographic identity from the filesystem or generate a new
/// one.
///
/// This method centralizes how Neptune Cash nodes manage their Peer-to-Peer
/// identity. It supports three primary workflows:
///
///  1. **Persistent Identity (Default)**
///     If no flags are set, the function looks for `identity.key` in the
///     `data_dir`. This ensures the node maintains its **reputation** and
///     **reachability** in the Kademlia DHT and Relay service across restarts.
///
///  2. **Incognito Mode (`incognito: true`)**
///     Generates a purely ephemeral identity. The node will act as a "stranger"
///     to the network. No data is read from or written to the disk. Use this
///     for one-off sessions where identity persistence is not desired.
///
///  3. **Identity Rotation (`new_identity: true`)**
///     Forces the generation of a fresh identity while preserving the old one.
///     The existing `identity.key` is renamed to `identity.<timestamp>.bak`.
///     This is useful if a node's identity has been blacklisted or if the user
///     wants to "reset" their network presence.
///
/// The identity file contains a human-readable header explaining that this key
/// manages **network identity only** and does not control **cryptocurrency
/// funds**. The key material itself is stored as a hex-encoded
/// Protobuf-serialized Ed25519 keypair.
///
/// # Arguments
///
///  - `data_dir` - The base directory where the identity file is stored by
///    default.
///  - `identity_file` - An optional custom path to the identity file (overrides
///    default).
///  - `incognito` - If true, skip disk operations and use an ephemeral identity.
///  - `new_identity` - If true, backup the existing identity file and create a
///    new one.
///
/// # Return Value
///
///  - Err(_) if some crucial file system or codec operation failed.
///  - Ok(KeyPair) otherwise.
///
/// Note that if the caller wants to fall back on an ephemeral identity in the
/// event of file system or codec failure, this is the caller's responsibility.
pub(crate) fn resolve_identity(
    data_dir: PathBuf,
    identity_file: Option<String>,
    incognito: bool,
    new_identity: bool,
) -> Result<Keypair> {
    // Incognito: ephemeral identity for this session only
    if incognito {
        info!("Incognito mode active: using ephemeral identity.");
        return Ok(Keypair::generate_ed25519());
    }

    // Determine path (default to data_dir/identity.key)
    let path = identity_file
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("identity.key"));

    // New Identity: rotate existing file with timestamped backup
    if new_identity && path.exists() {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let backup = path.with_extension(format!("{}.bak", ts));
        fs::rename(&path, &backup).context("Failed to backup identity")?;
        info!(
            "Backed up existing identity file to '{}'.",
            backup.to_string_lossy()
        );
        info!(
            "Proceeding with fresh new identity at '{}'.",
            path.to_string_lossy()
        );
    }

    // Load or create identity
    if path.exists() {
        let content = fs::read_to_string(&path).context("Failed to read identity file")?;
        let encoded_key = content
            .lines()
            .find(|line| !line.trim().starts_with('#') && !line.trim().is_empty())
            .context("No key data found")?;

        let bytes = hex::decode(encoded_key.trim()).context("Failed to decode hex key")?;
        let keypair =
            Keypair::from_protobuf_encoding(&bytes).context("Failed to parse protobuf key");

        info!("Using identity file '{}'.", path.to_string_lossy());

        keypair
    } else {
        info!("Generating new persistent identity.");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("Create identity directory")?;
        }

        let new_key = Keypair::generate_ed25519();
        let bytes = new_key
            .to_protobuf_encoding()
            .context("Failed to encode key")?;
        let file_content = format!("{}\n{}", IDENTITY_WARNING_HEADER, hex::encode(bytes));

        fs::write(&path, file_content).context("Failed to save identity file")?;
        info!("Saved new identity file to '{}'.", path.to_string_lossy());
        Ok(new_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_identity_lifecycle() {
        // Create a unique temporary directory name using the current timestamp
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut data_dir = env::temp_dir();
        data_dir.push(format!("identity_test_{}", ts));

        fs::create_dir_all(&data_dir).expect("Failed to create test temp dir");

        // --- Test 1: Initial Generation ---
        let key1 = resolve_identity(data_dir.clone(), None, false, false)
            .expect("Should generate new identity");
        let id1 = key1.public().to_peer_id();

        // --- Test 2: Persistence (Load existing) ---
        let key2 = resolve_identity(data_dir.clone(), None, false, false)
            .expect("Should load existing identity");
        assert_eq!(
            id1,
            key2.public().to_peer_id(),
            "Identity should be persistent"
        );

        // --- Test 3: Incognito (Ignore file) ---
        let key_incog = resolve_identity(data_dir.clone(), None, true, false)
            .expect("Should generate incognito identity");
        assert_ne!(
            id1,
            key_incog.public().to_peer_id(),
            "Incognito should produce a different ID"
        );

        // --- Test 4: New Identity (Backup and rotate) ---
        let key_new =
            resolve_identity(data_dir.clone(), None, false, true).expect("Should back up identity");
        assert_ne!(
            id1,
            key_new.public().to_peer_id(),
            "New identity should be different"
        );

        // Verify backup file exists
        let has_backup = fs::read_dir(&data_dir)
            .unwrap()
            .map(|res| res.unwrap().path())
            .any(|path| {
                path.extension()
                    .is_some_and(|ext| ext.to_string_lossy().contains("bak"))
            });
        assert!(has_backup, "Backup file should exist after backing up");

        // Cleanup
        let _ = fs::remove_dir_all(&data_dir);
    }
}
