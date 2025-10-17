//! Integration tests for wallet encryption system
//!
//! Tests the full encryption pipeline from password input to file I/O.

use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test helper: Create a temporary directory for wallet testing
fn create_test_wallet_dir() -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let wallet_dir = temp_dir.path().to_path_buf();
    (temp_dir, wallet_dir)
}

#[test]
fn test_full_encryption_pipeline() {
    // Setup
    let password = "TestPassword123!Secure";
    let test_data =
        r#"{"name":"test_wallet","secret_seed":{"coefficients":[123,456,789]},"version":0}"#;

    // Step 1: Encrypt
    let encrypted = EncryptedWalletFile::encrypt("test_wallet".to_string(), test_data, password)
        .expect("Encryption should succeed");

    // Step 2: Serialize to JSON
    let json = encrypted.to_json().expect("Serialization should succeed");

    // Step 3: Deserialize from JSON
    let deserialized =
        EncryptedWalletFile::from_json(&json).expect("Deserialization should succeed");

    // Step 4: Decrypt
    let decrypted = deserialized
        .decrypt(password)
        .expect("Decryption should succeed");

    // Verify
    assert_eq!(test_data, decrypted.as_str());
}

#[test]
fn test_file_io_roundtrip() {
    let (_temp_dir, wallet_dir) = create_test_wallet_dir();
    let test_file = wallet_dir.join("test_wallet.encrypted");

    let password = "FileIOTest456!";
    let test_data =
        r#"{"name":"io_test","secret_seed":{"coefficients":[111,222,333]},"version":0}"#;

    // Encrypt and write to file
    let encrypted = EncryptedWalletFile::encrypt("io_test".to_string(), test_data, password)
        .expect("Encryption should succeed");

    encrypted
        .write_to_file(&test_file)
        .expect("Writing to file should succeed");

    // Read from file and decrypt
    let loaded =
        EncryptedWalletFile::read_from_file(&test_file).expect("Reading from file should succeed");

    let decrypted = loaded.decrypt(password).expect("Decryption should succeed");

    assert_eq!(test_data, decrypted.as_str());
}

#[test]
fn test_password_strength_enforcement() {
    // Weak passwords
    assert!(!PasswordManager::analyze_strength("weak").is_acceptable());
    assert!(!PasswordManager::analyze_strength("short123").is_acceptable());

    // Acceptable passwords
    assert!(PasswordManager::analyze_strength("GoodPassword12!").is_acceptable());
    assert!(PasswordManager::analyze_strength("VeryLongAndSecure123!@#").is_acceptable());
}

#[test]
fn test_wrong_password_detection() {
    let correct_password = "CorrectPassword123!";
    let wrong_password = "WrongPassword456!";
    let test_data = r#"{"name":"test","secret_seed":{"coefficients":[1,2,3]},"version":0}"#;

    let encrypted = EncryptedWalletFile::encrypt("test".to_string(), test_data, correct_password)
        .expect("Encryption should succeed");

    // Correct password should work
    assert!(encrypted.decrypt(correct_password).is_ok());

    // Wrong password should fail
    assert!(encrypted.decrypt(wrong_password).is_err());
}

#[test]
fn test_tamper_detection() {
    let password = "TamperTest789!";
    let test_data = r#"{"name":"tamper_test","secret_seed":{"coefficients":[7,8,9]},"version":0}"#;

    let mut encrypted =
        EncryptedWalletFile::encrypt("tamper_test".to_string(), test_data, password)
            .expect("Encryption should succeed");

    // Tamper with ciphertext
    if !encrypted.ciphertext.is_empty() {
        encrypted.ciphertext[0] ^= 0xFF;
    }

    // Decryption should fail due to authentication failure
    assert!(encrypted.decrypt(password).is_err());
}

#[test]
fn test_version_checking() {
    let password = "VersionTest!123";
    let test_data = r#"{"name":"version_test","secret_seed":{"coefficients":[9,9,9]},"version":0}"#;

    let mut encrypted =
        EncryptedWalletFile::encrypt("version_test".to_string(), test_data, password)
            .expect("Encryption should succeed");

    // Tamper with version
    encrypted.version = 999;

    // Decryption should fail due to version mismatch
    let result = encrypted.decrypt(password);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unsupported wallet file version"));
}

#[test]
fn test_deterministic_key_derivation() {
    let password = "DeterministicTest!456";
    let salt = [42u8; 32];

    // Derive key twice with same password + salt
    let km1 =
        WalletKeyManager::from_password(password, &salt).expect("Key derivation should succeed");
    let km2 =
        WalletKeyManager::from_password(password, &salt).expect("Key derivation should succeed");

    // Keys should be identical
    assert_eq!(
        km1.derive_wallet_key().as_ref(),
        km2.derive_wallet_key().as_ref()
    );
}

#[test]
fn test_salt_uniqueness() {
    // Generate multiple salts
    let salt1 = WalletKeyManager::generate_salt();
    let salt2 = WalletKeyManager::generate_salt();
    let salt3 = WalletKeyManager::generate_salt();

    // All should be different (with overwhelming probability)
    assert_ne!(salt1, salt2);
    assert_ne!(salt2, salt3);
    assert_ne!(salt1, salt3);
}

#[test]
fn test_nonce_uniqueness() {
    // Generate multiple nonces
    let nonce1 = WalletCipher::generate_nonce();
    let nonce2 = WalletCipher::generate_nonce();
    let nonce3 = WalletCipher::generate_nonce();

    // All should be different (with overwhelming probability)
    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce2, nonce3);
    assert_ne!(nonce1, nonce3);
}

#[test]
fn test_argon2_params_defaults() {
    let params = format::Argon2Params::default();

    // Verify recommended parameters
    assert_eq!(params.memory_cost_kib, 262144); // 256 MB
    assert_eq!(params.time_cost, 4);
    assert_eq!(params.parallelism, 4);
}

#[test]
fn test_encryption_non_deterministic() {
    let password = "NonDetTest!789";
    let test_data = r#"{"name":"test","secret_seed":{"coefficients":[5,5,5]},"version":0}"#;

    // Encrypt same data twice
    let encrypted1 = EncryptedWalletFile::encrypt("test".to_string(), test_data, password)
        .expect("Encryption should succeed");

    let encrypted2 = EncryptedWalletFile::encrypt("test".to_string(), test_data, password)
        .expect("Encryption should succeed");

    // Ciphertexts should be different (due to random salt and nonce)
    assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
    assert_ne!(encrypted1.argon2_params.salt, encrypted2.argon2_params.salt);
    assert_ne!(
        encrypted1.aes_gcm_params.nonce,
        encrypted2.aes_gcm_params.nonce
    );

    // But both should decrypt to the same plaintext
    let decrypted1 = encrypted1
        .decrypt(password)
        .expect("Decryption should succeed");
    let decrypted2 = encrypted2
        .decrypt(password)
        .expect("Decryption should succeed");
    assert_eq!(decrypted1.as_str(), decrypted2.as_str());
    assert_eq!(test_data, decrypted1.as_str());
}

#[test]
fn test_large_wallet_data() {
    let password = "LargeDataTest!123";
    // Simulate a large wallet with many transactions
    let large_data = format!(
        r#"{{"name":"large_wallet","secret_seed":{{"coefficients":[{},{}]}},"version":0,"extra_data":"{}"}}"#,
        "123456789".repeat(100),
        "987654321".repeat(100),
        "x".repeat(10000)
    );

    let encrypted = EncryptedWalletFile::encrypt("large_wallet".to_string(), &large_data, password)
        .expect("Encryption of large data should succeed");

    let decrypted = encrypted
        .decrypt(password)
        .expect("Decryption of large data should succeed");

    assert_eq!(large_data, decrypted.as_str());
}

#[test]
fn test_unicode_in_wallet_data() {
    let password = "UnicodeTest!456🔐";
    let unicode_data = r#"{"name":"日本語_wallet","secret_seed":{"coefficients":[1,2,3]},"notes":"Ελληνικά, 中文, עברית, العربية"}"#;

    let encrypted =
        EncryptedWalletFile::encrypt("unicode_wallet".to_string(), unicode_data, password)
            .expect("Encryption with Unicode should succeed");

    let decrypted = encrypted
        .decrypt(password)
        .expect("Decryption with Unicode should succeed");

    assert_eq!(unicode_data, decrypted.as_str());
}

#[test]
fn test_env_var_password_fallback() {
    let env_var = "TEST_WALLET_PASSWORD_FALLBACK";
    let test_password = "EnvVarTest!789";

    // Set environment variable
    std::env::set_var(env_var, test_password);

    // Should be able to retrieve it
    let retrieved =
        PasswordManager::from_env_var(env_var).expect("Should retrieve password from env var");
    assert_eq!(retrieved, test_password);

    // Clean up
    std::env::remove_var(env_var);

    // Should fail after removal
    assert!(PasswordManager::from_env_var(env_var).is_err());
}
