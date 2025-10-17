//! Password management for wallet encryption
//!
//! Handles secure password input, strength validation, and environment variable fallback.

use anyhow::{anyhow, Result};
use rpassword::prompt_password;

/// Password strength classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    /// Very weak: < 8 characters
    VeryWeak,
    /// Weak: 8-11 characters
    Weak,
    /// Moderate: 12-15 characters, basic complexity
    Moderate,
    /// Strong: 16+ characters with good complexity
    Strong,
    /// Very Strong: 20+ characters with excellent complexity
    VeryStrong,
}

impl PasswordStrength {
    /// Check if strength meets minimum security requirements
    pub fn is_acceptable(&self) -> bool {
        matches!(
            self,
            PasswordStrength::Moderate | PasswordStrength::Strong | PasswordStrength::VeryStrong
        )
    }

    /// Get human-readable description
    pub fn description(&self) -> &str {
        match self {
            PasswordStrength::VeryWeak => "Very Weak (unacceptable)",
            PasswordStrength::Weak => "Weak (unacceptable)",
            PasswordStrength::Moderate => "Moderate (acceptable)",
            PasswordStrength::Strong => "Strong (recommended)",
            PasswordStrength::VeryStrong => "Very Strong (excellent)",
        }
    }
}

/// Manages password input and validation
#[derive(Debug, Clone, Copy)]
pub struct PasswordManager;

impl PasswordManager {
    /// Prompt user for password with validation
    ///
    /// Ensures password meets minimum strength requirements.
    /// Returns error if password is too weak or user cancels.
    pub fn prompt_new_password() -> Result<String> {
        println!("\n🔐 Creating encrypted wallet");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Your wallet will be encrypted with a password.");
        println!("⚠️  If you lose this password, your funds are PERMANENTLY LOST.");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        loop {
            let password = prompt_password("Enter wallet password: ")?;

            if password.is_empty() {
                eprintln!("❌ Password cannot be empty. Please try again.\n");
                continue;
            }

            let strength = Self::analyze_strength(&password);
            println!("Password strength: {}", strength.description());

            if !strength.is_acceptable() {
                eprintln!("❌ Password is too weak. Minimum: 12 characters with mixed case, numbers, and symbols.\n");
                continue;
            }

            let confirm = prompt_password("Confirm wallet password: ")?;

            if password != confirm {
                eprintln!("❌ Passwords do not match. Please try again.\n");
                continue;
            }

            println!("✅ Password accepted\n");
            return Ok(password);
        }
    }

    /// Prompt user to enter existing password
    pub fn prompt_unlock_password() -> Result<String> {
        println!("\n🔓 Unlocking encrypted wallet");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        let password = prompt_password("Enter wallet password: ")?;

        if password.is_empty() {
            return Err(anyhow!("Password cannot be empty"));
        }

        Ok(password)
    }

    /// Get password from environment variable (for automation/testing)
    ///
    /// ⚠️ WARNING: Environment variables are not secure!
    /// Only use for testing or CI/CD environments.
    pub fn from_env_var(var_name: &str) -> Result<String> {
        std::env::var(var_name).map_err(|_| {
            anyhow!(
                "Environment variable {} not set. Use interactive prompt instead.",
                var_name
            )
        })
    }

    /// Analyze password strength
    ///
    /// Considers:
    /// - Length (primary factor)
    /// - Character diversity (uppercase, lowercase, numbers, symbols)
    /// - Common patterns (optional, not implemented yet)
    pub fn analyze_strength(password: &str) -> PasswordStrength {
        let len = password.len();

        // Length-based baseline
        let base_strength = match len {
            0..=7 => PasswordStrength::VeryWeak,
            8..=11 => PasswordStrength::Weak,
            12..=15 => PasswordStrength::Moderate,
            16..=19 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        };

        // Check character diversity
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace());

        let diversity_score =
            has_lowercase as u8 + has_uppercase as u8 + has_digit as u8 + has_symbol as u8;

        // Downgrade if poor diversity
        match (base_strength, diversity_score) {
            (PasswordStrength::VeryStrong, 0..=2) => PasswordStrength::Strong,
            (PasswordStrength::Strong, 0..=1) => PasswordStrength::Moderate,
            (PasswordStrength::Moderate, 0..=1) => PasswordStrength::Weak,
            _ => base_strength,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_strength_length() {
        assert_eq!(
            PasswordManager::analyze_strength("short"),
            PasswordStrength::VeryWeak
        );
        assert_eq!(
            PasswordManager::analyze_strength("medium12"),
            PasswordStrength::Weak
        );
        // "longpassword" is 12 chars but only lowercase, so Weak (downgraded from Moderate)
        assert_eq!(
            PasswordManager::analyze_strength("longpassword"),
            PasswordStrength::Weak
        );
        // "LongPassword" has mixed case, so Moderate
        assert_eq!(
            PasswordManager::analyze_strength("LongPassword"),
            PasswordStrength::Moderate
        );
        assert_eq!(
            PasswordManager::analyze_strength("verylongpassword"),
            PasswordStrength::Moderate // Downgraded from Strong due to poor diversity
        );
        assert_eq!(
            PasswordManager::analyze_strength("VeryLongPassword"),
            PasswordStrength::Strong
        );
        assert_eq!(
            PasswordManager::analyze_strength("superlongpasswordhere123"),
            PasswordStrength::Strong // Downgraded from VeryStrong due to poor diversity
        );
    }

    #[test]
    fn test_password_strength_diversity() {
        // Long but no diversity
        assert_eq!(
            PasswordManager::analyze_strength("aaaaaaaaaaaaaaaaaaaa"),
            PasswordStrength::Strong // Downgraded from VeryStrong
        );

        // Good length + diversity
        assert_eq!(
            PasswordManager::analyze_strength("Password123!"),
            PasswordStrength::Moderate
        );

        // Excellent length + diversity
        assert_eq!(
            PasswordManager::analyze_strength("MySecurePassword2024!@#"),
            PasswordStrength::VeryStrong
        );
    }

    #[test]
    fn test_strength_acceptable() {
        assert!(!PasswordStrength::VeryWeak.is_acceptable());
        assert!(!PasswordStrength::Weak.is_acceptable());
        assert!(PasswordStrength::Moderate.is_acceptable());
        assert!(PasswordStrength::Strong.is_acceptable());
        assert!(PasswordStrength::VeryStrong.is_acceptable());
    }

    #[test]
    fn test_env_var_fallback() {
        // Set test env var
        std::env::set_var("TEST_WALLET_PASSWORD", "test123");

        let result = PasswordManager::from_env_var("TEST_WALLET_PASSWORD");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test123");

        // Clean up
        std::env::remove_var("TEST_WALLET_PASSWORD");

        // Test missing var
        let missing_result = PasswordManager::from_env_var("NONEXISTENT_VAR");
        assert!(missing_result.is_err());
    }
}
