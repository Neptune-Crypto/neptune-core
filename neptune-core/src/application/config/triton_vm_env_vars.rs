use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Deref;
use std::ops::DerefMut;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

/// A mapping from log2 padded height to the environment variables to set for
/// the Triton VM proving process for proofs of this size.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TritonVmEnvVars(HashMap<u8, Vec<(String, String)>>);

impl Deref for TritonVmEnvVars {
    type Target = HashMap<u8, Vec<(String, String)>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TritonVmEnvVars {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for TritonVmEnvVars {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return write!(f, "TritonVmEnvVars: {{}}");
        }

        writeln!(f, "TritonVmEnvVars: {{")?;
        let mut heights: Vec<&u8> = self.0.keys().collect();
        heights.sort(); // Sort keys for consistent output

        for (i, height) in heights.iter().enumerate() {
            let vars = self.0.get(height).unwrap();
            if vars.is_empty() {
                writeln!(f, " log2 padded Height {}: {{}}", height)?;
            } else {
                writeln!(f, " log2 padded Height {}: {{", height)?;
                for (j, (key, value)) in vars.iter().enumerate() {
                    let comma = if j == vars.len() - 1 { "" } else { "," };
                    writeln!(f, "    {} = {}{}", key, value, comma)?;
                }
                writeln!(f, "}}")?;
            }
            if i < heights.len() - 1 {
                writeln!(f)?;
            }
        }
        write!(f, "}}")
    }
}

impl FromStr for TritonVmEnvVars {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self::default());
        }

        let mut map = HashMap::new();

        // Split by commas to separate the u8:"VAR1=VAL1 VAR2=VAL2" entries
        for entry in s.split(',') {
            let (key_str, vars_str) = entry
                .split_once(':')
                .ok_or_else(|| format!("TVM env var: Invalid entry (missing ':'): '{}'", entry))?;

            let key: u8 = key_str
                .trim()
                .parse()
                .map_err(|_| format!("TVM env var: Invalid u8 key: '{}'", key_str))?;
            if !(8..=31).contains(&key) {
                return Err(format!("TVM env var: {key} not in range 8..=31"));
            }

            // Remove optional surrounding quotes from vars_str
            let vars_str = vars_str.trim();
            let vars_str = vars_str
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(vars_str);
            let vars_str = vars_str
                .strip_prefix("'")
                .and_then(|v| v.strip_suffix("'"))
                .unwrap_or(vars_str);

            // Split space-separated VAR=VAL pairs
            let mut pairs = Vec::new();
            for var_val in vars_str.split_whitespace() {
                let (var, val) = var_val
                    .split_once('=')
                    .ok_or_else(|| format!("TVM env var: Invalid VAR=VAL: '{}'", var_val))?;
                pairs.push((var.to_string(), val.to_string()));
            }

            map.insert(key, pairs);
        }

        Ok(TritonVmEnvVars(map))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn parses_no_entries() {
        let parsed = TritonVmEnvVars::from_str("").unwrap();
        assert_eq!(HashMap::default(), parsed.0);
    }

    #[test]
    fn parses_single_entry() {
        let input = r#"24:"RAYON_NUM_THREADS=50 TVM_LDE_TRACE=no_cache""#;
        let parsed = TritonVmEnvVars::from_str(input).unwrap();

        let mut expected = HashMap::new();
        expected.insert(
            24,
            vec![
                ("RAYON_NUM_THREADS".to_string(), "50".to_string()),
                ("TVM_LDE_TRACE".to_string(), "no_cache".to_string()),
            ],
        );

        assert_eq!(expected, parsed.0);
    }

    #[test]
    fn parses_multiple_entries() {
        let input = r#"24:"RAYON_NUM_THREADS=50 TVM_LDE_TRACE=no_cache",25:"RAYON_NUM_THREADS=20 TVM_LDE_TRACE=no_cache""#;
        let parsed = TritonVmEnvVars::from_str(input).unwrap();

        let mut expected = HashMap::new();
        expected.insert(
            24,
            vec![
                ("RAYON_NUM_THREADS".to_string(), "50".to_string()),
                ("TVM_LDE_TRACE".to_string(), "no_cache".to_string()),
            ],
        );
        expected.insert(
            25,
            vec![
                ("RAYON_NUM_THREADS".to_string(), "20".to_string()),
                ("TVM_LDE_TRACE".to_string(), "no_cache".to_string()),
            ],
        );

        assert_eq!(expected, parsed.0);
    }
}
