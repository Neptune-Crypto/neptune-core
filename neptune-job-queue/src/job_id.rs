/// A unique identifier for a [Job](super::traits::Job)
#[derive(Debug, Clone, Copy)]
pub struct JobId([u8; 12]);

impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl JobId {
    /// generates a random JobId
    pub(super) fn random() -> Self {
        Self(rand::random())
    }
}
