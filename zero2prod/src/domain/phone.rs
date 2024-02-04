use anyhow::bail;
use secrecy::{CloneableSecret, DebugSecret, Zeroize};
use validator::validate_phone;

#[derive(Clone, Debug)]
pub struct Phone(String);

impl Phone {
    pub fn parse(value: String) -> anyhow::Result<Self> {
        if validate_phone(&value) {
            Ok(Self(value))
        } else {
            bail!("{} is not a valid subscriber email", value)
        }
    }
}

impl std::fmt::Display for Phone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for Phone {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Zeroize for Phone {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Permits cloning
impl CloneableSecret for Phone {}

/// Provides a `Debug` impl (by default `[[REDACTED]]`)
impl DebugSecret for Phone {}
