use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
pub struct Error {
    pub code: i32,
    pub error: &'static str,
}
impl Error {
    pub const fn new(code: i32, error: &'static str) -> Self {
        Self { code, error }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
pub const INVALID: Error = Error::new(30, "invalid_input_or_configuration");
pub const STORAGE: Error = Error::new(22, "protected_storage_failed");
pub const SCANNER: Error = Error::new(22, "scanner_failed_closed");
pub const NETWORK: Error = Error::new(40, "communication_unavailable");
