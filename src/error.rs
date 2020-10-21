#[derive(Debug)]
pub enum WebauthnCError {
    JSON,
    Unknown,
    Security,
    NotSupported,
}
