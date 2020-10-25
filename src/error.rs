#[derive(Debug)]
pub enum WebauthnCError {
    JSON,
    CBOR,
    Unknown,
    Security,
    NotSupported,
    PlatformAuthenticator,
    Internal,
    ParseNOMFailure,
    OpenSSL,
}
