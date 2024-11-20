#[derive(thiserror::Error, Debug)]
pub enum SigningError {
    #[error("Address does not match")]
    AddressDoesNotMatch,

    #[error("Invalid address format")]
    InvalidAddressFormat,

    #[error("Invalid network")]
    InvalidNetwork,

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Invalid signature error: {0}")]
    InvalidSignature(#[from] bitcoin::secp256k1::Error),

    #[error("Invalid signature error: {0}")]
    InvalidSignatureLength(String),
    // #[error("Public key cannot be converted to address: {0}")]
    // PublicKeyConversionError(#[from] bitcoin::::AddressError),
}
