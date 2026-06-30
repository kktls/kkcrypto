use alloc::string::String;

/// Represents possible errors that can occur during cryptographic
/// operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The provided key has an invalid length.
    InvalidKeyLength,
    /// The provided nonce/IV has an invalid length.
    InvalidNonceLength,
    /// The authentication tag length is incorrect.
    InvalidTagLength,
    /// AEAD or standard decryption failed (e.g., authentication tag mismatch).
    DecryptionFailed,
    /// The digital signature failed verification.
    InvalidSignature,
    /// The underlying random number generator failed.
    RngFailure,
    /// The ciphertext is malformed or invalid.
    InvalidCiphertext,
    /// The public key is malformed or invalid.
    InvalidPublicKey,
    /// The private key is malformed or invalid.
    InvalidPrivateKey,
    /// The requested operation is not supported by the underlying provider.
    UnsupportedOperation,
    /// An unknown or backend-specific error occurred.
    Other(String),
}

/// A specialized Result type for cryptographic operations.
pub type Result<T> = core::result::Result<T, CryptoError>;
