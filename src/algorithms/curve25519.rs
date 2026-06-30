//! ChaCha family stream ciphers and AEADs.

use crate::{
    base,
    markers,
};

/// Length of a ChaCha20 / XChaCha20 key in bytes (256 bits).
pub const CHACHA_KEY_LEN: usize = 32;

/// Length of a standard IETF ChaCha20 nonce in bytes (96 bits).
pub const CHACHA_NONCE_LEN: usize = 12;

/// Length of an XChaCha20 extended nonce in bytes (192 bits).
pub const XCHACHA_NONCE_LEN: usize = 24;

/// Length of a Poly1305 authentication tag in bytes (128 bits).
pub const POLY1305_TAG_LEN: usize = 16;

/// ChaCha20 Stream Cipher.
///
/// Defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
pub trait ChaCha20:
    base::KeyInit<CHACHA_KEY_LEN> + base::StreamCipher<CHACHA_NONCE_LEN> + markers::Symmetric + markers::StreamCipher
{
}

/// XChaCha20 Stream Cipher (extended 192-bit nonce).
///
/// Defined in [Draft RFC: XChaCha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
pub trait XChaCha20:
    base::KeyInit<CHACHA_KEY_LEN> + base::StreamCipher<XCHACHA_NONCE_LEN> + markers::Symmetric + markers::StreamCipher
{
}

/// ChaCha20-Poly1305 AEAD.
///
/// Defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
pub trait ChaCha20Poly1305:
    base::KeyInit<CHACHA_KEY_LEN> + base::Aead<CHACHA_NONCE_LEN, POLY1305_TAG_LEN> + markers::Symmetric + markers::Aead
{
}

/// XChaCha20-Poly1305 AEAD (extended 192-bit nonce).
///
/// Defined in [Draft RFC: XChaCha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
pub trait XChaCha20Poly1305:
    base::KeyInit<CHACHA_KEY_LEN> + base::Aead<XCHACHA_NONCE_LEN, POLY1305_TAG_LEN> + markers::Symmetric + markers::Aead
{
}
