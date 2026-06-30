//! ChaCha family stream ciphers and AEADs.

use crate::{
    base,
    markers,
};

/// ChaCha20 Stream Cipher.
///
/// Defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
pub trait ChaCha20: base::KeyInit<32> + base::StreamCipher<12> + markers::Symmetric + markers::StreamCipher {}

/// XChaCha20 Stream Cipher (extended 192-bit nonce).
///
/// Defined in [Draft RFC: XChaCha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
pub trait XChaCha20: base::KeyInit<32> + base::StreamCipher<24> + markers::Symmetric + markers::StreamCipher {}

/// ChaCha20-Poly1305 AEAD.
///
/// Defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
pub trait ChaCha20Poly1305: base::KeyInit<32> + base::Aead<12, 16> + markers::Symmetric + markers::Aead {}

/// XChaCha20-Poly1305 AEAD (extended 192-bit nonce).
///
/// Defined in [Draft RFC: XChaCha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
pub trait XChaCha20Poly1305: base::KeyInit<32> + base::Aead<24, 16> + markers::Symmetric + markers::Aead {}
