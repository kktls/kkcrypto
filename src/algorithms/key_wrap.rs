//! Key Wrap (KW) and Key Wrap with Padding (KWP) algorithms.

use crate::{
    base,
    markers,
};

/// Length of an AES-128 key in bytes (128 bits).
pub const AES128_KEY_LEN: usize = 16;
/// Length of an AES-192 key in bytes (192 bits).
pub const AES192_KEY_LEN: usize = 24;
/// Length of an AES-256 key in bytes (256 bits).
pub const AES256_KEY_LEN: usize = 32;

/// AES-128 Key Wrap (KW).
///
/// Defined in [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394).
pub trait Aes128Kw: base::KeyInit<AES128_KEY_LEN> + base::KeyWrap + markers::Symmetric + markers::KeyWrap {}

/// AES-192 Key Wrap (KW).
///
/// Defined in [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394).
pub trait Aes192Kw: base::KeyInit<AES192_KEY_LEN> + base::KeyWrap + markers::Symmetric + markers::KeyWrap {}

/// AES-256 Key Wrap (KW).
///
/// Defined in [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394).
pub trait Aes256Kw: base::KeyInit<AES256_KEY_LEN> + base::KeyWrap + markers::Symmetric + markers::KeyWrap {}

/// AES-128 Key Wrap with Padding (KWP).
///
/// Defined in [RFC 5649](https://datatracker.ietf.org/doc/html/rfc5649).
pub trait Aes128Kwp: base::KeyInit<AES128_KEY_LEN> + base::KeyWrap + markers::Symmetric + markers::KeyWrap {}

/// AES-192 Key Wrap with Padding (KWP).
///
/// Defined in [RFC 5649](https://datatracker.ietf.org/doc/html/rfc5649).
pub trait Aes192Kwp: base::KeyInit<AES192_KEY_LEN> + base::KeyWrap + markers::Symmetric + markers::KeyWrap {}

/// AES-256 Key Wrap with Padding (KWP).
///
/// Defined in [RFC 5649](https://datatracker.ietf.org/doc/html/rfc5649).
pub trait Aes256Kwp: base::KeyInit<AES256_KEY_LEN> + base::KeyWrap + markers::Symmetric + markers::KeyWrap {}
